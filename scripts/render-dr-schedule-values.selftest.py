#!/usr/bin/env python3
"""Regression self-test for the DR schedule value renderer."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "scripts/render-dr-schedule-values.py"
ARROW = "\N{RIGHTWARDS ARROW}"


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected: str
    actual: str
    passed: bool


def load_renderer_module() -> Any:
    spec = importlib.util.spec_from_file_location("render_dr_schedule_values", RENDERER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {RENDERER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def lines(*items: str) -> str:
    return "\n".join(items) + "\n"


def base_files(renderer: Any) -> dict[str, str]:
    return {
        str(renderer.ETCD_CRONJOB): lines(
            "apiVersion: batch/v1",
            "kind: CronJob",
            "spec:",
            '  schedule: "0 3 * * *"',
        ),
        str(renderer.ETCD_RECURRINGJOB): lines(
            "apiVersion: longhorn.io/v1beta2",
            "kind: RecurringJob",
            "spec:",
            "  name: etcd-daily-backup",
            "  task: backup",
            '  cron: "47 3 * * *"',
            "  retain: 14",
        ),
        str(renderer.VAULT_RECURRINGJOB): lines(
            "apiVersion: longhorn.io/v1beta2",
            "kind: RecurringJob",
            "spec:",
            "  name: vault-daily-backup",
            "  task: backup",
            '  cron: "17 8 * * *"',
            "  retain: 14",
        ),
        str(renderer.ETCD_ENCRYPT_SCRIPT): lines(
            "apiVersion: v1",
            "kind: ConfigMap",
            "data:",
            "  encrypt.sh: |",
            "    #!/bin/sh",
            "    ls -1 /data/etcd-*.db.sops.json | sort | head -n -21 | while read -r old; do",
            '      rm -- "$old"',
            "    done",
        ),
        str(renderer.ADR_0026): lines(
            "# ADR fixture",
            "",
            "- **CronJob** (03:00 UTC daily, two containers, the talos-drift pattern):",
            "  a snapshot line.",
            "  `etcd-snapshots` PVC (`longhorn-etcd-snapshot` StorageClass), prunes to 21",
            "  local dailies, and refuses snapshots smaller than 10 MB.",
            "  `etcd-daily-backup` RecurringJob (03:47 UTC, retain 14) to the volume;",
            "",
            f"- ~110 MB snapshot {ARROW} ~147 MB ciphertext daily; 21 local + 14 Synology copies",
            "  is a few GB - negligible on both tiers.",
        ),
        str(renderer.DR_STAGE1_RUNBOOK): lines(
            "# DR Stage 1 fixture",
            "",
            "```yaml",
            "apiVersion: longhorn.io/v1beta2",
            "kind: RecurringJob",
            "metadata:",
            "  name: vault-daily-backup",
            "  namespace: longhorn-system",
            "spec:",
            "  task: backup",
            '  cron: "17 8 * * *"',
            "  retain: 14",
            "  concurrency: 1",
            "  groups:",
            "    - default",
            "```",
            "",
            "Retention is 14 Longhorn backups for the selected Vault volumes. Treat this as",
            "local operational recovery.",
        ),
        str(renderer.ARCHITECTURE): lines(
            "# Architecture fixture",
            "",
            "```mermaid",
            "flowchart LR",
            '    VaultDailyBackup["Longhorn RecurringJob vault-daily-backup<br/>backup cron 17 8 daily, retain 14"]',
            '    EtcdCronJob["CronJob etcd-snapshot in dr-etcd-backup<br/>talosctl os:etcd:backup role, 03:00 daily<br/>whole-file age encryption, escrowed key"]',
            '    EtcdPVC["PVC etcd-snapshots<br/>storageClassName longhorn-etcd-snapshot<br/>21 encrypted local dailies"]',
            '    EtcdDailyBackup["Longhorn RecurringJob etcd-daily-backup<br/>backup cron 47 3 daily, retain 14<br/>detached-volume backup enabled"]',
            "```",
        ),
    }


def write_file(root: Path, relpath: str, content: str) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_fixture(renderer: Any, root: Path, overrides: dict[str, str] | None = None) -> None:
    files = base_files(renderer)
    if overrides:
        files.update(overrides)
    for relpath, content in files.items():
        write_file(root, relpath, content)


def assert_equal(actual: object, expected: object, detail: str) -> None:
    if actual != expected:
        raise AssertionError(f"{detail}: expected {expected!r}, got {actual!r}")


def assert_contains(haystack: str, needle: str, detail: str) -> None:
    if needle not in haystack:
        raise AssertionError(f"{detail}: missing {needle!r} in {haystack!r}")


def assert_raises_render_error(
    renderer: Any,
    name: str,
    overrides: dict[str, str] | None = None,
    remove: Sequence[str] = (),
    expected_substring: str | None = None,
) -> None:
    with tempfile.TemporaryDirectory(prefix=f"dr-render-{name}-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root, overrides)
        for relpath in remove:
            (root / relpath).unlink()

        try:
            renderer.render_documents(root)
        except renderer.RenderError as exc:
            if expected_substring is not None:
                assert_contains(str(exc), expected_substring, name)
            return
        raise AssertionError(f"{name}: expected RenderError")


def capture_main(renderer: Any, root: Path, argv: Sequence[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = renderer.main(argv, root=root)
    return rc, stdout.getvalue(), stderr.getvalue()


def read_docs(renderer: Any, root: Path) -> dict[Path, str]:
    return {
        renderer.ADR_0026: (root / renderer.ADR_0026).read_text(encoding="utf-8"),
        renderer.DR_STAGE1_RUNBOOK: (root / renderer.DR_STAGE1_RUNBOOK).read_text(encoding="utf-8"),
        renderer.ARCHITECTURE: (root / renderer.ARCHITECTURE).read_text(encoding="utf-8"),
    }


def target_lines(renderer: Any) -> dict[str, tuple[Path, str]]:
    return {
        "D1": (
            renderer.ADR_0026,
            "- **CronJob** (03:00 UTC daily, two containers, the talos-drift pattern):",
        ),
        "D2": (
            renderer.ADR_0026,
            "  `etcd-daily-backup` RecurringJob (03:47 UTC, retain 14) to the volume;",
        ),
        "D3": (renderer.DR_STAGE1_RUNBOOK, '  cron: "17 8 * * *"'),
        "D4": (renderer.DR_STAGE1_RUNBOOK, "  retain: 14"),
        "D5": (
            renderer.DR_STAGE1_RUNBOOK,
            "Retention is 14 Longhorn backups for the selected Vault volumes. Treat this as",
        ),
        "D6": (
            renderer.ARCHITECTURE,
            '    VaultDailyBackup["Longhorn RecurringJob vault-daily-backup<br/>backup cron 17 8 daily, retain 14"]',
        ),
        "D7": (
            renderer.ARCHITECTURE,
            '    EtcdCronJob["CronJob etcd-snapshot in dr-etcd-backup<br/>talosctl os:etcd:backup role, 03:00 daily<br/>whole-file age encryption, escrowed key"]',
        ),
        "D8": (
            renderer.ARCHITECTURE,
            '    EtcdDailyBackup["Longhorn RecurringJob etcd-daily-backup<br/>backup cron 47 3 daily, retain 14<br/>detached-volume backup enabled"]',
        ),
        "D9": (
            renderer.ADR_0026,
            "  `etcd-snapshots` PVC (`longhorn-etcd-snapshot` StorageClass), prunes to 21",
        ),
        "D10": (
            renderer.ADR_0026,
            f"- ~110 MB snapshot {ARROW} ~147 MB ciphertext daily; 21 local + 14 Synology copies",
        ),
        "D11": (
            renderer.ARCHITECTURE,
            '    EtcdPVC["PVC etcd-snapshots<br/>storageClassName longhorn-etcd-snapshot<br/>21 encrypted local dailies"]',
        ),
    }


def target_index_by_path(renderer: Any, docs: dict[Path, str]) -> dict[tuple[Path, int], str]:
    indexed: dict[tuple[Path, int], str] = {}
    for target_id, (path, expected_line) in target_lines(renderer).items():
        matches = [index for index, line in enumerate(docs[path].splitlines()) if line == expected_line]
        if len(matches) != 1:
            raise AssertionError(f"{target_id}: expected one fixture target line, found {len(matches)}")
        indexed[(path, matches[0])] = target_id
    return indexed


def changed_target_ids(renderer: Any, before: dict[Path, str], after: dict[Path, str]) -> set[str]:
    indexes = target_index_by_path(renderer, before)
    changed: set[str] = set()
    unexpected: list[str] = []

    for path, before_text in before.items():
        before_lines = before_text.splitlines()
        after_lines = after[path].splitlines()
        if len(before_lines) != len(after_lines):
            raise AssertionError(f"{path}: line count changed from {len(before_lines)} to {len(after_lines)}")
        for index, (before_line, after_line) in enumerate(zip(before_lines, after_lines)):
            if before_line == after_line:
                continue
            target_id = indexes.get((path, index))
            if target_id is None:
                unexpected.append(f"{path}:{index + 1}")
            else:
                changed.add(target_id)

    if unexpected:
        raise AssertionError(f"unexpected non-target line changes: {', '.join(unexpected)}")
    return changed


def rendered_target_lines(renderer: Any, before: dict[Path, str], after: dict[Path, str]) -> dict[str, str]:
    indexes = target_index_by_path(renderer, before)
    rendered: dict[str, str] = {}
    for (path, index), target_id in indexes.items():
        rendered[target_id] = after[path].splitlines()[index]
    return rendered


def replace_once_text(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise AssertionError(f"fixture replacement target {old!r} must occur exactly once, found {count}")
    return text.replace(old, new, 1)


def mutate_file(root: Path, relpath: Path, old: str, new: str) -> None:
    path = root / relpath
    path.write_text(replace_once_text(path.read_text(encoding="utf-8"), old, new), encoding="utf-8")


def check_derivations(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="dr-render-derivations-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root)
        values = renderer.collect_values(root)
        assert_equal(values.etcd_snapshot.raw, "0 3 * * *", "V1 raw")
        assert_equal(values.etcd_snapshot.clock, "03:00", "V1 clock")
        assert_equal(values.etcd_longhorn.raw, "47 3 * * *", "V2 raw")
        assert_equal(values.etcd_longhorn.clock, "03:47", "V2 clock")
        assert_equal(values.etcd_longhorn_retain, 14, "V3 retain")
        assert_equal(values.vault_longhorn.raw, "17 8 * * *", "V4 raw")
        assert_equal(values.vault_longhorn.clock, "08:17", "V4 clock")
        assert_equal(values.vault_longhorn_retain, 14, "V5 retain")
        assert_equal(values.etcd_local_retain, 21, "V6 retain")


def check_output_formats(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="dr-render-formats-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root)
        rendered = "\n".join(document.rendered for document in renderer.render_documents(root))
        assert_contains(rendered, "03:00 UTC daily", "HH:MM UTC format")
        assert_contains(rendered, "03:00 daily<br/>whole-file", "HH:MM daily without UTC format")
        assert_contains(rendered, '  cron: "17 8 * * *"', "raw quoted cron format")
        assert_contains(rendered, "  retain: 14", "bare YAML scalar format")
        assert_contains(rendered, "Retention is 14 Longhorn backups", "English sentence format")
        assert_contains(rendered, "prunes to 21", "local retention English format")
        assert_contains(rendered, "21 local + 14 Synology copies", "dual-retention English format")
        assert_contains(rendered, "backup cron 17 8 daily, retain 14", "Vault Mermaid format")
        assert_contains(rendered, "backup cron 47 3 daily, retain 14", "etcd Mermaid format")
        assert_contains(rendered, "21 encrypted local dailies", "local retention Mermaid format")


def check_check_mode(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="dr-render-check-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root)
        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 0, "current --check rc")
        assert_contains(stdout, "match canonical sources", "current --check stdout")
        assert_equal(stderr, "", "current --check stderr")

    with tempfile.TemporaryDirectory(prefix="dr-render-stale-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root)
        stale_path = root / renderer.ADR_0026
        before = replace_once_text(
            stale_path.read_text(encoding="utf-8"),
            "03:00 UTC daily",
            "04:00 UTC daily",
        )
        stale_path.write_text(before, encoding="utf-8")
        rc, _stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 1, "stale --check rc")
        assert_contains(stderr, "--- docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md (current)", "stale diff")
        assert_equal(stale_path.read_text(encoding="utf-8"), before, "--check must not write")

    with tempfile.TemporaryDirectory(prefix="dr-render-write-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root)
        mutate_file(root, renderer.ETCD_CRONJOB, '  schedule: "0 3 * * *"', '  schedule: "5 4 * * *"')
        rc, _stdout, stderr = capture_main(renderer, root, [])
        assert_equal(rc, 0, "default render rc")
        assert_equal(stderr, "", "default render stderr")
        rendered = (root / renderer.ADR_0026).read_text(encoding="utf-8")
        assert_contains(rendered, "04:05 UTC daily", "default render writes docs")


def check_anchor_failures(renderer: Any) -> None:
    missing_adr = replace_once_text(
        base_files(renderer)[str(renderer.ADR_0026)],
        "- **CronJob** (03:00 UTC daily, two containers, the talos-drift pattern):",
        "- **CronJob** (daily, two containers, the talos-drift pattern):",
    )
    assert_raises_render_error(
        renderer,
        "anchor-zero-match",
        {str(renderer.ADR_0026): missing_adr},
        expected_substring="must occur exactly once, found 0",
    )

    duplicate_adr = base_files(renderer)[str(renderer.ADR_0026)].replace(
        "- **CronJob** (03:00 UTC daily, two containers, the talos-drift pattern):",
        lines(
            "- **CronJob** (03:00 UTC daily, two containers, the talos-drift pattern):",
            "- **CronJob** (03:00 UTC daily, two containers, the talos-drift pattern):",
        ).rstrip("\n"),
        1,
    )
    assert_raises_render_error(
        renderer,
        "anchor-two-match",
        {str(renderer.ADR_0026): duplicate_adr},
        expected_substring="must occur exactly once, found 2",
    )

    with tempfile.TemporaryDirectory(prefix="dr-render-tooling-exit-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root, {str(renderer.ADR_0026): missing_adr})
        rc, _stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 2, "tooling --check rc")
        assert_contains(stderr, "ERROR:", "tooling --check stderr")


def check_runbook_fence_relabel_exits_2(renderer: Any) -> None:
    runbook = replace_once_text(
        base_files(renderer)[str(renderer.DR_STAGE1_RUNBOOK)],
        "  name: vault-daily-backup",
        "  name: etcd-daily-backup",
    )
    with tempfile.TemporaryDirectory(prefix="dr-render-runbook-relabel-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root, {str(renderer.DR_STAGE1_RUNBOOK): runbook})
        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 2, "runbook relabel rc")
        assert_equal(stdout, "", "runbook relabel stdout")
        assert_contains(stderr, "ERROR:", "runbook relabel stderr")
        assert_contains(stderr, "found 0", "runbook relabel stderr")


def check_runbook_duplicate_fence_exits_2(renderer: Any) -> None:
    vault_fence = lines(
        "```yaml",
        "apiVersion: longhorn.io/v1beta2",
        "kind: RecurringJob",
        "metadata:",
        "  name: vault-daily-backup",
        "  namespace: longhorn-system",
        "spec:",
        "  task: backup",
        '  cron: "17 8 * * *"',
        "  retain: 14",
        "  concurrency: 1",
        "  groups:",
        "    - default",
        "```",
    ).rstrip("\n")
    runbook = replace_once_text(
        base_files(renderer)[str(renderer.DR_STAGE1_RUNBOOK)],
        vault_fence,
        f"{vault_fence}\n\n{vault_fence}",
    )
    with tempfile.TemporaryDirectory(prefix="dr-render-runbook-duplicate-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root, {str(renderer.DR_STAGE1_RUNBOOK): runbook})
        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 2, "runbook duplicate rc")
        assert_equal(stdout, "", "runbook duplicate stdout")
        assert_contains(stderr, "ERROR:", "runbook duplicate stderr")
        assert_contains(stderr, "found 2", "runbook duplicate stderr")


def check_source_errors(renderer: Any) -> None:
    assert_raises_render_error(
        renderer,
        "missing-source",
        remove=(str(renderer.ETCD_CRONJOB),),
        expected_substring="missing required file",
    )
    assert_raises_render_error(
        renderer,
        "invalid-yaml",
        {str(renderer.ETCD_CRONJOB): "apiVersion: [\n"},
        expected_substring="not valid YAML",
    )
    assert_raises_render_error(
        renderer,
        "yaml-root-not-mapping",
        {str(renderer.ETCD_CRONJOB): lines("- item")},
        expected_substring="must parse to a YAML mapping",
    )
    assert_raises_render_error(
        renderer,
        "missing-spec",
        {str(renderer.ETCD_CRONJOB): lines("apiVersion: batch/v1", "kind: CronJob")},
        expected_substring="missing required spec mapping",
    )
    assert_raises_render_error(
        renderer,
        "missing-field",
        {str(renderer.ETCD_CRONJOB): lines("apiVersion: batch/v1", "kind: CronJob", "spec:", "  suspend: false")},
        expected_substring="missing required spec.schedule",
    )
    assert_raises_render_error(
        renderer,
        "wrong-field-type",
        {
            str(renderer.ETCD_RECURRINGJOB): lines(
                "apiVersion: longhorn.io/v1beta2",
                "kind: RecurringJob",
                "spec:",
                '  cron: "47 3 * * *"',
                '  retain: "fourteen"',
            )
        },
        expected_substring="spec.retain must be an integer",
    )
    assert_raises_render_error(
        renderer,
        "cron-not-five-fields",
        {str(renderer.ETCD_CRONJOB): lines("apiVersion: batch/v1", "kind: CronJob", "spec:", '  schedule: "0 3 * *"')},
        expected_substring="must have exactly 5 fields",
    )
    assert_raises_render_error(
        renderer,
        "cron-not-daily",
        {str(renderer.ETCD_CRONJOB): lines("apiVersion: batch/v1", "kind: CronJob", "spec:", '  schedule: "0 3 * * 1"')},
        expected_substring="fields 3-5 must all be '*'",
    )
    assert_raises_render_error(
        renderer,
        "cron-non-integer-minute-hour",
        {str(renderer.ETCD_CRONJOB): lines("apiVersion: batch/v1", "kind: CronJob", "spec:", '  schedule: "*/5 3 * * *"')},
        expected_substring="minute/hour must be integers",
    )
    assert_raises_render_error(
        renderer,
        "head-retention-absent",
        {str(renderer.ETCD_ENCRYPT_SCRIPT): lines("apiVersion: v1", "kind: ConfigMap", "data:", "  encrypt.sh: |", "    true")},
        expected_substring="must occur exactly once, found 0",
    )
    duplicate_prune = base_files(renderer)[str(renderer.ETCD_ENCRYPT_SCRIPT)] + (
        "    ls -1 /data/etcd-*.db.sops.json | sort | head -n -14 | while read -r old; do\n"
    )
    assert_raises_render_error(
        renderer,
        "head-retention-two-matches",
        {str(renderer.ETCD_ENCRYPT_SCRIPT): duplicate_prune},
        expected_substring="must occur exactly once, found 2",
    )


def check_source_mutation(
    renderer: Any,
    name: str,
    relpath: Path,
    old: str,
    new: str,
    expected_lines: dict[str, str],
) -> None:
    with tempfile.TemporaryDirectory(prefix=f"dr-render-{name}-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root)
        before = read_docs(renderer, root)
        mutate_file(root, relpath, old, new)
        rc, _stdout, stderr = capture_main(renderer, root, [])
        assert_equal(rc, 0, f"{name} render rc")
        assert_equal(stderr, "", f"{name} render stderr")
        after = read_docs(renderer, root)
        assert_equal(changed_target_ids(renderer, before, after), set(expected_lines), f"{name} changed lines")
        actual_lines = rendered_target_lines(renderer, before, after)
        for target_id, expected_line in expected_lines.items():
            assert_equal(actual_lines[target_id], expected_line, f"{name} {target_id} rendered line")


def check_mutation_matrix(renderer: Any) -> None:
    check_source_mutation(
        renderer,
        "V1",
        renderer.ETCD_CRONJOB,
        '  schedule: "0 3 * * *"',
        '  schedule: "5 4 * * *"',
        {
            "D1": "- **CronJob** (04:05 UTC daily, two containers, the talos-drift pattern):",
            "D7": '    EtcdCronJob["CronJob etcd-snapshot in dr-etcd-backup<br/>talosctl os:etcd:backup role, 04:05 daily<br/>whole-file age encryption, escrowed key"]',
        },
    )
    check_source_mutation(
        renderer,
        "V2",
        renderer.ETCD_RECURRINGJOB,
        '  cron: "47 3 * * *"',
        '  cron: "6 4 * * *"',
        {
            "D2": "  `etcd-daily-backup` RecurringJob (04:06 UTC, retain 14) to the volume;",
            "D8": '    EtcdDailyBackup["Longhorn RecurringJob etcd-daily-backup<br/>backup cron 6 4 daily, retain 14<br/>detached-volume backup enabled"]',
        },
    )
    check_source_mutation(
        renderer,
        "V3",
        renderer.ETCD_RECURRINGJOB,
        "  retain: 14",
        "  retain: 9",
        {
            "D2": "  `etcd-daily-backup` RecurringJob (03:47 UTC, retain 9) to the volume;",
            "D8": '    EtcdDailyBackup["Longhorn RecurringJob etcd-daily-backup<br/>backup cron 47 3 daily, retain 9<br/>detached-volume backup enabled"]',
            "D10": f"- ~110 MB snapshot {ARROW} ~147 MB ciphertext daily; 21 local + 9 Synology copies",
        },
    )
    check_source_mutation(
        renderer,
        "V4",
        renderer.VAULT_RECURRINGJOB,
        '  cron: "17 8 * * *"',
        '  cron: "21 9 * * *"',
        {
            "D3": '  cron: "21 9 * * *"',
            "D6": '    VaultDailyBackup["Longhorn RecurringJob vault-daily-backup<br/>backup cron 21 9 daily, retain 14"]',
        },
    )
    check_source_mutation(
        renderer,
        "V5",
        renderer.VAULT_RECURRINGJOB,
        "  retain: 14",
        "  retain: 9",
        {
            "D4": "  retain: 9",
            "D5": "Retention is 9 Longhorn backups for the selected Vault volumes. Treat this as",
            "D6": '    VaultDailyBackup["Longhorn RecurringJob vault-daily-backup<br/>backup cron 17 8 daily, retain 9"]',
        },
    )
    check_source_mutation(
        renderer,
        "V6",
        renderer.ETCD_ENCRYPT_SCRIPT,
        "head -n -21",
        "head -n -9",
        {
            "D9": "  `etcd-snapshots` PVC (`longhorn-etcd-snapshot` StorageClass), prunes to 9",
            "D10": f"- ~110 MB snapshot {ARROW} ~147 MB ciphertext daily; 9 local + 14 Synology copies",
            "D11": '    EtcdPVC["PVC etcd-snapshots<br/>storageClassName longhorn-etcd-snapshot<br/>9 encrypted local dailies"]',
        },
    )


def check_d10_segment_order(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="dr-render-d10-order-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(renderer, root)
        before = read_docs(renderer, root)
        mutate_file(root, renderer.ETCD_RECURRINGJOB, "  retain: 14", "  retain: 8")
        mutate_file(root, renderer.ETCD_ENCRYPT_SCRIPT, "head -n -21", "head -n -5")
        rc, _stdout, stderr = capture_main(renderer, root, [])
        assert_equal(rc, 0, "D10 order render rc")
        assert_equal(stderr, "", "D10 order render stderr")
        after = read_docs(renderer, root)
        actual_lines = rendered_target_lines(renderer, before, after)
        assert_equal(
            actual_lines["D10"],
            f"- ~110 MB snapshot {ARROW} ~147 MB ciphertext daily; 5 local + 8 Synology copies",
            "D10 local/Synology segment order",
        )


def run_case(name: str, func: Callable[[], None]) -> CaseResult:
    try:
        func()
    except Exception as exc:
        return CaseResult(name, "pass", repr(exc), False)
    return CaseResult(name, "pass", "pass", True)


def print_table(results: Sequence[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected  result")
    print(f"{'-' * name_width}  --------  ------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"{result.name:<{name_width}}  {result.expected:<8}  {status}")
        if not result.passed:
            print(f"  actual: {result.actual}")


def main() -> int:
    try:
        renderer = load_renderer_module()
    except Exception as exc:
        print(f"SELFTEST FAIL: {exc}", file=sys.stderr)
        return 1

    checks: Sequence[tuple[str, Callable[[], None]]] = (
        ("six source derivations", lambda: check_derivations(renderer)),
        ("five output formats", lambda: check_output_formats(renderer)),
        ("check and write modes", lambda: check_check_mode(renderer)),
        ("exactly-once anchors", lambda: check_anchor_failures(renderer)),
        ("runbook fence relabel exits 2", lambda: check_runbook_fence_relabel_exits_2(renderer)),
        ("runbook duplicate fence exits 2", lambda: check_runbook_duplicate_fence_exits_2(renderer)),
        ("source error paths", lambda: check_source_errors(renderer)),
        ("source mutation matrix", lambda: check_mutation_matrix(renderer)),
        ("D10 segment order", lambda: check_d10_segment_order(renderer)),
    )
    results = [run_case(name, func) for name, func in checks]

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for failure in failures:
            print(f"{failure.name}: {failure.actual}", file=sys.stderr)
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
