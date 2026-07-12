#!/usr/bin/env python3
"""Fail if curated documentation schedule claims drift from live manifests."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


FREQUENCY_EXPECTATIONS = {"hourly", "daily", "weekly"}
SOURCE_KINDS = {
    "workflow_cron",
    "workflow_no_schedule",
    "cronjob_schedule",
    "recurringjob_cron",
    "recurringjob_retain",
}


class WorkflowLoader(yaml.SafeLoader):
    """YAML loader that keeps GitHub Actions' `on` key as a string."""


WorkflowLoader.yaml_implicit_resolvers = {
    key: [
        (tag, regexp)
        for tag, regexp in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


@dataclass(frozen=True)
class Claim:
    name: str
    doc_path: str
    anchor_regex: str
    source_path: str
    source_kind: str
    expected: str


@dataclass(frozen=True)
class Failure:
    claim: str
    detail: str


@dataclass(frozen=True)
class CheckResult:
    checked: int
    failures: tuple[Failure, ...]

    @property
    def ok(self) -> bool:
        return not self.failures


# Claim inventory rationale:
# - This table is deliberately curated. It covers live schedule and retention
#   claims whose truth is available in this repository, without sweeping prose
#   that should remain historical or aspirational.
# - ADR-0006 and ADR-0014 target tables are excluded because they are
#   superseded/aspirational and literally headed "target".
# - docs/decision-records/README.md index blurbs are excluded because they are
#   historical summaries of decision records, not current schedule assertions.
# - vault-restore-validator claims are excluded because the CronJob is
#   deliberately inert (ADR-0024) and docs byte-match that suspended manifest.
# - Renovate cadence claims are excluded because renovate.json5 is a distinct
#   source class; that belongs in a future SM8c-style guard.
# - Synology DSM-side runbook/ADR-0021 claims such as "daily, retain 30" are
#   excluded because DSM UI configuration has no in-repo source of truth.
# - Same-doc restatements use one anchor per doc per source. A covered anchor
#   already forces edits to that file to preserve the live-truth mapping.
CLAIMS: tuple[Claim, ...] = (
    Claim(
        name="readme-intro-etcd-snapshot-daily",
        doc_path="README.md",
        anchor_regex=r"daily in-cluster etcd and Vault snapshot jobs",
        source_path="clusters/talos-cluster/apps/dr-etcd-backup/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="daily",
    ),
    Claim(
        name="readme-intro-vault-backup-daily",
        doc_path="README.md",
        anchor_regex=r"daily in-cluster etcd and Vault snapshot jobs",
        source_path="clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml",
        source_kind="recurringjob_cron",
        expected="daily",
    ),
    Claim(
        name="readme-dr-vault-longhorn-daily",
        doc_path="README.md",
        anchor_regex=r"Longhorn volume backups daily \(Vault data included\), and etcd snapshots via the",
        source_path="clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml",
        source_kind="recurringjob_cron",
        expected="daily",
    ),
    Claim(
        name="readme-dr-etcd-cronjob-daily",
        doc_path="README.md",
        anchor_regex=r"in-cluster `dr-etcd-backup` CronJob",
        source_path="clusters/talos-cluster/apps/dr-etcd-backup/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="daily",
    ),
    Claim(
        name="readme-dr-etcd-recurringjob-daily",
        doc_path="README.md",
        anchor_regex=r"`etcd-daily-backup` RecurringJob",
        source_path="clusters/talos-cluster/apps/longhorn-etcd-storage/recurringjob.yaml",
        source_kind="recurringjob_cron",
        expected="daily",
    ),
    Claim(
        name="readme-security-workflow-weekly",
        doc_path="README.md",
        anchor_regex=r"\| Security \| `security\.yaml` \| Runs Gitleaks and the config audit on PRs, weekly schedule, and manual dispatch\. \|",
        source_path=".github/workflows/security.yaml",
        source_kind="workflow_cron",
        expected="weekly",
    ),
    Claim(
        name="adr0025-security-workflow-weekly",
        doc_path="docs/decision-records/repo/0025-deliberate-transparency-public-repo.md",
        anchor_regex=r"requests and on a weekly schedule\.",
        source_path=".github/workflows/security.yaml",
        source_kind="workflow_cron",
        expected="weekly",
    ),
    Claim(
        name="readme-org-adr-sync-no-schedule",
        doc_path="README.md",
        anchor_regex=r"\| Org ADR sync \| `org-adr-sync\.yaml` \| Mirrors organization ADRs into `docs/decision-records/org/` on PRs and manual dispatch\. \|",
        source_path=".github/workflows/org-adr-sync.yaml",
        source_kind="workflow_no_schedule",
        expected="absent",
    ),
    Claim(
        name="readme-talos-drift-hourly",
        doc_path="README.md",
        anchor_regex=r"which runs an hourly in-cluster",
        source_path="clusters/talos-cluster/apps/talos-drift/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="hourly",
    ),
    Claim(
        name="adr0003-talos-drift-hourly",
        doc_path="docs/decision-records/repo/0003-repo-as-cluster-source-of-truth.md",
        anchor_regex=r"Flux reconciles `clusters/talos-cluster/apps/talos-drift/`, which runs hourly in-cluster",
        source_path="clusters/talos-cluster/apps/talos-drift/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="hourly",
    ),
    Claim(
        name="kubescape-workflow-header-daily",
        doc_path=".github/workflows/kubescape.yaml",
        anchor_regex=r"# Kubescape . daily CIS K8s Benchmark compliance scan",
        source_path=".github/workflows/kubescape.yaml",
        source_kind="workflow_cron",
        expected="daily",
    ),
    Claim(
        name="compliance-readme-kubescape-daily",
        doc_path="docs/compliance/README.md",
        anchor_regex=r"\[Kubescape\]\(https://kubescape\.io/\) runs daily via `.github/workflows/kubescape\.yaml`",
        source_path=".github/workflows/kubescape.yaml",
        source_kind="workflow_cron",
        expected="daily",
    ),
    Claim(
        name="adr0009-kubescape-daily",
        doc_path="docs/decision-records/repo/0009-stig-cis-compliance-baseline.md",
        anchor_regex=r"\[`kubescape`\]\(https://kubescape\.io/\) runs daily via `.github/workflows/kubescape\.yaml`",
        source_path=".github/workflows/kubescape.yaml",
        source_kind="workflow_cron",
        expected="daily",
    ),
    Claim(
        name="workflow-health-header-weekly",
        doc_path=".github/workflows/workflow-health.yaml",
        anchor_regex=r"# Workflow Health - weekly guard against silent pipeline death",
        source_path=".github/workflows/workflow-health.yaml",
        source_kind="workflow_cron",
        expected="weekly",
    ),
    Claim(
        name="adr0026-tldr-etcd-cronjob-daily",
        doc_path="docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md",
        anchor_regex=r"etcd snapshots are captured \*\*in-cluster\*\* by a daily Flux-reconciled CronJob",
        source_path="clusters/talos-cluster/apps/dr-etcd-backup/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="daily",
    ),
    Claim(
        name="adr0026-etcd-cronjob-daily",
        doc_path="docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md",
        anchor_regex=r"- \*\*CronJob\*\* \(03:00 UTC daily, two containers, the talos-drift pattern\):",
        source_path="clusters/talos-cluster/apps/dr-etcd-backup/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="daily",
    ),
    Claim(
        name="adr0026-etcd-cronjob-time",
        doc_path="docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md",
        anchor_regex=r"- \*\*CronJob\*\* \(03:00 UTC daily, two containers, the talos-drift pattern\):",
        source_path="clusters/talos-cluster/apps/dr-etcd-backup/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="time=03:00",
    ),
    Claim(
        name="adr0026-etcd-recurringjob-time",
        doc_path="docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md",
        anchor_regex=r"`etcd-daily-backup` RecurringJob \(03:47 UTC, retain 14\) to the volume;",
        source_path="clusters/talos-cluster/apps/longhorn-etcd-storage/recurringjob.yaml",
        source_kind="recurringjob_cron",
        expected="time=03:47",
    ),
    Claim(
        name="adr0026-etcd-recurringjob-retain",
        doc_path="docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md",
        anchor_regex=r"`etcd-daily-backup` RecurringJob \(03:47 UTC, retain 14\) to the volume;",
        source_path="clusters/talos-cluster/apps/longhorn-etcd-storage/recurringjob.yaml",
        source_kind="recurringjob_retain",
        expected="retain=14",
    ),
    Claim(
        name="adr0026-talos-drift-hourly",
        doc_path="docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md",
        anchor_regex=r"path must be revisited \(the drift detector exercises the same path hourly",
        source_path="clusters/talos-cluster/apps/talos-drift/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="hourly",
    ),
    Claim(
        name="runbook-stage1-vault-cron-daily",
        doc_path="docs/runbooks/dr-stage1-backup.md",
        anchor_regex=r'  cron: "17 8 \* \* \*"',
        source_path="clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml",
        source_kind="recurringjob_cron",
        expected="daily",
    ),
    Claim(
        name="runbook-stage1-vault-cron-time",
        doc_path="docs/runbooks/dr-stage1-backup.md",
        anchor_regex=r'  cron: "17 8 \* \* \*"',
        source_path="clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml",
        source_kind="recurringjob_cron",
        expected="time=08:17",
    ),
    Claim(
        name="runbook-stage1-vault-retain-code",
        doc_path="docs/runbooks/dr-stage1-backup.md",
        anchor_regex=r"  retain: 14",
        source_path="clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml",
        source_kind="recurringjob_retain",
        expected="retain=14",
    ),
    Claim(
        name="runbook-stage1-vault-retain-sentence",
        doc_path="docs/runbooks/dr-stage1-backup.md",
        anchor_regex=r"Retention is 14 Longhorn backups for the selected Vault volumes\.",
        source_path="clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml",
        source_kind="recurringjob_retain",
        expected="retain=14",
    ),
    Claim(
        name="architecture-vault-backup-daily",
        doc_path="docs/explanation/architecture.md",
        anchor_regex=r'VaultDailyBackup\["Longhorn RecurringJob vault-daily-backup<br/>backup cron 17 8 daily, retain 14"\]',
        source_path="clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml",
        source_kind="recurringjob_cron",
        expected="daily",
    ),
    Claim(
        name="architecture-vault-backup-time",
        doc_path="docs/explanation/architecture.md",
        anchor_regex=r'VaultDailyBackup\["Longhorn RecurringJob vault-daily-backup<br/>backup cron 17 8 daily, retain 14"\]',
        source_path="clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml",
        source_kind="recurringjob_cron",
        expected="time=08:17",
    ),
    Claim(
        name="architecture-vault-backup-retain",
        doc_path="docs/explanation/architecture.md",
        anchor_regex=r'VaultDailyBackup\["Longhorn RecurringJob vault-daily-backup<br/>backup cron 17 8 daily, retain 14"\]',
        source_path="clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml",
        source_kind="recurringjob_retain",
        expected="retain=14",
    ),
    Claim(
        name="architecture-etcd-cronjob-daily",
        doc_path="docs/explanation/architecture.md",
        anchor_regex=r'EtcdCronJob\["CronJob etcd-snapshot in dr-etcd-backup<br/>talosctl os:etcd:backup role, 03:00 daily<br/>whole-file age encryption, escrowed key"\]',
        source_path="clusters/talos-cluster/apps/dr-etcd-backup/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="daily",
    ),
    Claim(
        name="architecture-etcd-cronjob-time",
        doc_path="docs/explanation/architecture.md",
        anchor_regex=r'EtcdCronJob\["CronJob etcd-snapshot in dr-etcd-backup<br/>talosctl os:etcd:backup role, 03:00 daily<br/>whole-file age encryption, escrowed key"\]',
        source_path="clusters/talos-cluster/apps/dr-etcd-backup/cronjob.yaml",
        source_kind="cronjob_schedule",
        expected="time=03:00",
    ),
    Claim(
        name="architecture-etcd-recurringjob-daily",
        doc_path="docs/explanation/architecture.md",
        anchor_regex=r'EtcdDailyBackup\["Longhorn RecurringJob etcd-daily-backup<br/>backup cron 47 3 daily, retain 14<br/>detached-volume backup enabled"\]',
        source_path="clusters/talos-cluster/apps/longhorn-etcd-storage/recurringjob.yaml",
        source_kind="recurringjob_cron",
        expected="daily",
    ),
    Claim(
        name="architecture-etcd-recurringjob-time",
        doc_path="docs/explanation/architecture.md",
        anchor_regex=r'EtcdDailyBackup\["Longhorn RecurringJob etcd-daily-backup<br/>backup cron 47 3 daily, retain 14<br/>detached-volume backup enabled"\]',
        source_path="clusters/talos-cluster/apps/longhorn-etcd-storage/recurringjob.yaml",
        source_kind="recurringjob_cron",
        expected="time=03:47",
    ),
    Claim(
        name="architecture-etcd-recurringjob-retain",
        doc_path="docs/explanation/architecture.md",
        anchor_regex=r'EtcdDailyBackup\["Longhorn RecurringJob etcd-daily-backup<br/>backup cron 47 3 daily, retain 14<br/>detached-volume backup enabled"\]',
        source_path="clusters/talos-cluster/apps/longhorn-etcd-storage/recurringjob.yaml",
        source_kind="recurringjob_retain",
        expected="retain=14",
    ),
)


def load_yaml_documents(path: Path, loader: type[yaml.SafeLoader] = yaml.SafeLoader) -> list[Any]:
    with path.open(encoding="utf-8") as handle:
        return [document for document in yaml.load_all(handle, Loader=loader) if document is not None]


def load_single_mapping(path: Path, loader: type[yaml.SafeLoader] = yaml.SafeLoader) -> dict[str, Any]:
    documents = load_yaml_documents(path, loader)
    if len(documents) != 1:
        raise ValueError(f"{path} must contain exactly one YAML document, found {len(documents)}")
    document = documents[0]
    if not isinstance(document, dict):
        raise ValueError(f"{path} must parse to a YAML mapping")
    return document


def workflow_on(document: dict[str, Any]) -> Any:
    if "on" in document:
        return document["on"]
    if True in document:
        return document[True]
    return None


def workflow_schedule_entries(document: dict[str, Any]) -> Any:
    on_value = workflow_on(document)
    if not isinstance(on_value, dict):
        return None
    return on_value.get("schedule")


def first_workflow_cron(path: Path) -> str:
    document = load_single_mapping(path, WorkflowLoader)
    schedules = workflow_schedule_entries(document)
    if not isinstance(schedules, list) or not schedules:
        raise ValueError(f"{path} has no on.schedule entries")

    crons: list[str] = []
    for schedule in schedules:
        if isinstance(schedule, dict) and "cron" in schedule:
            cron = schedule["cron"]
            if not isinstance(cron, str):
                raise ValueError(f"{path} on.schedule cron must be a string")
            crons.append(cron)

    if len(crons) > 1:
        raise ValueError(f"{path} has multiple on.schedule cron values: {', '.join(crons)}")
    if not crons:
        raise ValueError(f"{path} has no on.schedule cron value")
    return crons[0]


def workflow_schedule_block(path: Path) -> tuple[bool, list[str]]:
    document = load_single_mapping(path, WorkflowLoader)
    on_value = workflow_on(document)
    if not isinstance(on_value, dict) or "schedule" not in on_value:
        return False, []

    schedules = on_value.get("schedule")
    crons: list[str] = []
    if isinstance(schedules, list):
        for schedule in schedules:
            if isinstance(schedule, dict) and isinstance(schedule.get("cron"), str):
                crons.append(schedule["cron"])
    return True, crons


def manifest_spec_value(path: Path, key: str) -> Any:
    document = load_single_mapping(path)
    spec = document.get("spec")
    if not isinstance(spec, dict) or key not in spec:
        raise ValueError(f"{path} must define spec.{key}")
    return spec[key]


def cronjob_schedule(path: Path) -> str:
    value = manifest_spec_value(path, "schedule")
    if not isinstance(value, str):
        raise ValueError(f"{path} spec.schedule must be a string")
    return value


def recurringjob_cron(path: Path) -> str:
    value = manifest_spec_value(path, "cron")
    if not isinstance(value, str):
        raise ValueError(f"{path} spec.cron must be a string")
    return value


def recurringjob_retain(path: Path) -> int:
    value = manifest_spec_value(path, "retain")
    if not isinstance(value, int):
        raise ValueError(f"{path} spec.retain must be an integer")
    return value


def cron_fields(cron: str) -> tuple[str, str, str, str, str]:
    fields = cron.split()
    if len(fields) != 5:
        raise ValueError(f"cron {cron!r} must have exactly 5 fields")
    return fields[0], fields[1], fields[2], fields[3], fields[4]


def is_decimal(value: str) -> bool:
    return re.fullmatch(r"[0-9]{1,2}", value) is not None


def classify_cron(cron: str) -> str:
    minute, hour, day_of_month, month, day_of_week = cron_fields(cron)
    if is_decimal(minute) and hour == "*" and day_of_month == "*" and month == "*" and day_of_week == "*":
        return "hourly"
    if is_decimal(minute) and is_decimal(hour) and day_of_month == "*" and month == "*" and day_of_week == "*":
        return "daily"
    if is_decimal(minute) and is_decimal(hour) and day_of_month == "*" and month == "*" and day_of_week != "*":
        return "weekly"
    return "other"


def cron_time(cron: str) -> str:
    minute, hour, _day_of_month, _month, _day_of_week = cron_fields(cron)
    if not is_decimal(minute) or not is_decimal(hour):
        return "other"
    return f"{int(hour):02d}:{int(minute):02d}"


def source_value(repo_root: Path, claim: Claim) -> str | int | bool:
    source = repo_root / claim.source_path

    if claim.source_kind == "workflow_cron":
        return first_workflow_cron(source)
    if claim.source_kind == "workflow_no_schedule":
        has_schedule, crons = workflow_schedule_block(source)
        if has_schedule:
            detail = ", ".join(crons) if crons else "present without cron values"
            raise ValueError(f"{source} unexpectedly defines on.schedule: {detail}")
        return False
    if claim.source_kind == "cronjob_schedule":
        return cronjob_schedule(source)
    if claim.source_kind == "recurringjob_cron":
        return recurringjob_cron(source)
    if claim.source_kind == "recurringjob_retain":
        return recurringjob_retain(source)

    raise ValueError(f"unsupported source_kind {claim.source_kind!r}")


def anchor_matches(repo_root: Path, claim: Claim) -> list[int]:
    path = repo_root / claim.doc_path
    pattern = re.compile(claim.anchor_regex)
    with path.open(encoding="utf-8") as handle:
        return [
            lineno
            for lineno, line in enumerate(handle, start=1)
            if pattern.search(line.rstrip("\n"))
        ]


def expected_matches(claim: Claim, actual: str | int | bool) -> tuple[bool, str]:
    if claim.expected in FREQUENCY_EXPECTATIONS:
        if not isinstance(actual, str):
            return False, f"expected {claim.expected}, got non-cron value {actual!r}"
        actual_frequency = classify_cron(actual)
        return (
            actual_frequency == claim.expected,
            f"expected {claim.expected}, source cron {actual!r} classifies as {actual_frequency}",
        )

    if claim.expected.startswith("time="):
        if not isinstance(actual, str):
            return False, f"expected {claim.expected}, got non-cron value {actual!r}"
        expected_time = claim.expected.removeprefix("time=")
        actual_time = cron_time(actual)
        return (
            actual_time == expected_time,
            f"expected time {expected_time}, source cron {actual!r} has time {actual_time}",
        )

    if claim.expected.startswith("retain="):
        if not isinstance(actual, int):
            return False, f"expected {claim.expected}, got non-retain value {actual!r}"
        expected_retain = int(claim.expected.removeprefix("retain="))
        return (
            actual == expected_retain,
            f"expected retain {expected_retain}, source retain is {actual}",
        )

    if claim.source_kind == "workflow_no_schedule" and claim.expected == "absent":
        return True, "expected no workflow schedule and source has none"

    raise ValueError(f"{claim.name}: unsupported expected value {claim.expected!r}")


def check_claim(repo_root: Path, claim: Claim) -> Failure | None:
    if claim.source_kind not in SOURCE_KINDS:
        return Failure(claim.name, f"unsupported source_kind {claim.source_kind!r}")

    try:
        matches = anchor_matches(repo_root, claim)
    except OSError as exc:
        return Failure(claim.name, f"failed to read doc anchor {claim.doc_path}: {exc}")
    except re.error as exc:
        return Failure(claim.name, f"invalid anchor_regex: {exc}")

    if len(matches) != 1:
        return Failure(
            claim.name,
            (
                f"{claim.doc_path} anchor_regex matched {len(matches)} lines "
                f"(expected exactly 1): {claim.anchor_regex}"
            ),
        )

    try:
        actual = source_value(repo_root, claim)
        ok, detail = expected_matches(claim, actual)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return Failure(claim.name, str(exc))

    if not ok:
        return Failure(claim.name, f"{claim.source_path}: {detail}")
    return None


def check_claims(repo_root: Path, claims: Sequence[Claim] = CLAIMS) -> CheckResult:
    failures = [
        failure
        for claim in claims
        for failure in [check_claim(repo_root, claim)]
        if failure is not None
    ]
    return CheckResult(checked=len(claims), failures=tuple(failures))


def exit_code(result: CheckResult) -> int:
    return 0 if result.ok else 1


def format_result(result: CheckResult) -> list[str]:
    if result.ok:
        return [f"PASS: {result.checked} curated doc schedule claims checked."]

    lines = [f"FAIL: {len(result.failures)} doc schedule claim violation(s):"]
    for failure in result.failures:
        lines.append(f"  - {failure.claim}: {failure.detail}")
    return lines


def main() -> int:
    result = check_claims(Path.cwd().resolve())
    for line in format_result(result):
        print(line)
    return exit_code(result)


if __name__ == "__main__":
    sys.exit(main())
