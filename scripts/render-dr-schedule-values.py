#!/usr/bin/env python3
"""Render DR schedule and retention values from canonical manifests."""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


ETCD_CRONJOB = Path("clusters/talos-cluster/apps/dr-etcd-backup/cronjob.yaml")
ETCD_RECURRINGJOB = Path("clusters/talos-cluster/apps/longhorn-etcd-storage/recurringjob.yaml")
VAULT_RECURRINGJOB = Path(
    "clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml"
)
ETCD_ENCRYPT_SCRIPT = Path("clusters/talos-cluster/apps/dr-etcd-backup/configmap-encrypt-script.yaml")

ADR_0026 = Path("docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md")
DR_STAGE1_RUNBOOK = Path("docs/runbooks/dr-stage1-backup.md")
ARCHITECTURE = Path("docs/explanation/architecture.md")


class RenderError(RuntimeError):
    """Raised when a canonical source or documentation target cannot be resolved."""


@dataclass(frozen=True)
class DailyCron:
    raw: str
    minute: str
    hour: str
    clock: str


@dataclass(frozen=True)
class DrScheduleValues:
    etcd_snapshot: DailyCron
    etcd_longhorn: DailyCron
    etcd_longhorn_retain: int
    vault_longhorn: DailyCron
    vault_longhorn_retain: int
    etcd_local_retain: int


@dataclass(frozen=True)
class RenderedDocument:
    path: Path
    current: str
    rendered: str


def read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except FileNotFoundError as exc:
        raise RenderError(f"missing required file: {path}") from exc
    except UnicodeDecodeError as exc:
        raise RenderError(f"{path} is not valid UTF-8") from exc


def load_single_mapping(path: Path) -> dict[str, object]:
    try:
        documents = [document for document in yaml.safe_load_all(read_text(path)) if document is not None]
    except yaml.YAMLError as exc:
        raise RenderError(f"{path} is not valid YAML: {exc}") from exc

    if len(documents) != 1:
        raise RenderError(f"{path} must contain exactly one YAML document, found {len(documents)}")
    document = documents[0]
    if not isinstance(document, dict):
        raise RenderError(f"{path} must parse to a YAML mapping")
    return document


def manifest_spec_value(path: Path, key: str) -> object:
    document = load_single_mapping(path)
    if "spec" not in document:
        raise RenderError(f"{path} missing required spec mapping")
    spec = document["spec"]
    if not isinstance(spec, dict):
        raise RenderError(f"{path} spec must be a mapping")
    if key not in spec:
        raise RenderError(f"{path} missing required spec.{key}")
    return spec[key]


def spec_string(path: Path, key: str) -> str:
    value = manifest_spec_value(path, key)
    if not isinstance(value, str):
        raise RenderError(f"{path} spec.{key} must be a string")
    return value


def spec_int(path: Path, key: str) -> int:
    value = manifest_spec_value(path, key)
    if type(value) is not int:
        raise RenderError(f"{path} spec.{key} must be an integer")
    return value


def parse_daily_cron(path: Path, field_name: str, cron: str) -> DailyCron:
    fields = cron.split()
    if len(fields) != 5:
        raise RenderError(f"{path} spec.{field_name} cron {cron!r} must have exactly 5 fields")

    minute, hour, day_of_month, month, day_of_week = fields
    if (day_of_month, month, day_of_week) != ("*", "*", "*"):
        raise RenderError(
            f"{path} spec.{field_name} cron {cron!r} fields 3-5 must all be '*'"
        )
    if re.fullmatch(r"[0-9]+", minute) is None or re.fullmatch(r"[0-9]+", hour) is None:
        raise RenderError(f"{path} spec.{field_name} cron {cron!r} minute/hour must be integers")

    minute_number = int(minute)
    hour_number = int(hour)
    if minute_number > 59 or hour_number > 23:
        raise RenderError(f"{path} spec.{field_name} cron {cron!r} minute/hour out of range")

    return DailyCron(
        raw=cron,
        minute=minute,
        hour=hour,
        clock=f"{hour_number:02d}:{minute_number:02d}",
    )


def recurringjob_retain(path: Path) -> int:
    return spec_int(path, "retain")


def etcd_local_retention(path: Path) -> int:
    pattern = (
        r"(?m)^    ls -1 /data/etcd-\*\.db\.sops\.json \| sort "
        r"\| head -n -([0-9]+) \| while read -r old; do$"
    )
    matches = re.findall(pattern, read_text(path))
    if len(matches) != 1:
        raise RenderError(f"{path} etcd local retention prune line must occur exactly once, found {len(matches)}")
    return int(matches[0])


def collect_values(root: Path = Path(".")) -> DrScheduleValues:
    etcd_cronjob = root / ETCD_CRONJOB
    etcd_recurringjob = root / ETCD_RECURRINGJOB
    vault_recurringjob = root / VAULT_RECURRINGJOB

    return DrScheduleValues(
        etcd_snapshot=parse_daily_cron(etcd_cronjob, "schedule", spec_string(etcd_cronjob, "schedule")),
        etcd_longhorn=parse_daily_cron(etcd_recurringjob, "cron", spec_string(etcd_recurringjob, "cron")),
        etcd_longhorn_retain=recurringjob_retain(etcd_recurringjob),
        vault_longhorn=parse_daily_cron(vault_recurringjob, "cron", spec_string(vault_recurringjob, "cron")),
        vault_longhorn_retain=recurringjob_retain(vault_recurringjob),
        etcd_local_retain=etcd_local_retention(root / ETCD_ENCRYPT_SCRIPT),
    )


def replace_once(pattern: str, replacement: str, text: str, description: str) -> str:
    rendered, count = re.subn(pattern, replacement, text, count=0, flags=re.MULTILINE)
    if count != 1:
        raise RenderError(f"documentation target for {description} must occur exactly once, found {count}")
    return rendered


def render_adr_0026(text: str, values: DrScheduleValues) -> str:
    rendered = text
    rendered = replace_once(
        r"^(- \*\*CronJob\*\* \()([0-9]{2}:[0-9]{2})( UTC daily, two containers, the talos-drift pattern\):)$",
        rf"\g<1>{values.etcd_snapshot.clock}\g<3>",
        rendered,
        "ADR-0026 etcd CronJob HH:MM UTC",
    )
    rendered = replace_once(
        r"^(  `etcd-snapshots` PVC \(`longhorn-etcd-snapshot` StorageClass\), prunes to )([0-9]+)$",
        rf"\g<1>{values.etcd_local_retain}",
        rendered,
        "ADR-0026 etcd local retention",
    )
    rendered = replace_once(
        r"^(  `etcd-daily-backup` RecurringJob \()([0-9]{2}:[0-9]{2})( UTC, retain )([0-9]+)(\) to the volume;)$",
        rf"\g<1>{values.etcd_longhorn.clock}\g<3>{values.etcd_longhorn_retain}\g<5>",
        rendered,
        "ADR-0026 etcd Longhorn backup time and retention",
    )
    rendered = replace_once(
        r"^(- ~110 MB snapshot \N{RIGHTWARDS ARROW} ~147 MB ciphertext daily; )([0-9]+)( local \+ )([0-9]+)( Synology copies)$",
        rf"\g<1>{values.etcd_local_retain}\g<3>{values.etcd_longhorn_retain}\g<5>",
        rendered,
        "ADR-0026 etcd local and Synology retention",
    )
    return rendered


def render_dr_stage1_runbook(text: str, values: DrScheduleValues) -> str:
    rendered = text
    rendered = replace_once(
        (
            r"^(apiVersion: longhorn\.io/v1beta2\n"
            r"kind: RecurringJob\n"
            r"metadata:\n"
            r"  name: vault-daily-backup\n"
            r"  namespace: longhorn-system\n"
            r"spec:\n"
            r"  task: backup\n"
            r'  cron: )"([^"]+)"(\n'
            r"  retain: )([0-9]+)(\n"
            r"  concurrency: 1\n"
            r"  groups:\n"
            r"    - default)$"
        ),
        rf'\g<1>"{values.vault_longhorn.raw}"\g<3>{values.vault_longhorn_retain}\g<5>',
        rendered,
        "DR Stage 1 runbook Vault backup raw cron and retention",
    )
    rendered = replace_once(
        r"^(Retention is )([0-9]+)( Longhorn backups for the selected Vault volumes\. Treat this as)$",
        rf"\g<1>{values.vault_longhorn_retain}\g<3>",
        rendered,
        "DR Stage 1 runbook Vault backup retention sentence",
    )
    return rendered


def render_architecture(text: str, values: DrScheduleValues) -> str:
    rendered = text
    rendered = replace_once(
        r'^(    VaultDailyBackup\["Longhorn RecurringJob vault-daily-backup<br/>backup cron )([0-9]+)( )([0-9]+)( daily, retain )([0-9]+)("\])$',
        rf"\g<1>{values.vault_longhorn.minute}\g<3>{values.vault_longhorn.hour}\g<5>{values.vault_longhorn_retain}\g<7>",
        rendered,
        "architecture Vault backup Mermaid label",
    )
    rendered = replace_once(
        r'^(    EtcdCronJob\["CronJob etcd-snapshot in dr-etcd-backup<br/>talosctl os:etcd:backup role, )([0-9]{2}:[0-9]{2})( daily<br/>whole-file age encryption, escrowed key"\])$',
        rf"\g<1>{values.etcd_snapshot.clock}\g<3>",
        rendered,
        "architecture etcd CronJob HH:MM daily Mermaid label",
    )
    rendered = replace_once(
        r'^(    EtcdPVC\["PVC etcd-snapshots<br/>storageClassName longhorn-etcd-snapshot<br/>)([0-9]+)( encrypted local dailies"\])$',
        rf"\g<1>{values.etcd_local_retain}\g<3>",
        rendered,
        "architecture etcd local retention Mermaid label",
    )
    rendered = replace_once(
        r'^(    EtcdDailyBackup\["Longhorn RecurringJob etcd-daily-backup<br/>backup cron )([0-9]+)( )([0-9]+)( daily, retain )([0-9]+)(<br/>detached-volume backup enabled"\])$',
        rf"\g<1>{values.etcd_longhorn.minute}\g<3>{values.etcd_longhorn.hour}\g<5>{values.etcd_longhorn_retain}\g<7>",
        rendered,
        "architecture etcd Longhorn backup Mermaid label",
    )
    return rendered


def render_documents(root: Path = Path(".")) -> list[RenderedDocument]:
    values = collect_values(root)
    renderers = (
        (ADR_0026, render_adr_0026),
        (DR_STAGE1_RUNBOOK, render_dr_stage1_runbook),
        (ARCHITECTURE, render_architecture),
    )

    documents: list[RenderedDocument] = []
    for path, renderer in renderers:
        current = read_text(root / path)
        documents.append(RenderedDocument(path=path, current=current, rendered=renderer(current, values)))
    return documents


def write_rendered(documents: Sequence[RenderedDocument], root: Path = Path(".")) -> None:
    for document in documents:
        (root / document.path).write_text(document.rendered, encoding="utf-8", newline="\n")


def print_diff(document: RenderedDocument) -> None:
    diff = difflib.unified_diff(
        document.current.splitlines(keepends=True),
        document.rendered.splitlines(keepends=True),
        fromfile=f"{document.path} (current)",
        tofile=f"{document.path} (expected)",
    )
    sys.stderr.writelines(diff)


def main(argv: Sequence[str] | None = None, root: Path = Path(".")) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if rendered DR schedule values are stale")
    args = parser.parse_args(argv)

    try:
        documents = render_documents(root)
    except RenderError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        # Deliberate divergence from render-readme-versions.py: exit 1 means
        # stale docs, while exit 2 means the renderer, anchors, or sources broke.
        return 2

    stale = [document for document in documents if document.current != document.rendered]
    if args.check:
        if stale:
            print(
                "DR schedule values are stale; run scripts/render-dr-schedule-values.py",
                file=sys.stderr,
            )
            for document in stale:
                print_diff(document)
            return 1
        print("DR schedule values match canonical sources")
        return 0

    write_rendered(documents, root)
    for document in documents:
        print(f"wrote {document.path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
