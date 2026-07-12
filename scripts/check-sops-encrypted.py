#!/usr/bin/env python3
"""Fail if git-tracked SOPS-named secrets are not actually encrypted.

The default scan uses ``git ls-files`` so CI checks only tracked files matching
``*.sops.yaml``, ``*.sops.yml``, or ``*.sops.json``. This is intentional for a
deny-all ``.gitignore`` repository: untracked scratch files are outside the CI
contract.

The repo-root ``.sops.yaml`` is the SOPS creation-rules config, not an
encrypted secret, even though its basename matches the scan pattern. This guard
skips SOPS config files identified by either the dotfile config basename
(``.sops.yaml``, ``.sops.yml``, ``.sops.json``) or by a top-level
``creation_rules`` key with no top-level ``sops`` metadata mapping. Skipping
those config files is correct coverage, not a gap.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


SOPS_SUFFIXES = (".sops.yaml", ".sops.yml", ".sops.json")
CONFIG_BASENAMES = {".sops.yaml", ".sops.yml", ".sops.json"}
RECIPIENT_KEYS = ("age", "kms", "pgp", "gcp_kms", "azure_kv", "hc_vault")


class GuardUsageError(Exception):
    """A tooling or input error that should exit with code 2."""


@dataclass(frozen=True)
class CheckResult:
    path: Path
    status: str
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status in {"secret", "skip"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify that tracked *.sops.yaml/*.sops.yml/*.sops.json files "
            "contain real SOPS encryption metadata and at least one encrypted "
            "payload value."
        )
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help=(
            "tracked repo roots/files to scan (default: whole repo); explicit "
            "files may also be passed for scratch-fixture checks"
        ),
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="repository root used for git ls-files (default: current directory)",
    )
    return parser.parse_args()


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def is_sops_candidate(path: Path) -> bool:
    return path.name.endswith(SOPS_SUFFIXES)


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def git_ls_files(repo_root: Path) -> list[Path]:
    cmd = [
        "git",
        "-C",
        str(repo_root),
        "ls-files",
        "--",
        "*.sops.yaml",
        "*.sops.yml",
        "*.sops.json",
    ]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise GuardUsageError("git is required to enumerate tracked files") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or f"git ls-files exited {result.returncode}"
        raise GuardUsageError(detail)

    return [repo_root / line for line in result.stdout.splitlines() if line]


def iter_direct_paths(path: Path) -> list[Path]:
    if path.is_file():
        if not is_sops_candidate(path):
            raise GuardUsageError(f"{path} is not a SOPS-named YAML/JSON file")
        return [path]
    if path.is_dir():
        return sorted(
            candidate
            for candidate in path.rglob("*")
            if candidate.is_file() and is_sops_candidate(candidate)
        )
    raise GuardUsageError(f"{path} does not exist")


def iter_candidate_paths(repo_root: Path, inputs: Iterable[Path]) -> list[Path]:
    repo_root = repo_root.resolve()
    input_paths = list(inputs)
    tracked_paths = git_ls_files(repo_root)
    if not input_paths:
        return tracked_paths

    selected: set[Path] = set()
    for raw_path in input_paths:
        path = raw_path if raw_path.is_absolute() else repo_root / raw_path
        path = path.resolve()

        if is_relative_to(path, repo_root) and path.is_dir():
            selected.update(
                tracked_path
                for tracked_path in tracked_paths
                if is_relative_to(tracked_path.resolve(), path)
            )
            continue

        selected.update(iter_direct_paths(path))

    return sorted(selected, key=display_path)


def load_single_mapping(path: Path) -> tuple[dict[object, object] | None, str | None]:
    try:
        with path.open(encoding="utf-8") as handle:
            if path.name.endswith(".sops.json"):
                document = json.load(handle)
            else:
                document = yaml.safe_load(handle)
    except json.JSONDecodeError as exc:
        return None, f"does not parse as JSON: {exc}"
    except yaml.YAMLError as exc:
        return None, f"does not parse as a single YAML document: {exc}"
    except OSError as exc:
        raise GuardUsageError(f"failed to read {path}: {exc}") from exc

    if not isinstance(document, dict):
        return None, "does not parse as a single top-level mapping"
    return document, None


def has_recipient_list(sops_metadata: dict[object, object]) -> bool:
    return any(
        isinstance(sops_metadata.get(key), list) and len(sops_metadata[key]) > 0
        for key in RECIPIENT_KEYS
    )


def has_encrypted_value(value: object) -> bool:
    if isinstance(value, str):
        return value.startswith("ENC[")
    if isinstance(value, dict):
        return any(has_encrypted_value(child) for child in value.values())
    if isinstance(value, list):
        return any(has_encrypted_value(child) for child in value)
    return False


def has_encrypted_payload(document: dict[object, object]) -> bool:
    return any(
        has_encrypted_value(value)
        for key, value in document.items()
        if key != "sops"
    )


def check_sops_file(path: Path) -> CheckResult:
    if path.name in CONFIG_BASENAMES:
        return CheckResult(path=path, status="skip", reason="SOPS creation-rules config")

    document, error = load_single_mapping(path)
    if error is not None:
        return CheckResult(path=path, status="violation", reason=error)
    assert document is not None

    if "creation_rules" in document and "sops" not in document:
        return CheckResult(path=path, status="skip", reason="SOPS creation-rules config")

    sops_metadata = document.get("sops")
    if not isinstance(sops_metadata, dict):
        return CheckResult(path=path, status="violation", reason="missing top-level sops mapping")

    mac = sops_metadata.get("mac")
    if not isinstance(mac, str) or not mac.strip():
        return CheckResult(path=path, status="violation", reason="sops.mac is missing or empty")

    if not has_recipient_list(sops_metadata):
        return CheckResult(
            path=path,
            status="violation",
            reason="sops metadata has no non-empty recipient list",
        )

    if not has_encrypted_payload(document):
        return CheckResult(
            path=path,
            status="violation",
            reason="no ENC[...] value exists outside the sops metadata block",
        )

    return CheckResult(path=path, status="secret")


def main() -> int:
    args = parse_args()

    try:
        paths = iter_candidate_paths(args.repo_root, args.paths)
        results = [check_sops_file(path) for path in paths]
    except GuardUsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    violations = [result for result in results if result.status == "violation"]
    if violations:
        print("ERROR: SOPS-encrypted secret guard failed:", file=sys.stderr)
        for result in violations:
            print(f"ERROR: {display_path(result.path)}: {result.reason}", file=sys.stderr)
        return 1

    verified = sum(1 for result in results if result.status == "secret")
    skipped = sum(1 for result in results if result.status == "skip")
    config_word = "config" if skipped == 1 else "configs"
    print(f"PASS: {verified} secret files verified, {skipped} {config_word} skipped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
