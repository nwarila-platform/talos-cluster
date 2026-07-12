#!/usr/bin/env python3
"""Fail if Renovate annotations are not covered by a Renovate manager."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Pattern, Sequence


RENOVATE_CONFIG = Path(".github/renovate.json5")
RENOVATE_MARKER = "# renovate:"
WORKFLOW_RE = re.compile(r"^\.github/workflows/.+\.ya?ml$")
USES_LINE_RE = re.compile(r"^\s*uses\s*:")
BARE_KEY_RE = re.compile(r"(?m)^(\s*)([A-Za-z_$][A-Za-z0-9_$-]*)\s*:")
TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")


@dataclass(frozen=True)
class Annotation:
    path: str
    line: int
    text: str


class GuardUsageError(Exception):
    """A tooling or input error that should exit with code 2."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan tracked files for Renovate annotations without manager coverage."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="repository root to scan (default: current directory)",
    )
    return parser.parse_args()


def strip_json5_line_comments(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        in_string = False
        quote = ""
        escaped = False
        comment_index: int | None = None

        for index, char in enumerate(line):
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    in_string = False
                continue

            if char in {'"', "'"}:
                in_string = True
                quote = char
                continue

            if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
                comment_index = index
                break

        if comment_index is not None:
            line = line[:comment_index]
        lines.append(line)

    return "\n".join(lines)


def normalize_json5_for_json_loads(text: str) -> str:
    stripped = strip_json5_line_comments(text)
    quoted_keys = BARE_KEY_RE.sub(r'\1"\2":', stripped)
    previous = None
    current = quoted_keys
    while previous != current:
        previous = current
        current = TRAILING_COMMA_RE.sub(r"\1", current)
    return current


def parse_renovate_config(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
        parsed = json.loads(normalize_json5_for_json_loads(raw))
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardUsageError(f"failed to parse {path}: {exc}") from exc

    if not isinstance(parsed, dict):
        raise GuardUsageError(f"{path} did not parse to an object")
    return parsed


def renovate_pattern_to_regex(pattern: str) -> str:
    if len(pattern) >= 2 and pattern.startswith("/") and pattern.endswith("/"):
        return pattern[1:-1]
    return pattern


def custom_manager_patterns(config: Mapping[str, object]) -> list[Pattern[str]]:
    managers = config.get("customManagers", [])
    if not isinstance(managers, list):
        raise GuardUsageError("customManagers must be a list")

    patterns: list[Pattern[str]] = []
    for index, manager in enumerate(managers, start=1):
        if not isinstance(manager, dict):
            raise GuardUsageError(f"customManagers[{index}] must be an object")
        manager_patterns = manager.get("managerFilePatterns", [])
        if not isinstance(manager_patterns, list):
            raise GuardUsageError(
                f"customManagers[{index}].managerFilePatterns must be a list"
            )
        for pattern in manager_patterns:
            if not isinstance(pattern, str):
                raise GuardUsageError(
                    f"customManagers[{index}].managerFilePatterns entries must be strings"
                )
            regex_text = renovate_pattern_to_regex(pattern)
            try:
                patterns.append(re.compile(regex_text))
            except re.error as exc:
                raise GuardUsageError(
                    f"invalid managerFilePatterns regex {pattern!r}: {exc}"
                ) from exc
    return patterns


def git_tracked_files(repo_root: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise GuardUsageError(f"failed to run git ls-files: {exc}") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise GuardUsageError(f"git ls-files failed{detail}")

    return [line for line in result.stdout.splitlines() if line]


def should_scan_path(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in {".md", ".markdown"}:
        return False
    if path in {
        "scripts/check-renovate-coverage.py",
        "scripts/check-renovate-coverage.selftest.py",
    }:
        # These guard files legitimately contain the '# renovate:' marker as the
        # guard's own constant and self-test fixtures, not real annotations.
        # Scanning them would make the guard self-flag.
        return False
    return path != RENOVATE_CONFIG.as_posix()


def load_file_texts(repo_root: Path, paths: Sequence[str]) -> dict[str, str]:
    texts: dict[str, str] = {}
    for path in paths:
        if not should_scan_path(path):
            continue
        try:
            texts[path] = (repo_root / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise GuardUsageError(f"failed to read {path}: {exc}") from exc
    return texts


def is_uses_adjacent_workflow_annotation(
    path: str, lines: Sequence[str], line_index: int
) -> bool:
    if not WORKFLOW_RE.match(path):
        return False
    next_index = line_index + 1
    if next_index >= len(lines):
        return False
    return USES_LINE_RE.match(lines[next_index]) is not None


def path_matches_manager(path: str, patterns: Sequence[Pattern[str]]) -> bool:
    return any(pattern.search(path) for pattern in patterns)


def find_orphaned_annotations(
    file_texts: Mapping[str, str], patterns: Sequence[Pattern[str]]
) -> tuple[int, list[Annotation]]:
    checked = 0
    orphaned: list[Annotation] = []
    for path in sorted(file_texts):
        if not should_scan_path(path):
            continue
        lines = file_texts[path].splitlines()
        path_covered = path_matches_manager(path, patterns)
        for index, line in enumerate(lines):
            if RENOVATE_MARKER not in line:
                continue
            checked += 1
            if path_covered or is_uses_adjacent_workflow_annotation(path, lines, index):
                continue
            orphaned.append(Annotation(path=path, line=index + 1, text=line.strip()))
    return checked, orphaned


def print_orphaned(orphaned: Sequence[Annotation]) -> None:
    for annotation in orphaned:
        print(
            "ERROR: orphaned Renovate annotation: "
            f"{annotation.path}:{annotation.line} ({annotation.text})",
            file=sys.stderr,
        )
    print(
        "Add a Renovate customManagers entry covering the file, or remove the dead "
        "annotation.",
        file=sys.stderr,
    )


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()

    try:
        config = parse_renovate_config(repo_root / RENOVATE_CONFIG)
        patterns = custom_manager_patterns(config)
        tracked_files = git_tracked_files(repo_root)
        file_texts = load_file_texts(repo_root, tracked_files)
    except GuardUsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    checked, orphaned = find_orphaned_annotations(file_texts, patterns)
    if orphaned:
        print_orphaned(orphaned)
        return 1

    print(f"PASS: {checked} Renovate annotations checked, all covered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
