#!/usr/bin/env python3
"""Fail if tracked Markdown contains broken relative link targets."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


INLINE_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
REFERENCE_DEF_RE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s+(.+?)\s*$")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:", "//")


class GuardUsageError(Exception):
    """A tooling or input error that should exit with code 2."""


@dataclass(frozen=True)
class BrokenLink:
    file: str
    target: str


@dataclass(frozen=True)
class ScanResult:
    checked: int
    broken: tuple[BrokenLink, ...]

    @property
    def ok(self) -> bool:
        return not self.broken


def git_ls_markdown_files(repo_root: Path) -> list[str]:
    cmd = ["git", "-C", str(repo_root), "ls-files", "--", "*.md"]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise GuardUsageError("git is required to enumerate tracked markdown files") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or f"git ls-files exited {result.returncode}"
        raise GuardUsageError(detail)

    return [line for line in result.stdout.splitlines() if line]


def read_tracked_markdown(repo_root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for relpath in git_ls_markdown_files(repo_root):
        try:
            files[relpath] = (repo_root / relpath).read_text(encoding="utf-8")
        except OSError as exc:
            raise GuardUsageError(f"failed to read {relpath}: {exc}") from exc
    return files


def strip_fenced_code_blocks(text: str) -> str:
    lines: list[str] = []
    in_fence = False
    fence_marker = ""

    for line in text.splitlines(keepends=True):
        match = FENCE_RE.match(line)
        if match:
            marker = match.group(1)
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = ""
            lines.append("\n" if line.endswith("\n") else "")
            continue

        if in_fence:
            lines.append("\n" if line.endswith("\n") else "")
        else:
            lines.append(line)

    return "".join(lines)


def extract_raw_targets(text: str) -> list[str]:
    without_fences = strip_fenced_code_blocks(text)
    without_inline_code = INLINE_CODE_RE.sub("", without_fences)

    targets = [match.group(1) for match in INLINE_LINK_RE.finditer(without_inline_code)]
    for line in without_fences.splitlines():
        match = REFERENCE_DEF_RE.match(line)
        if match:
            targets.append(match.group(1))
    return targets


def target_path(raw_target: str) -> str | None:
    target = raw_target.strip()
    if not target:
        return None

    if target.startswith("<"):
        close = target.find(">")
        if close != -1:
            path = target[1:close].strip()
        else:
            path = target.strip("<>").strip()
    else:
        path = target.split(None, 1)[0].strip()
        if path.startswith("<") and path.endswith(">"):
            path = path[1:-1].strip()

    path = path.split("#", 1)[0]
    if not path or path.startswith(EXTERNAL_PREFIXES):
        return None
    return path


def resolve_target(md_relpath: str, target: str, repo_root: Path) -> Path:
    if target.startswith("/"):
        raw_path = repo_root / target.lstrip("/")
    else:
        raw_path = repo_root / Path(md_relpath).parent / target
    return Path(os.path.normpath(raw_path))


def scan(files: Mapping[str, str], repo_root: Path) -> ScanResult:
    checked = 0
    broken: list[BrokenLink] = []

    for relpath, text in files.items():
        for raw_target in extract_raw_targets(text):
            target = target_path(raw_target)
            if target is None:
                continue

            checked += 1
            if not resolve_target(relpath, target, repo_root).exists():
                broken.append(BrokenLink(file=relpath, target=target))

    return ScanResult(checked=checked, broken=tuple(broken))


def find_broken_links(md_relpath: str, text: str, repo_root: Path) -> list[str]:
    result = scan({md_relpath: text}, repo_root)
    return [broken.target for broken in result.broken]


def exit_code(result: ScanResult) -> int:
    return 0 if result.ok else 1


def main() -> int:
    repo_root = Path.cwd().resolve()

    try:
        files = read_tracked_markdown(repo_root)
        result = scan(files, repo_root)
    except GuardUsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if result.broken:
        print(f"ERROR: {len(result.broken)} broken relative markdown links:")
        for broken in result.broken:
            print(f"  {broken.file}  ->  {broken.target}")
        return 1

    print(f"PASS: {result.checked} relative link targets checked, all resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
