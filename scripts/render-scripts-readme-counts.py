#!/usr/bin/env python3
"""Render scripts/README.md line counts from the script files themselves."""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

SCRIPTS_DIR = Path("scripts")
README = SCRIPTS_DIR / "README.md"
ROW_PATTERN = re.compile(
    r"(?m)^"
    r"(?P<prefix>\| `(?P<display>[^`]+(?:\.py|\.sh))` \()"
    r"\s*(?P<count>[0-9]+)\s*"
    r"(?P<suffix>\) \|)"
)
LOOSE_ROW_PATTERN = re.compile(r"(?m)^\|\s*`[^`]+\.(?:py|sh)`\s*\(\s*[0-9]+\s*\)")
FENCE_MARKERS = ("```", "~~~")


class RenderError(RuntimeError):
    """Raised when a README row or cited script cannot be resolved."""


@dataclass(frozen=True)
class RenderedDocument:
    path: Path
    current: str
    rendered: str
    row_count: int


def read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except FileNotFoundError as exc:
        raise RenderError(f"missing required file: {path}") from exc
    except UnicodeDecodeError as exc:
        raise RenderError(f"{path} is not valid UTF-8") from exc
    except OSError as exc:
        raise RenderError(f"failed to read {path}: {exc}") from exc


def wc_line_count(path: Path) -> int:
    try:
        return path.read_bytes().count(b"\n")
    except FileNotFoundError as exc:
        raise RenderError(f"missing required file: {path}") from exc
    except OSError as exc:
        raise RenderError(f"failed to read {path}: {exc}") from exc


def validate_display_path(display: str) -> Path:
    relpath = Path(display)
    if relpath.is_absolute() or ".." in relpath.parts:
        raise RenderError(f"invalid script path in README row: {display!r}")
    return relpath


def resolve_script_path(display: str, root: Path = Path(".")) -> Path:
    relpath = validate_display_path(display)
    scripts_dir = root / SCRIPTS_DIR
    if not scripts_dir.is_dir():
        raise RenderError(f"missing required directory: {scripts_dir}")
    literal = scripts_dir / relpath
    if literal.is_file():
        return literal
    basename = relpath.name
    matches = sorted(path for path in scripts_dir.rglob(basename) if path.is_file())
    if not matches:
        raise RenderError(
            f"unresolved script name {display!r}: no file at {literal} and no {basename!r} under {scripts_dir}"
        )
    if len(matches) > 1:
        formatted = ", ".join(str(path) for path in matches)
        raise RenderError(f"ambiguous script name {display!r}: {basename!r} matches {formatted}")
    return matches[0]




def render_readme(root: Path = Path(".")) -> RenderedDocument:
    current = read_text(root / README)
    row_count = 0
    listed_rows: set[str] = set()
    loose_only_rows: list[str] = []

    def replace_row(match: re.Match[str]) -> str:
        nonlocal row_count
        row_count += 1
        display = match.group("display")
        # Row IDENTITY, normalised: a row may legitimately cite "check-x.py",
        # "./check-x.py", or a nested "vault-config/check-x.py". Comparing basenames of
        # real rows is what makes the coverage check below trustworthy.
        listed_rows.add(Path(display).name)
        line_count = wc_line_count(resolve_script_path(display, root=root))
        return f"{match.group('prefix')}{line_count}{match.group('suffix')}"

    rendered_lines: list[str] = []
    in_fence = False
    for lineno, line in enumerate(current.splitlines(keepends=True), start=1):
        stripped = line.strip()
        fenced = stripped.startswith(FENCE_MARKERS)
        in_fence = not in_fence if fenced else in_fence
        if not in_fence and not fenced:
            if LOOSE_ROW_PATTERN.search(line) and ROW_PATTERN.search(line) is None:
                loose_only_rows.append(f"line {lineno}: {line.rstrip()}")
            line = ROW_PATTERN.sub(replace_row, line)
        rendered_lines.append(line)
    if in_fence:
        raise RenderError("scripts/README.md has an unclosed code fence")
    if row_count == 0:
        raise RenderError("scripts/README.md manifest table format is unrecognised: no `name` (N) rows found")
    if loose_only_rows:
        raise RenderError(
            "scripts/README.md row(s) look like manifest entries but did not match the expected cell format"
            f" ({row_count} strict rows, {row_count + len(loose_only_rows)} loose rows): {'; '.join(loose_only_rows)}"
        )

    # COVERAGE, not just freshness. Refreshing the wc -l of rows that EXIST cannot notice a
    # guard that was never listed at all, so a new guard could stay invisible in the audit
    # manifest forever while this check reported green — the "derived value drifts, and no
    # guard watches it" blind spot. Adding a guard must therefore also add its row.
    # Membership is tested against PARSED ROW IDENTITIES, never a substring search of the
    # document: scanning the raw text accepted a mere prose mention of a guard as though it
    # were a manifest row, and rejected a legitimate "./check-x.py" row because the literal
    # backticked basename did not appear.
    unlisted = [
        path.name
        for path in sorted((root / "scripts").glob("check-*.py"))
        if not path.name.endswith(".selftest.py") and path.name not in listed_rows
    ]
    if unlisted:
        raise RenderError(
            "scripts/README.md is the guard audit manifest but is MISSING a row for: "
            + ", ".join(unlisted)
            + " — add each guard's row (a missing row cannot be detected by refreshing existing rows)"
        )

    rendered = "".join(rendered_lines)
    return RenderedDocument(path=README, current=current, rendered=rendered, row_count=row_count)


def write_rendered(document: RenderedDocument, root: Path = Path(".")) -> None:
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
    parser.add_argument("--check", action="store_true", help="fail if scripts/README.md line counts are stale")
    args = parser.parse_args(argv)
    try:
        document = render_readme(root)
    except RenderError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        # Exit 1 means stale generated docs; exit 2 means the renderer, anchors,
        # or source files cannot be resolved.
        return 2
    stale = document.current != document.rendered
    if args.check:
        if stale:
            print(
                f"scripts/README.md line counts are stale; run scripts/render-scripts-readme-counts.py "
                f"({document.row_count} rows)",
                file=sys.stderr,
            )
            print_diff(document)
            return 1
        print(f"scripts/README.md line counts match script wc -l sources ({document.row_count} rows)")
        return 0
    write_rendered(document, root)
    print(f"wrote {document.path} ({document.row_count} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
