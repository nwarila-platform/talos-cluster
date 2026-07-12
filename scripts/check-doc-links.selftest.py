#!/usr/bin/env python3
"""Regression self-test for the Markdown doc-link guard."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-doc-links.py"


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected: tuple[str, ...]
    actual: tuple[str, ...]
    passed: bool


def load_guard_module():
    spec = importlib.util.spec_from_file_location("check_doc_links", GUARD)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {GUARD}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_file(root: Path, relpath: str, content: str = "") -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run_case(guard_module: object, root: Path, name: str, relpath: str, text: str) -> CaseResult:
    result = guard_module.scan({relpath: textwrap.dedent(text).strip() + "\n"}, root)
    actual = tuple(f"{broken.file}->{broken.target}" for broken in result.broken)
    expected = EXPECTED[name]
    return CaseResult(
        name=name,
        expected=expected,
        actual=actual,
        passed=actual == expected,
    )


def print_table(results: list[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected  actual  result")
    print(f"{'-' * name_width}  --------  ------  ------")
    for result in results:
        expected = ",".join(result.expected) if result.expected else "-"
        actual = ",".join(result.actual) if result.actual else "-"
        status = "PASS" if result.passed else "FAIL"
        print(f"{result.name:<{name_width}}  {expected:<8}  {actual:<6}  {status}")


EXPECTED = {
    "valid-inline": (),
    "broken-inline": ("docs/page.md->missing.md",),
    "images": ("docs/page.md->missing.png",),
    "references": ("docs/page.md->nope.md",),
    "code-is-skipped": (),
    "external-and-anchor": (),
    "root-relative": ("docs/page.md->/missing-root.md",),
}


def main() -> int:
    try:
        guard_module = load_guard_module()
        with tempfile.TemporaryDirectory(prefix="doc-link-guard-") as tmpdir:
            root = Path(tmpdir)
            write_file(root, "docs/real.md", "real\n")
            write_file(root, "docs/x.png")
            write_file(root, "root.md", "root\n")

            results = [
                run_case(
                    guard_module,
                    root,
                    "valid-inline",
                    "docs/page.md",
                    "[real](real.md)",
                ),
                run_case(
                    guard_module,
                    root,
                    "broken-inline",
                    "docs/page.md",
                    "[missing](missing.md)",
                ),
                run_case(
                    guard_module,
                    root,
                    "images",
                    "docs/page.md",
                    "![ok](x.png)\n![bad](missing.png)",
                ),
                run_case(
                    guard_module,
                    root,
                    "references",
                    "docs/page.md",
                    "[x]: real.md\n[y]: nope.md",
                ),
                run_case(
                    guard_module,
                    root,
                    "code-is-skipped",
                    "docs/page.md",
                    """
                    `[-a-z0-9]*[a-z0-9]`

                    ```markdown
                    [bad](missing.md)
                    ```
                    """,
                ),
                run_case(
                    guard_module,
                    root,
                    "external-and-anchor",
                    "docs/page.md",
                    """
                    [http](http://example.invalid/missing.md)
                    [https](https://example.invalid/missing.md)
                    [mail](mailto:ops@example.invalid)
                    [tel](tel:+15550101)
                    [anchor](#foo)
                    """,
                ),
                run_case(
                    guard_module,
                    root,
                    "root-relative",
                    "docs/page.md",
                    "[root](/root.md)\n[missing](/missing-root.md)",
                ),
            ]

            clean = guard_module.scan({"docs/clean.md": "[real](real.md)\n"}, root)
            broken = guard_module.scan({"docs/broken.md": "[bad](bad.md)\n"}, root)
            invariant_ok = (
                guard_module.exit_code(clean) == 0
                and not clean.broken
                and guard_module.exit_code(broken) == 1
                and bool(broken.broken)
            )
            results.append(
                CaseResult(
                    name="exit-code-invariant",
                    expected=("0-if-empty/1-if-broken",),
                    actual=("0-if-empty/1-if-broken",) if invariant_ok else ("violated",),
                    passed=invariant_ok,
                )
            )
    except Exception as exc:
        print(f"SELFTEST FAIL: {exc}", file=sys.stderr)
        return 1

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for result in failures:
            print(
                f"{result.name}: expected {result.expected}, got {result.actual}",
                file=sys.stderr,
            )
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
