#!/usr/bin/env python3
"""Regression self-test for the Renovate annotation coverage guard."""

from __future__ import annotations

import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-renovate-coverage.py"


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected_orphans: int
    actual_orphans: int
    passed: bool


def load_guard():
    spec = importlib.util.spec_from_file_location("check_renovate_coverage", GUARD)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {GUARD}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_case(
    name: str, files: dict[str, str], patterns: list[str], expected_orphans: int
) -> CaseResult:
    guard = load_guard()
    compiled = [re.compile(pattern) for pattern in patterns]
    _checked, orphaned = guard.find_orphaned_annotations(files, compiled)
    actual_orphans = len(orphaned)
    return CaseResult(
        name=name,
        expected_orphans=expected_orphans,
        actual_orphans=actual_orphans,
        passed=actual_orphans == expected_orphans,
    )


def print_table(results: list[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected  actual  result")
    print(f"{'-' * name_width}  --------  ------  ------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.name:<{name_width}}  "
            f"{result.expected_orphans:^8}  {result.actual_orphans:^6}  {status}"
        )


def main() -> int:
    results = [
        run_case(
            "uncovered-annotation",
            {"foo.yaml": "# renovate: datasource=docker depName=example/app\nimage: app\n"},
            [],
            1,
        ),
        run_case(
            "covered-by-manager",
            {"foo.yaml": "# renovate: datasource=docker depName=example/app\nimage: app\n"},
            [r"^foo\.ya?ml$"],
            0,
        ),
        run_case(
            "workflow-uses-adjacent",
            {
                ".github/workflows/build.yaml": (
                    "steps:\n"
                    "  - name: Example\n"
                    "    # renovate: datasource=git-refs depName=example/action\n"
                    "    uses: example/action@0123456789abcdef0123456789abcdef01234567\n"
                )
            },
            [],
            0,
        ),
        run_case(
            "markdown-ignored",
            {"docs/example.md": "# renovate: datasource=docker depName=example/app\n"},
            [],
            0,
        ),
        run_case(
            "guard-source-ignored",
            {"scripts/check-renovate-coverage.py": 'RENOVATE_MARKER = "# renovate:"\n'},
            [],
            0,
        ),
    ]

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for result in failures:
            print(
                f"{result.name}: expected {result.expected_orphans} orphan(s), "
                f"got {result.actual_orphans}",
                file=sys.stderr,
            )
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
