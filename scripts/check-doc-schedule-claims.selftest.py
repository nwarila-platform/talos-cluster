#!/usr/bin/env python3
"""Regression self-test for the curated doc schedule claim guard."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-doc-schedule-claims.py"


@dataclass(frozen=True)
class Case:
    name: str
    claims: tuple[Any, ...]
    files: dict[str, str]
    expected_rc: int
    expected_claim: str | None


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected: str
    actual: str
    passed: bool


def load_guard_module() -> Any:
    spec = importlib.util.spec_from_file_location("check_doc_schedule_claims", GUARD)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {GUARD}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_file(root: Path, relpath: str, content: str) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def base_files() -> dict[str, str]:
    return {
        "docs/claims.md": """
        daily CronJob claim
        time claim is 03:00 UTC
        retain 14 claim
        no schedule workflow claim
        """,
        "manifests/daily-cronjob.yaml": """
        apiVersion: batch/v1
        kind: CronJob
        spec:
          schedule: "0 3 * * *"
        """,
        "manifests/retaining-recurringjob.yaml": """
        apiVersion: longhorn.io/v1beta2
        kind: RecurringJob
        spec:
          cron: "47 3 * * *"
          retain: 14
        """,
        ".github/workflows/no-schedule.yaml": """
        name: No Schedule
        on:
          workflow_dispatch:
        """,
    }


def base_claims(guard: Any) -> tuple[Any, ...]:
    return (
        guard.Claim(
            name="daily-cronjob",
            doc_path="docs/claims.md",
            anchor_regex=r"daily CronJob claim",
            source_path="manifests/daily-cronjob.yaml",
            source_kind="cronjob_schedule",
            expected="daily",
        ),
        guard.Claim(
            name="exact-time",
            doc_path="docs/claims.md",
            anchor_regex=r"time claim is 03:00 UTC",
            source_path="manifests/daily-cronjob.yaml",
            source_kind="cronjob_schedule",
            expected="time=03:00",
        ),
        guard.Claim(
            name="retain-count",
            doc_path="docs/claims.md",
            anchor_regex=r"retain 14 claim",
            source_path="manifests/retaining-recurringjob.yaml",
            source_kind="recurringjob_retain",
            expected="retain=14",
        ),
        guard.Claim(
            name="workflow-no-schedule",
            doc_path="docs/claims.md",
            anchor_regex=r"no schedule workflow claim",
            source_path=".github/workflows/no-schedule.yaml",
            source_kind="workflow_no_schedule",
            expected="absent",
        ),
    )


def merged_files(overrides: dict[str, str]) -> dict[str, str]:
    files = base_files()
    files.update(overrides)
    return files


def run_case(guard: Any, case: Case) -> CaseResult:
    with tempfile.TemporaryDirectory(prefix="doc-schedule-guard-") as tmpdir:
        root = Path(tmpdir)
        for relpath, content in case.files.items():
            write_file(root, relpath, content)

        result = guard.check_claims(root, case.claims)
        output = "\n".join(guard.format_result(result))
        actual_rc = guard.exit_code(result)
        claim_ok = case.expected_claim is None or case.expected_claim in output
        passed = actual_rc == case.expected_rc and claim_ok
        expected = f"rc={case.expected_rc}"
        if case.expected_claim is not None:
            expected += f", output contains {case.expected_claim}"
        actual = f"rc={actual_rc}, output={output!r}"
        return CaseResult(case.name, expected, actual, passed)


def cases(guard: Any) -> Sequence[Case]:
    claims = base_claims(guard)
    clean = Case(
        name="clean-pass",
        claims=claims,
        files=base_files(),
        expected_rc=0,
        expected_claim=None,
    )

    frequency = Case(
        name="frequency-contradiction",
        claims=claims,
        files=merged_files(
            {
                "manifests/daily-cronjob.yaml": """
                apiVersion: batch/v1
                kind: CronJob
                spec:
                  schedule: "17 * * * *"
                """,
            }
        ),
        expected_rc=1,
        expected_claim="daily-cronjob",
    )

    exact_time = Case(
        name="exact-time-contradiction",
        claims=claims,
        files=merged_files(
            {
                "manifests/daily-cronjob.yaml": """
                apiVersion: batch/v1
                kind: CronJob
                spec:
                  schedule: "0 4 * * *"
                """,
            }
        ),
        expected_rc=1,
        expected_claim="exact-time",
    )

    retain = Case(
        name="retain-contradiction",
        claims=claims,
        files=merged_files(
            {
                "manifests/retaining-recurringjob.yaml": """
                apiVersion: longhorn.io/v1beta2
                kind: RecurringJob
                spec:
                  cron: "47 3 * * *"
                  retain: 7
                """,
            }
        ),
        expected_rc=1,
        expected_claim="retain-count",
    )

    zero_anchor = Case(
        name="anchor-zero-match",
        claims=claims,
        files=merged_files(
            {
                "docs/claims.md": """
                time claim is 03:00 UTC
                retain 14 claim
                no schedule workflow claim
                """,
            }
        ),
        expected_rc=1,
        expected_claim="daily-cronjob",
    )

    duplicate_anchor = Case(
        name="anchor-duplicate-match",
        claims=claims,
        files=merged_files(
            {
                "docs/claims.md": """
                daily CronJob claim
                daily CronJob claim
                time claim is 03:00 UTC
                retain 14 claim
                no schedule workflow claim
                """,
            }
        ),
        expected_rc=1,
        expected_claim="daily-cronjob",
    )

    workflow_no_schedule = Case(
        name="workflow-no-schedule-bites",
        claims=claims,
        files=merged_files(
            {
                ".github/workflows/no-schedule.yaml": """
                name: No Schedule
                on:
                  schedule:
                    - cron: "0 6 * * 1"
                  workflow_dispatch:
                """,
            }
        ),
        expected_rc=1,
        expected_claim="workflow-no-schedule",
    )

    return (
        clean,
        frequency,
        exact_time,
        retain,
        zero_anchor,
        duplicate_anchor,
        workflow_no_schedule,
    )


def print_table(results: Sequence[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected  result")
    print(f"{'-' * name_width}  --------  ------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"{result.name:<{name_width}}  {result.expected:<32}  {status}")
        if not result.passed:
            print(f"  actual: {result.actual}")


def main() -> int:
    try:
        guard = load_guard_module()
        results = [run_case(guard, case) for case in cases(guard)]
    except Exception as exc:
        print(f"SELFTEST FAIL: {exc}", file=sys.stderr)
        return 1

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for failure in failures:
            print(f"{failure.name}: expected {failure.expected}; {failure.actual}", file=sys.stderr)
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
