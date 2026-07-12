#!/usr/bin/env python3
"""Regression self-test for workflow-health stale-exception evaluation."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-workflow-health.py"


@dataclass(frozen=True)
class CaseResult:
    name: str
    passed: bool
    detail: str = ""


def load_guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_workflow_health_guard",
        GUARD,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {GUARD}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = load_guard()


def fail_run_gh(args: list[str]) -> str:
    raise AssertionError(f"self-test must not call gh: {args}")


guard.run_gh = fail_run_gh
DETAIL = guard.ExceptionDetail(
    tracking="TEST",
    reason="unit-test exception",
)


def workflow(key: str, *, persistent_red: bool):
    conclusions = ("failure",) * guard.THRESHOLD_RUNS if persistent_red else ("success",)
    return guard.WorkflowHealth(
        key=key,
        name=key,
        path=f".github/workflows/{key}",
        state="active",
        lifetime_runs=guard.THRESHOLD_RUNS,
        lifetime_successes=0 if persistent_red else 1,
        completed_runs=guard.THRESHOLD_RUNS,
        last_completed_conclusions=conclusions,
        persistent_red=persistent_red,
        persistent_red_reasons=(
            f"last {guard.THRESHOLD_RUNS} completed runs are red",
        ) if persistent_red else (),
        exception=None,
    )


def check(name: str, condition: bool, detail: str) -> CaseResult:
    return CaseResult(
        name=name,
        passed=condition,
        detail="" if condition else detail,
    )


def stale_reasons(evaluation) -> dict[str, str]:
    return {
        item.key: item.reason
        for item in evaluation.stale_exceptions
    }


def print_table(results: list[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  result  detail")
    print(f"{'-' * name_width}  ------  ------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        detail = result.detail or "-"
        print(f"{result.name:<{name_width}}  {status:<6}  {detail}")


def main() -> int:
    exceptions = {
        "excepted-red.yaml": DETAIL,
        "healthy-excepted.yaml": DETAIL,
        "missing-excepted.yaml": DETAIL,
    }
    evaluation = guard.evaluate_workflows(
        [
            workflow("excepted-red.yaml", persistent_red=True),
            workflow("healthy-excepted.yaml", persistent_red=False),
            workflow("unexcepted-red.yaml", persistent_red=True),
        ],
        exceptions=exceptions,
    )
    stale = stale_reasons(evaluation)
    non_excepted_red = {
        item.key
        for item in evaluation.non_excepted_red
    }

    clean_evaluation = guard.evaluate_workflows(
        [
            workflow("excepted-red.yaml", persistent_red=True),
            workflow("healthy-unexcepted.yaml", persistent_red=False),
        ],
        exceptions={"excepted-red.yaml": DETAIL},
    )
    stale_only_evaluation = guard.evaluate_workflows(
        [workflow("excepted-red.yaml", persistent_red=False)],
        exceptions={"excepted-red.yaml": DETAIL},
    )
    red_only_evaluation = guard.evaluate_workflows(
        [workflow("unexcepted-red.yaml", persistent_red=True)],
        exceptions={},
    )

    results = [
        check(
            "excepted red remains active",
            "excepted-red.yaml" not in stale
            and "excepted-red.yaml" not in non_excepted_red,
            "excepted red workflow was stale or non-excepted",
        ),
        check(
            "healthy exception becomes stale",
            stale.get("healthy-excepted.yaml") == "workflow is now healthy",
            f"got {stale.get('healthy-excepted.yaml')!r}",
        ),
        check(
            "missing exception becomes stale",
            stale.get("missing-excepted.yaml") == "workflow no longer exists",
            f"got {stale.get('missing-excepted.yaml')!r}",
        ),
        check(
            "non-excepted red is reported",
            non_excepted_red == {"unexcepted-red.yaml"},
            f"got {sorted(non_excepted_red)!r}",
        ),
        check(
            "exit code clean",
            clean_evaluation.exit_code == 0,
            f"got {clean_evaluation.exit_code}",
        ),
        check(
            "exit code stale-only",
            stale_only_evaluation.exit_code == 1,
            f"got {stale_only_evaluation.exit_code}",
        ),
        check(
            "exit code red-only",
            red_only_evaluation.exit_code == 1,
            f"got {red_only_evaluation.exit_code}",
        ),
        check(
            "exit code stale-and-red",
            evaluation.exit_code == 1,
            f"got {evaluation.exit_code}",
        ),
    ]

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
