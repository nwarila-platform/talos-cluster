#!/usr/bin/env python3
"""Fail when GitHub Actions workflows have silently become persistently red."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import PurePosixPath
import subprocess
import sys
from typing import Iterable


THRESHOLD_RUNS = 5
RED_CONCLUSIONS = frozenset(
    {
        "cancelled",
        "failure",
        "startup_failure",
        "timed_out",
    }
)


@dataclass(frozen=True)
class ExceptionDetail:
    tracking: str
    reason: str


# Known persistent-red workflows adjudicated in P1.6 Phase 2. Each exception is
# deliberately self-cleaning: if the workflow disappears or becomes healthy, the
# check fails until the stale exception is removed.
EXCEPTIONS = {
    # The workflow file is deleted (retired by ADR-0026; the in-cluster
    # dr-etcd-backup CronJob replaced it), but GitHub keeps listing the
    # workflow object while its run history exists. Remove this entry when the
    # stale-exception check reports "workflow no longer exists".
    "etcd-snapshot.yaml": ExceptionDetail(
        tracking="ADR-0026",
        reason="retired and deleted; red run history predates retirement",
    ),
}


@dataclass(frozen=True)
class Workflow:
    workflow_id: int
    name: str
    path: str
    state: str

    @property
    def key(self) -> str:
        if self.path.startswith(".github/workflows/"):
            return PurePosixPath(self.path).name
        return self.path


@dataclass(frozen=True)
class WorkflowHealth:
    key: str
    name: str
    path: str
    state: str
    lifetime_runs: int
    lifetime_successes: int
    completed_runs: int
    last_completed_conclusions: tuple[str, ...]
    persistent_red: bool
    persistent_red_reasons: tuple[str, ...]
    exception: ExceptionDetail | None = None


@dataclass(frozen=True)
class StaleException:
    key: str
    detail: ExceptionDetail
    reason: str


@dataclass(frozen=True)
class Evaluation:
    non_excepted_red: tuple[WorkflowHealth, ...]
    stale_exceptions: tuple[StaleException, ...]

    @property
    def exit_code(self) -> int:
        if self.non_excepted_red or self.stale_exceptions:
            return 1
        return 0


def run_gh(args: list[str]) -> str:
    try:
        completed = subprocess.run(
            ["gh", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise SystemExit("gh CLI is required but was not found in PATH") from None
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        stdout = exc.stdout.strip()
        detail = stderr or stdout or "no output"
        raise SystemExit(f"gh {' '.join(args)} failed: {detail}") from None
    return completed.stdout


def gh_api(endpoint: str, *, paginate: bool = False) -> object:
    args = ["api"]
    if paginate:
        args.extend(["--paginate", "--slurp"])
    args.append(endpoint)
    return json.loads(run_gh(args))


def int_field(data: object, field: str) -> int:
    if not isinstance(data, dict):
        return 0
    value = data.get(field, 0)
    if isinstance(value, int):
        return value
    return int(value)


def fetch_workflows() -> list[Workflow]:
    data = gh_api("repos/{owner}/{repo}/actions/workflows?per_page=100", paginate=True)
    pages = data if isinstance(data, list) else [data]

    workflows: list[Workflow] = []
    for page in pages:
        if not isinstance(page, dict):
            continue
        for workflow in page.get("workflows", []):
            workflows.append(
                Workflow(
                    workflow_id=int(workflow["id"]),
                    name=str(workflow["name"]),
                    path=str(workflow["path"]),
                    state=str(workflow["state"]),
                )
            )

    workflows.sort(key=lambda item: item.key)
    return workflows


def fetch_workflow_health(workflow: Workflow) -> WorkflowHealth:
    runs_endpoint = f"repos/{{owner}}/{{repo}}/actions/workflows/{workflow.workflow_id}/runs"
    lifetime_data = gh_api(f"{runs_endpoint}?per_page=1")
    completed_data = gh_api(f"{runs_endpoint}?status=completed&per_page={THRESHOLD_RUNS}")
    success_data = gh_api(f"{runs_endpoint}?status=success&per_page=1")

    lifetime_runs = int_field(lifetime_data, "total_count")
    completed_runs = int_field(completed_data, "total_count")
    lifetime_successes = int_field(success_data, "total_count")

    recent_runs = []
    if isinstance(completed_data, dict):
        recent_runs = completed_data.get("workflow_runs", [])
    last_completed = tuple(
        str(run.get("conclusion") or "unknown")
        for run in recent_runs
        if isinstance(run, dict)
    )

    reasons = persistent_red_reasons(
        lifetime_runs=lifetime_runs,
        lifetime_successes=lifetime_successes,
        last_completed_conclusions=last_completed,
    )

    return WorkflowHealth(
        key=workflow.key,
        name=workflow.name,
        path=workflow.path,
        state=workflow.state,
        lifetime_runs=lifetime_runs,
        lifetime_successes=lifetime_successes,
        completed_runs=completed_runs,
        last_completed_conclusions=last_completed,
        persistent_red=bool(reasons),
        persistent_red_reasons=reasons,
        exception=EXCEPTIONS.get(workflow.key),
    )


def persistent_red_reasons(
    *,
    lifetime_runs: int,
    lifetime_successes: int,
    last_completed_conclusions: tuple[str, ...],
) -> tuple[str, ...]:
    reasons: list[str] = []
    recent = last_completed_conclusions[:THRESHOLD_RUNS]

    if len(recent) == THRESHOLD_RUNS and all(item in RED_CONCLUSIONS for item in recent):
        reasons.append(
            f"last {THRESHOLD_RUNS} completed runs are red"
        )

    if lifetime_runs >= THRESHOLD_RUNS and lifetime_successes == 0:
        reasons.append(
            f"{lifetime_runs} lifetime runs and 0 successes"
        )

    return tuple(reasons)


def evaluate_workflows(
    health: Iterable[WorkflowHealth],
    exceptions: dict[str, ExceptionDetail] = EXCEPTIONS,
) -> Evaluation:
    health_by_key = {item.key: item for item in health}

    non_excepted_red = tuple(
        item
        for item in health_by_key.values()
        if item.persistent_red and item.key not in exceptions
    )

    stale: list[StaleException] = []
    for key, detail in sorted(exceptions.items()):
        item = health_by_key.get(key)
        if item is None:
            stale.append(
                StaleException(
                    key=key,
                    detail=detail,
                    reason="workflow no longer exists",
                )
            )
        elif not item.persistent_red:
            stale.append(
                StaleException(
                    key=key,
                    detail=detail,
                    reason="workflow is now healthy",
                )
            )

    return Evaluation(
        non_excepted_red=non_excepted_red,
        stale_exceptions=tuple(stale),
    )


def format_table(rows: list[WorkflowHealth]) -> str:
    headers = [
        "Result",
        "Workflow",
        "Name",
        "Runs",
        "Succ",
        "Completed",
        "Last completed",
        "Note",
    ]
    table_rows = [headers]

    for item in rows:
        if item.persistent_red and item.exception:
            result = "EXCEPTED"
            note = f"{item.exception.tracking}: {item.exception.reason}"
        elif item.persistent_red:
            result = "FAIL"
            note = "; ".join(item.persistent_red_reasons)
        else:
            result = "OK"
            note = "healthy"

        last_completed = ",".join(item.last_completed_conclusions) or "-"
        table_rows.append(
            [
                result,
                item.key,
                item.name,
                str(item.lifetime_runs),
                str(item.lifetime_successes),
                str(item.completed_runs),
                last_completed,
                note,
            ]
        )

    widths = [
        max(len(row[index]) for row in table_rows)
        for index in range(len(headers))
    ]

    formatted = []
    for row_index, row in enumerate(table_rows):
        formatted.append(
            "  ".join(
                cell.ljust(widths[index])
                for index, cell in enumerate(row)
            ).rstrip()
        )
        if row_index == 0:
            formatted.append(
                "  ".join("-" * width for width in widths).rstrip()
            )
    return "\n".join(formatted)


def print_report(rows: list[WorkflowHealth], evaluation: Evaluation) -> None:
    print(
        "Workflow health threshold: "
        f"last {THRESHOLD_RUNS} completed runs all in "
        f"{', '.join(sorted(RED_CONCLUSIONS))}, OR "
        f">={THRESHOLD_RUNS} lifetime runs and 0 successes."
    )
    print()
    print(format_table(rows))

    if evaluation.stale_exceptions:
        print()
        print("Stale exceptions:")
        for item in evaluation.stale_exceptions:
            print(
                f"- {item.key}: {item.reason}; remove exception "
                f"({item.detail.tracking}: {item.detail.reason})"
            )

    if evaluation.non_excepted_red:
        print()
        print("Non-excepted persistent-red workflows:")
        for item in evaluation.non_excepted_red:
            print(f"- {item.key}: {'; '.join(item.persistent_red_reasons)}")


def main() -> int:
    if not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"):
        print(
            "warning: GH_TOKEN/GITHUB_TOKEN is not set; relying on gh CLI auth",
            file=sys.stderr,
        )

    workflows = fetch_workflows()
    health = [fetch_workflow_health(workflow) for workflow in workflows]
    evaluation = evaluate_workflows(health)
    print_report(health, evaluation)
    return evaluation.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
