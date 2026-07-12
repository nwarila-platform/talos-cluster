#!/usr/bin/env python3
"""Regression self-test for the ARC runner CNP GitHub-egress parity guard."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-runner-cnp-github-parity.py"
POLICY_A = Path(
    "clusters/talos-cluster/tenants/arc-runners/"
    "ciliumnetworkpolicy-runner-egress.yaml"
)
POLICY_B = Path(
    "clusters/talos-cluster/tenants/arc-runners-repo-sync/"
    "ciliumnetworkpolicy-runner-egress.yaml"
)

SHARED = (
    ("matchName", "github.com"),
    ("matchName", "api.github.com"),
    ("matchPattern", "*.actions.githubusercontent.com"),
)
OFFENDING = ("matchName", "release-assets.githubusercontent.com")


@dataclass(frozen=True)
class GuardRun:
    rc: int
    stdout: str
    stderr: str

    @property
    def combined_output(self) -> str:
        return self.stdout + self.stderr


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected_rc: int
    actual_rc: int
    output_check: str
    passed: bool
    stdout: str
    stderr: str


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def yaml_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def selector_lines(entries: Sequence[tuple[str, str]]) -> str:
    return "\n".join(
        f"        - {kind}: {yaml_string(value)}" for kind, value in entries
    )


def policy_yaml(namespace: str, entries: Sequence[tuple[str, str]]) -> str:
    return "\n".join(
        (
            "apiVersion: cilium.io/v2",
            "kind: CiliumNetworkPolicy",
            "metadata:",
            "  name: allow-arc-runner-egress",
            f"  namespace: {namespace}",
            "spec:",
            "  endpointSelector:",
            "    matchLabels:",
            "      arc.nwarila.io/role: runner",
            "  egress:",
            "    - toFQDNs:",
            selector_lines(entries),
            "      toPorts:",
            "        - ports:",
            '            - port: "443"',
            "              protocol: TCP",
        )
    )


def policy_without_fqdns(namespace: str) -> str:
    return "\n".join(
        (
            "apiVersion: cilium.io/v2",
            "kind: CiliumNetworkPolicy",
            "metadata:",
            "  name: allow-arc-runner-egress",
            f"  namespace: {namespace}",
            "spec:",
            "  endpointSelector:",
            "    matchLabels:",
            "      arc.nwarila.io/role: runner",
            "  egress:",
            "    - toEndpoints:",
            "        - matchLabels:",
            "            k8s:k8s-app: kube-dns",
        )
    )


def run_guard(root: Path) -> GuardRun:
    result = subprocess.run(
        [sys.executable, str(GUARD.relative_to(ROOT)), str(root)],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return GuardRun(result.returncode, result.stdout, result.stderr)


def write_policy_pair(
    root: Path,
    left_entries: Sequence[tuple[str, str]],
    right_entries: Sequence[tuple[str, str]],
) -> None:
    write_file(root / POLICY_A, policy_yaml("arc-runners", left_entries))
    write_file(
        root / POLICY_B,
        policy_yaml("arc-runners-repo-sync", right_entries),
    )


def identical_fixture(root: Path) -> None:
    write_policy_pair(root, SHARED, SHARED)


def added_one_side_fixture(root: Path) -> None:
    write_policy_pair(root, (*SHARED, OFFENDING), SHARED)


def removed_one_side_fixture(root: Path) -> None:
    write_policy_pair(root, SHARED, (*SHARED, OFFENDING))


def empty_fqdns_fixture(root: Path) -> None:
    write_file(root / POLICY_A, policy_without_fqdns("arc-runners"))
    write_file(root / POLICY_B, policy_yaml("arc-runners-repo-sync", SHARED))


def missing_file_fixture(root: Path) -> None:
    write_file(root / POLICY_A, policy_yaml("arc-runners", SHARED))


def output_tail(text: str, line_count: int = 16) -> str:
    lines = text.splitlines()
    if len(lines) > line_count:
        lines = ["..."] + lines[-line_count:]
    return "\n".join(lines)


def run_case(
    name: str,
    expected_rc: int,
    fixture: Callable[[Path], None],
    required_output: Sequence[str],
) -> CaseResult:
    with tempfile.TemporaryDirectory(prefix="runner-cnp-parity-guard-") as tmpdir:
        root = Path(tmpdir)
        fixture(root)
        run = run_guard(root)

    missing_output = [
        required for required in required_output if required not in run.combined_output
    ]
    if not required_output:
        output_check = "not-required"
    elif missing_output:
        output_check = "missing:" + ",".join(missing_output)
    else:
        output_check = "present"

    return CaseResult(
        name=name,
        expected_rc=expected_rc,
        actual_rc=run.rc,
        output_check=output_check,
        passed=run.rc == expected_rc and not missing_output,
        stdout=run.stdout,
        stderr=run.stderr,
    )


def print_table(results: list[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected  actual  output-check  result")
    print(f"{'-' * name_width}  --------  ------  ------------  ------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.name:<{name_width}}  "
            f"{result.expected_rc:^8}  {result.actual_rc:^6}  "
            f"{result.output_check:<12}  {status}"
        )


def main() -> int:
    results = [
        run_case(
            "identical-sets-pass",
            0,
            identical_fixture,
            ("Shared GitHub FQDN set", "github.com"),
        ),
        run_case(
            "added-to-arc-runners-bites",
            1,
            added_one_side_fixture,
            (
                "missing from arc-runners-repo-sync",
                "release-assets.githubusercontent.com",
            ),
        ),
        run_case(
            "removed-from-arc-runners-bites",
            1,
            removed_one_side_fixture,
            (
                "missing from arc-runners",
                "release-assets.githubusercontent.com",
            ),
        ),
        run_case(
            "empty-tofqdns-fails-closed",
            1,
            empty_fqdns_fixture,
            ("zero toFQDNs entries found", "arc-runners"),
        ),
        run_case(
            "missing-file-fails-closed",
            1,
            missing_file_fixture,
            ("missing file", "arc-runners-repo-sync"),
        ),
    ]

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for result in failures:
            print(
                f"\n[{result.name}] expected rc {result.expected_rc}, "
                f"got rc {result.actual_rc}; output-check={result.output_check}",
                file=sys.stderr,
            )
            stderr_tail = output_tail(result.stderr)
            stdout_tail = output_tail(result.stdout)
            if stderr_tail:
                print("stderr tail:", file=sys.stderr)
                print(stderr_tail, file=sys.stderr)
            if stdout_tail:
                print("stdout tail:", file=sys.stderr)
                print(stdout_tail, file=sys.stderr)
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
