#!/usr/bin/env python3
"""Regression self-test for the kubelet-csr-approver values sync guard."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-kubelet-csr-approver-values-sync.py"


@dataclass(frozen=True)
class GuardRun:
    rc: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected_rc: int
    actual_rc: int
    passed: bool
    stdout: str
    stderr: str


def write_yaml(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def write_fixture(root: Path, addon_replicas: int) -> None:
    write_yaml(
        root / "values.yaml",
        f"""
        providerRegex: '^(cp[1-3]|w[1-3])$'
        providerIpPrefixes:
          - 10.69.112.0/24
        bypassDnsResolution: true
        bypassHostnameCheck: false
        ignoreNonSystemNode: true
        replicas: {addon_replicas}
        metrics:
          enable: false
        """,
    )
    write_yaml(
        root / "helmrelease.yaml",
        """
        apiVersion: helm.toolkit.fluxcd.io/v2
        kind: HelmRelease
        spec:
          values:
            providerRegex: '^(cp[1-3]|w[1-3])$'
            providerIpPrefixes:
              - 10.69.112.0/24
            bypassDnsResolution: true
            bypassHostnameCheck: false
            ignoreNonSystemNode: true
            replicas: 2
            metrics:
              enable: false
        """,
    )


def run_guard(root: Path) -> GuardRun:
    result = subprocess.run(
        [
            sys.executable,
            str(GUARD.relative_to(ROOT)),
            "--addon-values",
            str(root / "values.yaml"),
            "--helmrelease",
            str(root / "helmrelease.yaml"),
        ],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return GuardRun(result.returncode, result.stdout, result.stderr)


def clean_fixture(root: Path) -> None:
    write_fixture(root, addon_replicas=2)


def drift_fixture(root: Path) -> None:
    write_fixture(root, addon_replicas=3)


def run_case(name: str, expected_rc: int, fixture: Callable[[Path], None]) -> CaseResult:
    with tempfile.TemporaryDirectory(prefix="kubelet-csr-values-guard-") as tmpdir:
        root = Path(tmpdir)
        fixture(root)
        run = run_guard(root)
    return CaseResult(
        name=name,
        expected_rc=expected_rc,
        actual_rc=run.rc,
        passed=run.rc == expected_rc,
        stdout=run.stdout,
        stderr=run.stderr,
    )


def output_tail(text: str, line_count: int = 16) -> str:
    lines = text.splitlines()
    if len(lines) > line_count:
        lines = ["..."] + lines[-line_count:]
    return "\n".join(lines)


def print_table(results: list[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected  actual  result")
    print(f"{'-' * name_width}  --------  ------  ------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.name:<{name_width}}  "
            f"{result.expected_rc:^8}  {result.actual_rc:^6}  {status}"
        )


def main() -> int:
    results = [
        run_case("clean", 0, clean_fixture),
        run_case("values-drift", 1, drift_fixture),
    ]

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for result in failures:
            print(
                f"\n[{result.name}] expected rc {result.expected_rc}, "
                f"got rc {result.actual_rc}",
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
