#!/usr/bin/env python3
"""Regression self-test for the node patch consistency guard."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-node-patch-consistency.py"


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


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def write_config(root: Path) -> None:
    write_text(
        root / "config.env",
        """
        CLUSTER_GATEWAY="10.0.0.1"
        CLUSTER_NETMASK="24"
        CLUSTER_VIP="10.0.0.10"
        """,
    )


def write_systems(root: Path) -> None:
    write_text(
        root / "systems",
        """
        VIP 10.0.0.10

        HOSTNAME  ASSET_NAME     ROLE           IP          INSTALL_DISK   NIC   BOOTSTRAP
        cp1       TEST-CP1       control-plane  10.0.0.11  /dev/nvme0n1   eno1  yes
        w1        TEST-W1        worker         10.0.0.21  /dev/nvme0n1   eno1  no
        """,
    )


def write_cp_patch(
    root: Path,
    *,
    disk: str = "/dev/nvme0n1",
    address: str = "10.0.0.11/24",
    gateway: str = "10.0.0.1",
    vip: str | None = "10.0.0.10",
) -> None:
    vip_entry = ""
    if vip is not None:
        vip_entry = f"""
              - deviceSelector:
                  busPath: "0000:00:1f.6"
                dhcp: false
                vip:
                  ip: {vip}
        """

    write_text(
        root / "patches/cp1.yaml",
        f"""
        machine:
          install:
            disk: {disk}
          network:
            interfaces:
        {vip_entry}
              - deviceSelector:
                  busPath: "0000:00:1f.6"
                addresses:
                  - {address}
                routes:
                  - network: 0.0.0.0/0
                    gateway: {gateway}
        """,
    )


def write_worker_patch(
    root: Path,
    *,
    address: str = "10.0.0.21/24",
    gateway: str = "10.0.0.1",
    vip: str | None = None,
) -> None:
    vip_block = ""
    if vip is not None:
        vip_block = f"""
                vip:
                  ip: {vip}
        """

    write_text(
        root / "patches/w1.yaml",
        f"""
        machine:
          install:
            disk: /dev/nvme0n1
          network:
            interfaces:
              - deviceSelector:
                  busPath: "0000:00:1f.6"
                addresses:
                  - {address}
                routes:
                  - network: 0.0.0.0/0
                    gateway: {gateway}
        {vip_block}
        """,
    )


def clean_fixture(root: Path) -> None:
    write_config(root)
    write_systems(root)
    write_cp_patch(root)
    write_worker_patch(root)


def wrong_disk_fixture(root: Path) -> None:
    clean_fixture(root)
    write_cp_patch(root, disk="/dev/sda")


def wrong_address_prefix_fixture(root: Path) -> None:
    clean_fixture(root)
    write_worker_patch(root, address="10.0.0.21/25")


def wrong_gateway_fixture(root: Path) -> None:
    clean_fixture(root)
    write_cp_patch(root, gateway="10.0.0.254")


def worker_with_vip_fixture(root: Path) -> None:
    clean_fixture(root)
    write_worker_patch(root, vip="10.0.0.10")


def cp_missing_vip_fixture(root: Path) -> None:
    clean_fixture(root)
    write_cp_patch(root, vip=None)


def run_guard(root: Path) -> GuardRun:
    result = subprocess.run(
        [
            sys.executable,
            str(GUARD.relative_to(ROOT)),
            "--config-env",
            str(root / "config.env"),
            "--inventory",
            str(root / "systems"),
            "--patch-dir",
            str(root / "patches"),
        ],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return GuardRun(result.returncode, result.stdout, result.stderr)


def run_case(name: str, expected_rc: int, fixture: Callable[[Path], None]) -> CaseResult:
    with tempfile.TemporaryDirectory(prefix="node-patch-guard-") as tmpdir:
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
        run_case("wrong-disk", 1, wrong_disk_fixture),
        run_case("wrong-address-prefix", 1, wrong_address_prefix_fixture),
        run_case("wrong-gateway", 1, wrong_gateway_fixture),
        run_case("worker-with-vip", 1, worker_with_vip_fixture),
        run_case("cp-missing-vip", 1, cp_missing_vip_fixture),
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
