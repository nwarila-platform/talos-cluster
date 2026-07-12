#!/usr/bin/env python3
"""Regression self-test for the SOPS-encrypted secret guard."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-sops-encrypted.py"


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected_status: str
    actual_status: str
    passed: bool
    reason: str


def load_guard_module():
    spec = importlib.util.spec_from_file_location("check_sops_encrypted", GUARD)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {GUARD}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_yaml(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def clean_fixture(root: Path) -> Path:
    path = root / "clean.sops.yaml"
    write_yaml(
        path,
        """
        apiVersion: v1
        kind: Secret
        metadata:
          name: clean
        data:
          password: ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]
        sops:
          age:
            - recipient: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqlrg4d
              enc: ENC[AES256_GCM,data:recipient,iv:def,tag:ghi,type:str]
          mac: ENC[AES256_GCM,data:mac,iv:def,tag:ghi,type:str]
          encrypted_regex: ^(data|stringData)$
          version: 3.10.2
        """,
    )
    return path


def plaintext_fixture(root: Path) -> Path:
    path = root / "plaintext.sops.yaml"
    write_yaml(
        path,
        """
        apiVersion: v1
        kind: Secret
        data:
          password: hunter2
        """,
    )
    return path


def no_mac_fixture(root: Path) -> Path:
    path = root / "no-mac.sops.yaml"
    write_yaml(
        path,
        """
        apiVersion: v1
        kind: Secret
        data:
          password: ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]
        sops:
          age:
            - recipient: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqlrg4d
              enc: ENC[AES256_GCM,data:recipient,iv:def,tag:ghi,type:str]
        """,
    )
    return path


def no_enc_fixture(root: Path) -> Path:
    path = root / "no-enc.sops.yaml"
    write_yaml(
        path,
        """
        apiVersion: v1
        kind: Secret
        data:
          password: plaintext
        sops:
          age:
            - recipient: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqlrg4d
              enc: ENC[AES256_GCM,data:recipient,iv:def,tag:ghi,type:str]
          mac: ENC[AES256_GCM,data:mac,iv:def,tag:ghi,type:str]
        """,
    )
    return path


def creation_rules_fixture(root: Path) -> Path:
    path = root / "rules.sops.yaml"
    write_yaml(
        path,
        """
        creation_rules:
          - path_regex: .*\\.sops\\.yaml$
            age: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqlrg4d
        """,
    )
    return path


def dotfile_config_fixture(root: Path) -> Path:
    path = root / ".sops.yaml"
    write_yaml(
        path,
        """
        creation_rules:
          - encrypted_regex: ^(data|stringData)$
            age: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqlrg4d
        """,
    )
    return path


def run_case(
    guard_module: object,
    name: str,
    expected_status: str,
    fixture: Callable[[Path], Path],
) -> CaseResult:
    with tempfile.TemporaryDirectory(prefix="sops-encrypted-guard-") as tmpdir:
        path = fixture(Path(tmpdir))
        result = guard_module.check_sops_file(path)
    return CaseResult(
        name=name,
        expected_status=expected_status,
        actual_status=result.status,
        passed=result.status == expected_status,
        reason=result.reason,
    )


def print_table(results: list[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected   actual     result")
    print(f"{'-' * name_width}  ---------  ---------  ------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.name:<{name_width}}  "
            f"{result.expected_status:<9}  {result.actual_status:<9}  {status}"
        )


def main() -> int:
    try:
        guard_module = load_guard_module()
        results = [
            run_case(guard_module, "clean", "secret", clean_fixture),
            run_case(guard_module, "plaintext", "violation", plaintext_fixture),
            run_case(guard_module, "forged-no-mac", "violation", no_mac_fixture),
            run_case(guard_module, "forged-no-enc", "violation", no_enc_fixture),
            run_case(guard_module, "creation-rules-config", "skip", creation_rules_fixture),
            run_case(guard_module, "dotfile-config", "skip", dotfile_config_fixture),
        ]
    except Exception as exc:
        print(f"SELFTEST FAIL: {exc}", file=sys.stderr)
        return 1

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for result in failures:
            print(
                f"{result.name}: expected {result.expected_status}, "
                f"got {result.actual_status} ({result.reason})",
                file=sys.stderr,
            )
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
