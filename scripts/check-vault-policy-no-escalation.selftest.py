#!/usr/bin/env python3
"""Regression self-test for the managed Vault policy escalation guard."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-vault-policy-no-escalation.py"


@dataclass(frozen=True)
class GuardRun:
    rc: int
    stdout: str
    stderr: str

    @property
    def combined_output(self) -> str:
        return self.stdout + "\n" + self.stderr


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected_rc: int
    actual_rc: int
    evidence: str
    passed: bool
    output: str


def load_guard_module():
    spec = importlib.util.spec_from_file_location(
        "check_vault_policy_no_escalation", GUARD
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {GUARD}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = load_guard_module()


def write_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
    return path


def run_guard(policy_roots: tuple[Path, ...], cr_roots: tuple[Path, ...]) -> GuardRun:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = guard.run(policy_roots, cr_roots)
    return GuardRun(rc=rc, stdout=stdout.getvalue(), stderr=stderr.getvalue())


def real_policy_fixture(_root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    return (ROOT / guard.DEFAULT_POLICY_DIR,), ()


def e1_sudo_fixture(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    write_text(
        root / "policies/e1-sudo.hcl",
        """
        path "secret/data/team/*" {
          capabilities = ["read", "sudo"]
        }
        """,
    )
    return (root / "policies",), ()


def e2_global_wildcard_fixture(
    root: Path,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    write_text(
        root / "policies/e2-wildcard.hcl",
        """
        path "*" {
          capabilities = ["read"]
        }
        """,
    )
    return (root / "policies",), ()


def e3_policy_write_fixture(
    root: Path,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    write_text(
        root / "policies/e3-policy-write.hcl",
        """
        path "sys/policies/acl/evil" {
          capabilities = ["update"]
        }
        """,
    )
    return (root / "policies",), ()


def e3_auth_role_write_fixture(
    root: Path,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    write_text(
        root / "policies/e3-auth-role-write.hcl",
        """
        path "auth/kubernetes/role/evil" {
          capabilities = ["create", "update"]
        }
        """,
    )
    return (root / "policies",), ()


def e3_self_ops_fixture(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    write_text(
        root / "policies/e3-self-ops.hcl",
        """
        path "auth/token/renew-self" {
          capabilities = ["update"]
        }

        path "auth/token/lookup-self" {
          capabilities = ["read"]
        }
        """,
    )
    return (root / "policies",), ()


def e4_sys_write_fixture(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    write_text(
        root / "policies/e4-sys-write.hcl",
        """
        path "sys/*" {
          capabilities = ["update"]
        }
        """,
    )
    return (root / "policies",), ()


def policy_cr_sudo_fixture(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    write_text(
        root / "vault/policy-cr.yaml",
        """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: Policy
        metadata:
          name: evil-policy
        spec:
          policy: |
            path "secret/data/team/*" {
              capabilities = ["sudo"]
            }
        """,
    )
    return (), (root / "vault",)


def malformed_hcl_fixture(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    write_text(
        root / "policies/malformed.hcl",
        """
        path "secret/data/team/*" {
          capabilities = ["read"]
        """,
    )
    return (root / "policies",), ()


def run_case(
    name: str,
    expected_rc: int,
    evidence: str,
    fixture: Callable[[Path], tuple[tuple[Path, ...], tuple[Path, ...]]],
    fragments: tuple[str, ...],
) -> CaseResult:
    with tempfile.TemporaryDirectory(prefix="vault-policy-guard-") as tmpdir:
        policy_roots, cr_roots = fixture(Path(tmpdir))
        result = run_guard(policy_roots, cr_roots)

    output = result.combined_output
    fragments_present = all(fragment in output for fragment in fragments)
    passed = result.rc == expected_rc and fragments_present
    if not fragments_present:
        missing = ", ".join(repr(fragment) for fragment in fragments if fragment not in output)
        evidence = f"{evidence}; missing output fragment(s): {missing}"
    return CaseResult(
        name=name,
        expected_rc=expected_rc,
        actual_rc=result.rc,
        evidence=evidence,
        passed=passed,
        output=output,
    )


def print_table(results: list[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected  actual  result  evidence")
    print(f"{'-' * name_width}  --------  ------  ------  --------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.name:<{name_width}}  "
            f"{result.expected_rc:<8}  {result.actual_rc:<6}  "
            f"{status:<6}  {result.evidence}"
        )


def output_tail(output: str, lines: int = 12) -> str:
    return "\n".join(output.strip().splitlines()[-lines:])


def e1_neutered_falsifiability_case() -> CaseResult:
    original_check_stanza = guard.check_stanza

    def check_without_e1(stanza: object) -> list[str]:
        return [
            finding
            for finding in original_check_stanza(stanza)
            if "E1 sudo capability" not in finding
        ]

    guard.check_stanza = check_without_e1
    try:
        with tempfile.TemporaryDirectory(prefix="vault-policy-guard-") as tmpdir:
            policy_roots, cr_roots = e1_sudo_fixture(Path(tmpdir))
            result = run_guard(policy_roots, cr_roots)
    finally:
        guard.check_stanza = original_check_stanza

    output = result.combined_output
    passed = result.rc == 0 and "E1 sudo capability" not in output
    return CaseResult(
        name="falsifiable-e1-neuter",
        expected_rc=0,
        actual_rc=result.rc,
        evidence="temporary E1 neuter goes green, so e1-sudo would fail red",
        passed=passed,
        output=output,
    )


def main() -> int:
    try:
        results = [
            run_case(
                "real-current-tree",
                0,
                "six managed .hcl files pass",
                real_policy_fixture,
                ("PASS:", "source-minter-hwg.hcl", "vso-org-pull-read-nwp.hcl"),
            ),
            run_case(
                "e1-sudo",
                1,
                "E1 sudo capability on e1-sudo.hcl secret/data/team/* bites",
                e1_sudo_fixture,
                ("E1 sudo capability", "e1-sudo.hcl", "secret/data/team/*"),
            ),
            run_case(
                "e2-global-wildcard",
                1,
                "E2 path '*' in e2-wildcard.hcl bites",
                e2_global_wildcard_fixture,
                ("E2 global wildcard path", "e2-wildcard.hcl", "path '*'"),
            ),
            run_case(
                "e3-policy-write",
                1,
                "E3 sys/policies/acl/evil write bites",
                e3_policy_write_fixture,
                ("E3 self-escalation surface", "sys/policies/acl/evil"),
            ),
            run_case(
                "e3-auth-role-write",
                1,
                "E3 auth/kubernetes/role/evil write bites",
                e3_auth_role_write_fixture,
                ("E3 self-escalation surface", "auth/kubernetes/role/evil"),
            ),
            run_case(
                "e3-self-ops",
                0,
                "E3c renew-self/lookup-self false-positive guard passes",
                e3_self_ops_fixture,
                ("PASS:", "e3-self-ops.hcl"),
            ),
            run_case(
                "e4-sys-write",
                1,
                "E4 sys/* write in e4-sys-write.hcl bites",
                e4_sys_write_fixture,
                ("E4 broad sys write", "e4-sys-write.hcl", "sys/*"),
            ),
            run_case(
                "policy-cr-sudo",
                1,
                "Policy CR evil-policy spec.policy sudo bites",
                policy_cr_sudo_fixture,
                ("Policy CR evil-policy", "E1 sudo capability"),
            ),
            run_case(
                "malformed-hcl",
                2,
                "malformed HCL exits tooling error",
                malformed_hcl_fixture,
                ("ERROR:", "unterminated path block"),
            ),
        ]
        results.append(e1_neutered_falsifiability_case())
    except Exception as exc:
        print(f"SELFTEST FAIL: {exc}", file=sys.stderr)
        return 1

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
            print(output_tail(result.output), file=sys.stderr)
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
