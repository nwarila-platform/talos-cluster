#!/usr/bin/env python3
"""Regression self-test for the managed Vault policy allowlist guard."""

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


def _default_policy_roots() -> tuple[Path, ...]:
    # Mirror main(): the DEFAULT .hcl dir is optional — after CP-4 S4a the
    # managed policies live in redhatcop Policy CRs and the last tracked .hcl
    # removal deleted the directory. Explicit --policy-root stays strict.
    root = ROOT / guard.DEFAULT_POLICY_DIR
    return (root,) if root.exists() else ()


def real_tree_fixture(_root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    return _default_policy_roots(), (ROOT / guard.DEFAULT_POLICY_CR_ROOT,)


def policy_path_fixture(
    filename: str,
    vault_path: str,
    capabilities: tuple[str, ...] = ("update",),
) -> Callable[[Path], tuple[tuple[Path, ...], tuple[Path, ...]]]:
    def fixture(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
        capability_list = ", ".join(f'"{capability}"' for capability in capabilities)
        write_text(
            root / f"policies/{filename}",
            f"""
            path "{vault_path}" {{
              capabilities = [{capability_list}]
            }}
            """,
        )
        return (root / "policies",), ()

    return fixture


def policy_cr_path_fixture(
    vault_path: str,
    capabilities: tuple[str, ...] = ("update",),
) -> Callable[[Path], tuple[tuple[Path, ...], tuple[Path, ...]]]:
    def fixture(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
        capability_list = ", ".join(f'"{capability}"' for capability in capabilities)
        write_text(
            root / "vault/policy-cr.yaml",
            f"""
            apiVersion: redhatcop.redhat.io/v1alpha1
            kind: Policy
            metadata:
              name: synthetic-policy
            spec:
              policy: |
                path "{vault_path}" {{
                  capabilities = [{capability_list}]
                }}
            """,
        )
        return (), (root / "vault",)

    return fixture


def policy_cr_list_envelope_fixture(
    root: Path,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    # #312 audit FAIL-1: kustomize expands kind:List items into standalone
    # resources — a List-wrapped Policy CR IS applied, so it must be scanned.
    write_text(
        root / "vault/policy-cr-list.yaml",
        """
        apiVersion: v1
        kind: List
        items:
        - apiVersion: redhatcop.redhat.io/v1alpha1
          kind: Policy
          metadata:
            name: wrapped-policy
          spec:
            policy: |
              path "auth/*" {
                capabilities = ["update"]
              }
        """,
    )
    return (), (root / "vault",)


def malformed_hcl_fixture(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    write_text(
        root / "policies/malformed.hcl",
        """
        path "secret/data/team/provisioned/foo" {
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


def matcher_case(
    name: str,
    pattern: str,
    concrete_path: str,
    expected: bool,
) -> CaseResult:
    actual = guard.vault_glob_matches(pattern, concrete_path)
    return CaseResult(
        name=f"matcher-{name}",
        expected_rc=int(expected),
        actual_rc=int(actual),
        evidence=(
            f"vault_glob_matches({pattern!r}, {concrete_path!r}) "
            f"is {expected}"
        ),
        passed=actual is expected,
        output="",
    )


def covers_case(
    name: str,
    allow_pattern: str,
    policy_pattern: str,
    expected: bool,
) -> CaseResult:
    actual = guard.covers(allow_pattern, policy_pattern)
    return CaseResult(
        name=f"covers-{name}",
        expected_rc=int(expected),
        actual_rc=int(actual),
        evidence=f"covers({allow_pattern!r}, {policy_pattern!r}) is {expected}",
        passed=actual is expected,
        output="",
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


def secret_widen_falsifiability_case() -> CaseResult:
    original_allowlist = guard.MANAGED_POLICY_ALLOWLIST
    broad_entry = guard.ManagedPolicyAllowlistEntry(
        "secret/*", frozenset({"read", "create", "update", "patch", "delete", "list"})
    )
    guard.MANAGED_POLICY_ALLOWLIST = original_allowlist + (broad_entry,)
    try:
        with tempfile.TemporaryDirectory(prefix="vault-policy-guard-") as tmpdir:
            policy_roots, cr_roots = policy_path_fixture(
                "falsifiable-secret-widen.hcl", "secret/*", ("read",)
            )(Path(tmpdir))
            result = run_guard(policy_roots, cr_roots)
    finally:
        guard.MANAGED_POLICY_ALLOWLIST = original_allowlist

    output = result.combined_output
    passed = result.rc == 0 and "allowlist-covered" in output
    return CaseResult(
        name="falsifiable-secret-widen",
        expected_rc=0,
        actual_rc=result.rc,
        evidence="temporary secret/* allowlist widening goes green",
        passed=passed,
        output=output,
    )


def management_allow_falsifiability_case() -> CaseResult:
    original_allowlist = guard.MANAGED_POLICY_ALLOWLIST
    management_entry = guard.ManagedPolicyAllowlistEntry(
        "auth/kubernetes/role/*", frozenset({"create", "update"})
    )
    guard.MANAGED_POLICY_ALLOWLIST = original_allowlist + (management_entry,)
    try:
        with tempfile.TemporaryDirectory(prefix="vault-policy-guard-") as tmpdir:
            policy_roots, cr_roots = policy_path_fixture(
                "falsifiable-management-allow.hcl",
                "auth/kubernetes/role/evil",
                ("create", "update"),
            )(Path(tmpdir))
            result = run_guard(policy_roots, cr_roots)
    finally:
        guard.MANAGED_POLICY_ALLOWLIST = original_allowlist

    output = result.combined_output
    passed = result.rc == 0 and "allowlist-covered" in output
    return CaseResult(
        name="falsifiable-management-allow",
        expected_rc=0,
        actual_rc=result.rc,
        evidence="temporary management-plane allowlist entry goes green",
        passed=passed,
        output=output,
    )


def covers_neutered_falsifiability_case() -> CaseResult:
    original_covers = guard.covers
    guard.covers = lambda _allow_pattern, _policy_pattern: True
    try:
        with tempfile.TemporaryDirectory(prefix="vault-policy-guard-") as tmpdir:
            policy_roots, cr_roots = policy_path_fixture(
                "falsifiable-covers-neuter.hcl", "auth/*", ("update",)
            )(Path(tmpdir))
            result = run_guard(policy_roots, cr_roots)
    finally:
        guard.covers = original_covers

    output = result.combined_output
    passed = result.rc == 0 and "allowlist-covered" in output
    return CaseResult(
        name="falsifiable-covers-neuter",
        expected_rc=0,
        actual_rc=result.rc,
        evidence="temporary covers() neuter goes green for auth/*",
        passed=passed,
        output=output,
    )


def main() -> int:
    try:
        results = [
            matcher_case(
                "exact-true",
                "secret/data/team",
                "secret/data/team",
                True,
            ),
            matcher_case(
                "plus-single-segment-true",
                "auth/+",
                "auth/kubernetes",
                True,
            ),
            matcher_case(
                "trailing-star-prefix-across-slash",
                "auth/*",
                "auth/kubernetes/role/evil",
                True,
            ),
            covers_case(
                "secret-prefix-denies-broader",
                "secret/data/*",
                "secret/*",
                False,
            ),
            covers_case(
                "secret-data-exact-covered",
                "secret/data/*",
                "secret/data/foo",
                True,
            ),
            covers_case(
                "equal-prefix-covered",
                "secret/data/*",
                "secret/data/*",
                True,
            ),
            covers_case(
                "plus-generalizes-literal",
                "secret/data/+/*",
                "secret/data/team/*",
                True,
            ),
            covers_case(
                "literal-does-not-cover-plus",
                "secret/data/team/*",
                "secret/data/+/*",
                False,
            ),
            covers_case(
                "trailing-star-broader",
                "auth/*",
                "auth/kubernetes/*",
                True,
            ),
            covers_case(
                "trailing-star-narrower",
                "auth/kubernetes/*",
                "auth/*",
                False,
            ),
            covers_case(
                "plus-prefix-not-broad-enough",
                "secret/data/+/*",
                "secret/data/*",
                False,
            ),
            run_case(
                "real-tree-cr-scan",
                0,
                "default scan finds the six managed Policy CRs and is clean",
                real_tree_fixture,
                (
                    "allowlist-covered",
                    "Scanned managed Vault policy HCL",
                    "Policy CR source-minter-hwg",
                    "Policy CR tenant-read",
                    "Policy CR tenant-write",
                    "Policy CR vault-snapshot-backup",
                    "Policy CR vso-org-pull-read-hwg",
                    "Policy CR vso-org-pull-read-nwp",
                ),
            ),
            run_case(
                "explicit-missing-policy-root-strict",
                2,
                "an explicitly passed missing --policy-root stays a tooling error",
                lambda root: ((root / "does-not-exist",), ()),
                ("does not exist",),
            ),
            run_case(
                "default-policy-dir-optional",
                0,
                "empty default policy roots + CR sources scan clean (CP-4 S4a shape)",
                lambda root: (
                    (),
                    (
                        write_text(
                            root / "vault/policy-cr.yaml",
                            """
                            apiVersion: redhatcop.redhat.io/v1alpha1
                            kind: Policy
                            metadata:
                              name: cr-only
                            spec:
                              policy: |
                                path "auth/token/lookup-self" {
                                  capabilities = ["read"]
                                }
                            """,
                        ).parent,
                    ),
                ),
                ("allowlist-covered", "Policy CR cr-only"),
            ),
            run_case(
                "allowlisted-secret-read",
                0,
                "exact tenant provisioned read is covered",
                policy_path_fixture(
                    "allowlisted-secret-read.hcl",
                    "secret/data/team/provisioned/foo",
                    ("read",),
                ),
                ("allowlist-covered", "allowlisted-secret-read.hcl"),
            ),
            run_case(
                "deny-only-management-path",
                0,
                "deny-only stanza is ignored as a non-grant",
                policy_path_fixture(
                    "deny-only-management-path.hcl",
                    "auth/kubernetes/role/evil",
                    ("deny",),
                ),
                ("allowlist-covered", "deny-only-management-path.hcl"),
            ),
            run_case(
                "secret-broader-than-allowlist",
                1,
                "secret/* is broader than secret/data/* and is denied",
                policy_path_fixture("secret-broader.hcl", "secret/*", ("read",)),
                ("path-not-allowlisted", "secret/*", "MANAGED_POLICY_ALLOWLIST"),
            ),
            run_case(
                "secret-data-broad-prefix",
                1,
                "secret/data/* is broader than the managed tenant buckets",
                policy_path_fixture("secret-data-broad.hcl", "secret/data/*", ("read",)),
                ("path-not-allowlisted", "secret/data/*"),
            ),
            run_case(
                "broad-auth-prefix",
                1,
                "auth/* is not allowlisted",
                policy_path_fixture("broad-auth-prefix.hcl", "auth/*", ("update",)),
                ("path-not-allowlisted", "auth/*"),
            ),
            run_case(
                "broad-auth-kubernetes-prefix",
                1,
                "auth/kubernetes/* is not allowlisted",
                policy_path_fixture(
                    "broad-auth-kubernetes-prefix.hcl",
                    "auth/kubernetes/*",
                    ("update",),
                ),
                ("path-not-allowlisted", "auth/kubernetes/*"),
            ),
            run_case(
                "broad-sys-policies-prefix",
                1,
                "sys/policies* is not allowlisted",
                policy_path_fixture(
                    "broad-sys-policies-prefix.hcl",
                    "sys/policies*",
                    ("update",),
                ),
                ("path-not-allowlisted", "sys/policies*"),
            ),
            run_case(
                "broad-sys-mounts-prefix",
                1,
                "sys/mounts* is not allowlisted",
                policy_path_fixture(
                    "broad-sys-mounts-prefix.hcl",
                    "sys/mounts*",
                    ("update",),
                ),
                ("path-not-allowlisted", "sys/mounts*"),
            ),
            run_case(
                "broad-identity-prefix",
                1,
                "identity* is not allowlisted",
                policy_path_fixture(
                    "broad-identity-prefix.hcl",
                    "identity*",
                    ("update",),
                ),
                ("path-not-allowlisted", "identity*"),
            ),
            run_case(
                "broad-auth-segment-wildcards",
                1,
                "auth/+/+/+ is not allowlisted",
                policy_path_fixture(
                    "broad-auth-segment-wildcards.hcl",
                    "auth/+/+/+",
                    ("update",),
                ),
                ("path-not-allowlisted", "auth/+/+/+"),
            ),
            run_case(
                "broad-sys-prefix",
                1,
                "sys/* is not allowlisted",
                policy_path_fixture("broad-sys-prefix.hcl", "sys/*", ("update",)),
                ("path-not-allowlisted", "sys/*"),
            ),
            run_case(
                "global-wildcard",
                1,
                "path '*' is not allowlisted",
                policy_path_fixture("global-wildcard.hcl", "*", ("read",)),
                ("path-not-allowlisted", "path '*'"),
            ),
            run_case(
                "auth-kubernetes-role",
                1,
                "auth/kubernetes/role/evil is not allowlisted",
                policy_path_fixture(
                    "auth-kubernetes-role.hcl",
                    "auth/kubernetes/role/evil",
                    ("create", "update"),
                ),
                ("path-not-allowlisted", "auth/kubernetes/role/evil"),
            ),
            run_case(
                "token-roles-prefix",
                1,
                "auth/token/roles/* is not allowlisted",
                policy_path_fixture(
                    "token-roles-prefix.hcl",
                    "auth/token/roles/*",
                    ("update",),
                ),
                ("path-not-allowlisted", "auth/token/roles/*"),
            ),
            run_case(
                "token-create-prefix",
                1,
                "auth/token/create/* is not allowlisted",
                policy_path_fixture(
                    "token-create-prefix.hcl",
                    "auth/token/create/*",
                    ("update",),
                ),
                ("path-not-allowlisted", "auth/token/create/*"),
            ),
            run_case(
                "snapshot-create-capability",
                1,
                "snapshot path allows read only, not create",
                policy_path_fixture(
                    "snapshot-create-capability.hcl",
                    "sys/storage/raft/snapshot",
                    ("create",),
                ),
                ("capability-exceeds-allowlist", "sys/storage/raft/snapshot"),
            ),
            run_case(
                "sudo-capability",
                1,
                "sudo is not in any allowlist capability set",
                policy_path_fixture(
                    "sudo-capability.hcl",
                    "secret/data/team/provisioned/foo",
                    ("read", "sudo"),
                ),
                ("capability-exceeds-allowlist", "sudo"),
            ),
            run_case(
                "policy-cr-broad-auth",
                1,
                "Policy CR spec.policy is scanned and denied",
                policy_cr_path_fixture("auth/*", ("update",)),
                ("Policy CR synthetic-policy", "path-not-allowlisted", "auth/*"),
            ),
            run_case(
                "policy-cr-list-envelope",
                1,
                "List-wrapped Policy CR is descended into and denied",
                policy_cr_list_envelope_fixture,
                ("Policy CR wrapped-policy", "path-not-allowlisted", "auth/*"),
            ),
            run_case(
                "malformed-hcl",
                2,
                "malformed HCL exits tooling error",
                malformed_hcl_fixture,
                ("ERROR:", "unterminated path block"),
            ),
        ]
        results.append(secret_widen_falsifiability_case())
        results.append(management_allow_falsifiability_case())
        results.append(covers_neutered_falsifiability_case())
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
