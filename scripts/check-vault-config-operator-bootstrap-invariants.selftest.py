#!/usr/bin/env python3
"""Offline regression self-test for the bootstrap-invariant guard."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-vault-config-operator-bootstrap-invariants.py"


def load_guard():
    spec = importlib.util.spec_from_file_location("_bootstrap_guard", GUARD)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {GUARD}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = load_guard()
s0 = guard._load_s0_guard()

VALID_POLICY = """\
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "sys/policies/acl/tenant-read" { capabilities = ["create", "read", "update"] }
path "auth/kubernetes/role/tenant" { capabilities = ["create", "read", "update"] }
path "sys/mounts/pki-int-tcn" { capabilities = ["create", "read", "update"] }
path "pki-int-tcn/*" { capabilities = ["create", "read", "update"] }
"""

VALID_ROLE = """\
{
  "bound_service_account_names": ["vault-config-operator-vault"],
  "bound_service_account_namespaces": ["vault-config-operator"],
  "token_policies": ["vault-config-operator"],
  "token_no_default_policy": true,
  "token_ttl": "15m",
  "token_max_ttl": "30m"
}
"""


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_valid_tree(root: Path) -> None:
    paths = guard.paths_for_root(root)
    write(paths.bootstrap_policy, VALID_POLICY)
    write(paths.bootstrap_role, VALID_ROLE)
    # a benign managed policy so the managed dir exists and is scanned clean
    write(paths.managed_policy_dir / "tenant-read.hcl",
          'path "secret/data/x" { capabilities = ["read"] }\n')


def case_clean(root: Path) -> None:
    build_valid_tree(root)


def case_missing_policy(root: Path) -> None:
    build_valid_tree(root)
    guard.paths_for_root(root).bootstrap_policy.unlink()


def case_grants_sudo(root: Path) -> None:
    build_valid_tree(root)
    p = guard.paths_for_root(root).bootstrap_policy
    write(p, VALID_POLICY + 'path "sys/mounts/pki-int-tcn/tune" { capabilities = ["read", "sudo"] }\n')


def case_wildcard_path(root: Path) -> None:
    build_valid_tree(root)
    p = guard.paths_for_root(root).bootstrap_policy
    write(p, VALID_POLICY + 'path "*" { capabilities = ["create", "read", "update"] }\n')


def case_identity_managed_hcl(root: Path) -> None:
    build_valid_tree(root)
    mgd = guard.paths_for_root(root).managed_policy_dir
    write(mgd / "vault-config-operator.hcl",
          'path "sys/policies/acl/x" { capabilities = ["create"] }\n')


def case_identity_policy_cr(root: Path) -> None:
    build_valid_tree(root)
    cr = guard.paths_for_root(root).cluster_root / "apps/foo/policy.yaml"
    write(cr, (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: Policy\n"
        "metadata:\n"
        "  name: vault-config-operator\n"
        "spec:\n"
        "  policy: |\n"
        '    path "sys/policies/acl/x" { capabilities = ["create"] }\n'
    ))


def case_identity_kaer_cr(root: Path) -> None:
    build_valid_tree(root)
    cr = guard.paths_for_root(root).cluster_root / "apps/foo/role.yaml"
    write(cr, (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: KubernetesAuthEngineRole\n"
        "metadata:\n"
        "  name: vault-config-operator\n"
        "spec:\n"
        "  path: kubernetes\n"
    ))


def case_bootstrap_in_kustomization(root: Path) -> None:
    build_valid_tree(root)
    bdir = guard.paths_for_root(root).bootstrap_dir
    write(bdir / "kustomization.yaml", (
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n"
        "  - vault-config-operator.policy.hcl\n"
    ))


CASES = [
    ("clean", case_clean, True),
    ("missing-bootstrap-policy", case_missing_policy, False),
    ("bootstrap-grants-sudo", case_grants_sudo, False),
    ("bootstrap-wildcard-path", case_wildcard_path, False),
    ("identity-as-managed-hcl", case_identity_managed_hcl, False),
    ("identity-as-policy-cr", case_identity_policy_cr, False),
    ("identity-as-kaer-cr", case_identity_kaer_cr, False),
    ("bootstrap-referenced-by-kustomization", case_bootstrap_in_kustomization, False),
]


def main() -> int:
    failures = []
    for name, builder, expect_clean in CASES:
        with tempfile.TemporaryDirectory(prefix="vco-bootstrap-guard-") as tmp:
            root = Path(tmp)
            builder(root)
            findings = guard.evaluate(root, s0)
        ok = (not findings) if expect_clean else bool(findings)
        status = "PASS" if ok else "FAIL"
        print(f"{status}  {name:<40} findings={len(findings)}")
        if not ok:
            failures.append((name, findings))
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for name, findings in failures:
            print(f"  [{name}] findings={findings}", file=sys.stderr)
        return 1
    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
