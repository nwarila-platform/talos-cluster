#!/usr/bin/env python3
"""Offline regression self-test for the bootstrap-invariant guard."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import yaml

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

# The managed set the fixtures declare: policy "tenant-read", Kubernetes role
# "tenant", and the shared jwt-github config. The three AR4a stanzas are one
# indivisible grant set.
RATIFIED_JWT_GRANTS = """\
path "auth/jwt-github/config" {
  capabilities = ["create", "read", "update"]
}
path "auth/jwt-github/role/deploy-*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "sys/policies/acl/deploy-*" {
  capabilities = ["create", "read", "update", "delete"]
}
"""

VALID_POLICY = RATIFIED_JWT_GRANTS + """\
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "sys/policies/acl/tenant-read" { capabilities = ["create", "read", "update"] }
path "auth/kubernetes/role/tenant" { capabilities = ["create", "read", "update"] }
path "sys/mounts/pki-int-tcn" { capabilities = ["create", "read", "update"] }
path "pki-int-tcn/config/*" { capabilities = ["create", "read", "update"] }
path "sys/policies/acl/vault-config-operator-smoke" { capabilities = ["create", "read", "update", "delete"] }
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


def ensure_render_scaffold(root: Path) -> None:
    paths = guard.paths_for_root(root)
    managed = paths.cluster_root / "apps/vault/vault-config/managed"
    managed.mkdir(parents=True, exist_ok=True)
    config = managed / "jwtoidcauthengineconfig-jwt-github.yaml"
    if not config.exists():
        write(
            config,
            (
                "apiVersion: redhatcop.redhat.io/v1alpha1\n"
                "kind: JWTOIDCAuthEngineConfig\n"
                "metadata:\n"
                "  name: jwt-github\n"
                "spec:\n"
                "  path: jwt-github\n"
            ),
        )
    kustomization = managed / "kustomization.yaml"
    external_resources: list[str] = []
    if kustomization.is_file():
        existing = yaml.safe_load(kustomization.read_text(encoding="utf-8")) or {}
        for resource in existing.get("resources", []) or []:
            if isinstance(resource, str) and resource.startswith("../"):
                external_resources.append(resource)
    local_resources = sorted(
        path.name
        for path in managed.iterdir()
        if path.is_file() and path.name != "kustomization.yaml"
    )
    write(
        kustomization,
        yaml.safe_dump(
            {
                "apiVersion": "kustomize.config.k8s.io/v1beta1",
                "kind": "Kustomization",
                "namespace": "vault-config-operator",
                "resources": local_resources + external_resources,
            },
            sort_keys=False,
        ),
    )
    health = [
        {
            "apiVersion": guard.rendered_inventory.REDHATCOP_API_VERSION,
            "kind": kind,
            "current": guard.rendered_inventory.HEALTH_CURRENT,
        }
        for kind in guard.rendered_inventory.JWT_KINDS
    ]
    flux = paths.cluster_root / "apps/kustomization-vault-config-managed.yaml"
    write(
        flux,
        yaml.safe_dump(
            {
                "apiVersion": guard.rendered_inventory.FLUX_API_VERSION,
                "kind": "Kustomization",
                "metadata": {
                    "name": "vault-config-managed",
                    "namespace": "flux-system",
                },
                "spec": {
                    "interval": "10m",
                    "path": (
                        "./clusters/talos-cluster/apps/vault/"
                        "vault-config/managed"
                    ),
                    "prune": True,
                    "wait": True,
                    "dependsOn": [
                        {"name": "vault-config-operator"},
                        {"name": "vault"},
                    ],
                    "sourceRef": {
                        "kind": "GitRepository",
                        "name": "flux-system",
                    },
                    "healthCheckExprs": health,
                },
            },
            sort_keys=False,
        ),
    )
    write(
        paths.cluster_root / "apps/kustomization.yaml",
        (
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "resources:\n"
            "  - kustomization-vault-config-managed.yaml\n"
        ),
    )
    write(
        paths.cluster_root / "kustomization.yaml",
        (
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "resources:\n"
            "  - apps\n"
        ),
    )


def build_valid_tree(root: Path, policy: str = VALID_POLICY) -> None:
    paths = guard.paths_for_root(root)
    write(paths.bootstrap_policy, policy)
    write(paths.bootstrap_role, VALID_ROLE)
    write(paths.managed_policy_dir / "tenant-read.hcl",
          'path "secret/data/x" { capabilities = ["read"] }\n')
    write(paths.cluster_root / "apps/vault/vault-config/auth/kubernetes/roles/tenant.json",
          '{"bound_service_account_names": ["vault-client"]}\n')
    write(
        paths.cluster_root
        / "apps/vault/vault-config/managed/jwtoidcauthengineconfig-jwt-github.yaml",
        (
            "apiVersion: redhatcop.redhat.io/v1alpha1\n"
            "kind: JWTOIDCAuthEngineConfig\n"
            "metadata:\n"
            "  name: jwt-github\n"
            "spec:\n"
            "  path: jwt-github\n"
        ),
    )


def case_clean(root: Path) -> None:
    build_valid_tree(root)


def case_missing_policy(root: Path) -> None:
    build_valid_tree(root)
    guard.paths_for_root(root).bootstrap_policy.unlink()


def case_grants_sudo(root: Path) -> None:
    build_valid_tree(
        root, VALID_POLICY + 'path "sys/mounts/pki-int-tcn/tune" { capabilities = ["read", "sudo"] }\n'
    )


def case_wildcard_root_path(root: Path) -> None:
    build_valid_tree(root, VALID_POLICY + 'path "*" { capabilities = ["read"] }\n')


def case_root_slash(root: Path) -> None:
    # BLOCKING regression (auditor B #2): `path "/"` normalizes to "" and must
    # still be caught as a root grant.
    build_valid_tree(root, VALID_POLICY + 'path "/" { capabilities = ["read"] }\n')


def case_self_grant_policy(root: Path) -> None:
    # BLOCKING (auditor B #1): exact self-policy write → self-escalation.
    build_valid_tree(
        root, VALID_POLICY + 'path "sys/policies/acl/vault-config-operator" { capabilities = ["create", "update"] }\n'
    )


def case_self_grant_role(root: Path) -> None:
    build_valid_tree(
        root, VALID_POLICY + 'path "auth/kubernetes/role/vault-config-operator" { capabilities = ["create", "update"] }\n'
    )


def case_self_grant_policy_wildcard(root: Path) -> None:
    # `sys/policies/acl/*` covers its own policy — the wildcard self-escalation.
    build_valid_tree(
        root, VALID_POLICY + 'path "sys/policies/acl/*" { capabilities = ["create", "update"] }\n'
    )


def case_mgmt_plane_wildcard_role(root: Path) -> None:
    build_valid_tree(
        root, VALID_POLICY + 'path "auth/kubernetes/role/*" { capabilities = ["create", "update"] }\n'
    )


def case_over_grant_unmanaged(root: Path) -> None:
    build_valid_tree(
        root, VALID_POLICY + 'path "sys/policies/acl/not-a-real-policy" { capabilities = ["create", "read", "update"] }\n'
    )


def case_missing_enumeration(root: Path) -> None:
    # A managed policy file exists that the bootstrap does NOT enumerate.
    build_valid_tree(root)
    mgd = guard.paths_for_root(root).managed_policy_dir
    write(mgd / "extra-managed.hcl", 'path "secret/data/y" { capabilities = ["read"] }\n')


def case_delete_on_real_path(root: Path) -> None:
    # `delete` on an exact-path real object is still forbidden. Only the two
    # ratified deploy-* offboarding globs may carry it.
    policy = VALID_POLICY.replace(
        'path "sys/policies/acl/tenant-read" { capabilities = ["create", "read", "update"] }',
        'path "sys/policies/acl/tenant-read" { capabilities = ["create", "read", "update", "delete"] }',
    )
    build_valid_tree(root, policy)


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


def case_identity_cr_specname_bypass(root: Path) -> None:
    # Regression lock (auditor B #3): innocuous metadata.name but spec.name is
    # the operator identity — must still be caught.
    build_valid_tree(root)
    cr = guard.paths_for_root(root).cluster_root / "apps/foo/sneaky.yaml"
    write(cr, (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: Policy\n"
        "metadata:\n"
        "  name: totally-innocuous\n"
        "spec:\n"
        "  name: vault-config-operator\n"
        "  policy: |\n"
        '    path "sys/policies/acl/x" { capabilities = ["create"] }\n'
    ))


def case_clean_cr_only(root: Path) -> None:
    # CP-4 S4a shape: the managed set expressed ONLY as redhatcop CRs — no
    # legacy .hcl / .json capture files at all (the .hcl dir does not exist).
    paths = guard.paths_for_root(root)
    write(paths.bootstrap_policy, VALID_POLICY)
    write(paths.bootstrap_role, VALID_ROLE)
    mgd = paths.cluster_root / "apps/vault/vault-config/managed"
    write(mgd / "policy-tenant-read.yaml", (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: Policy\n"
        "metadata:\n"
        "  name: tenant-read\n"
        "spec:\n"
        "  type: acl\n"
        "  policy: |\n"
        '    path "secret/data/x" { capabilities = ["read"] }\n'
    ))
    write(mgd / "role-tenant.yaml", (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: KubernetesAuthEngineRole\n"
        "metadata:\n"
        "  name: tenant\n"
        "spec:\n"
        "  path: kubernetes\n"
        "  policies:\n"
        "    - tenant-read\n"
    ))


def case_cr_missing_enumeration(root: Path) -> None:
    # A managed Policy CR exists that the bootstrap does NOT enumerate — the
    # operator could not adopt it (S4 runtime break). CR-derived analogue of
    # case_missing_enumeration.
    build_valid_tree(root)
    mgd = guard.paths_for_root(root).cluster_root / "apps/vault/vault-config/managed"
    write(mgd / "policy-extra.yaml", (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: Policy\n"
        "metadata:\n"
        "  name: extra-cr-policy\n"
        "spec:\n"
        "  type: acl\n"
        "  policy: |\n"
        '    path "secret/data/x" { capabilities = ["read"] }\n'
    ))


def case_cr_specname_enumeration(root: Path) -> None:
    # The effective Vault name is spec.name (not metadata.name): a CR whose
    # spec.name is unenumerated must FAIL even if metadata.name matches an
    # enumerated grant.
    build_valid_tree(root)
    mgd = guard.paths_for_root(root).cluster_root / "apps/vault/vault-config/managed"
    write(mgd / "policy-sneaky-name.yaml", (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: Policy\n"
        "metadata:\n"
        "  name: tenant-read\n"
        "spec:\n"
        "  name: unenumerated-real-name\n"
        "  type: acl\n"
        "  policy: |\n"
        '    path "secret/data/x" { capabilities = ["read"] }\n'
    ))


def case_vault_admin_policy_cr(root: Path) -> None:
    # Break-glass protection: a redhatcop Policy CR managing vault-admin.
    build_valid_tree(root)
    cr = guard.paths_for_root(root).cluster_root / "apps/foo/breakglass.yaml"
    write(cr, (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: Policy\n"
        "metadata:\n"
        "  name: vault-admin\n"
        "spec:\n"
        "  policy: |\n"
        '    path "secret/data/x" { capabilities = ["read"] }\n'
    ))


def case_vault_admin_specname_bypass(root: Path) -> None:
    build_valid_tree(root)
    cr = guard.paths_for_root(root).cluster_root / "apps/foo/sneaky-admin.yaml"
    write(cr, (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: Policy\n"
        "metadata:\n"
        "  name: innocent-name\n"
        "spec:\n"
        "  name: vault-admin\n"
        "  policy: |\n"
        '    path "secret/data/x" { capabilities = ["read"] }\n'
    ))


def case_bootstrap_grants_vault_admin_path(root: Path) -> None:
    # The operator bootstrap policy must never cover the break-glass policy.
    build_valid_tree(
        root,
        VALID_POLICY
        + 'path "sys/policies/acl/vault-admin" { capabilities = ["create", "read", "update"] }\n',
    )


def case_vault_admin_list_envelope_bypass(root: Path) -> None:
    # #312 audit FAIL-1: kustomize expands a kind:List envelope into standalone
    # resources, so a List-wrapped vault-admin Policy CR IS applied live. The
    # guard must descend into items.
    build_valid_tree(root)
    cr = guard.paths_for_root(root).cluster_root / "apps/foo/wrapped.yaml"
    write(cr, (
        "apiVersion: v1\n"
        "kind: List\n"
        "items:\n"
        "- apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "  kind: Policy\n"
        "  metadata:\n"
        "    name: vault-admin\n"
        "  spec:\n"
        "    policy: |\n"
        '      path "secret/data/x" { capabilities = ["read"] }\n'
    ))


def case_vault_admin_case_fold_bypass(root: Path) -> None:
    # #312 audit FAIL-2: Vault lowercases ACL policy names on write, so a CR
    # named VAULT-ADMIN lands on vault-admin live. The name compare must fold.
    build_valid_tree(root)
    cr = guard.paths_for_root(root).cluster_root / "apps/foo/shouty-admin.yaml"
    write(cr, (
        "apiVersion: redhatcop.redhat.io/v1alpha1\n"
        "kind: Policy\n"
        "metadata:\n"
        "  name: innocent-name\n"
        "spec:\n"
        "  name: VAULT-ADMIN\n"
        "  policy: |\n"
        '    path "secret/data/x" { capabilities = ["read"] }\n'
    ))


def case_bootstrap_grants_vault_admin_case_path(root: Path) -> None:
    # #312 audit FAIL-2 (bootstrap leg): a case-variant grant still covers the
    # break-glass policy once Vault folds the name — the covers() compare must
    # fold too.
    build_valid_tree(
        root,
        VALID_POLICY
        + 'path "sys/policies/acl/VAULT-ADMIN" { capabilities = ["create", "read", "update"] }\n',
    )


def case_clean_with_vault_admin_capture(root: Path) -> None:
    # The out-of-band vault-admin DR capture in bootstrap/ must NOT trip the
    # guard (it is deliberately outside the managed set and the S0 scan).
    build_valid_tree(root)
    bdir = guard.paths_for_root(root).bootstrap_dir
    write(bdir / "vault-admin.policy.hcl",
          'path "auth/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }\n')


def case_bootstrap_in_kustomization(root: Path) -> None:
    build_valid_tree(root)
    bdir = guard.paths_for_root(root).bootstrap_dir
    write(bdir / "kustomization.yaml", (
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n"
        "  - vault-config-operator.policy.hcl\n"
    ))


def without_stanza(policy: str, stanza: str) -> str:
    if stanza not in policy:
        raise AssertionError(f"fixture stanza not found: {stanza!r}")
    return policy.replace(stanza, "", 1)


def case_missing_jwt_config_grant(root: Path) -> None:
    build_valid_tree(
        root,
        without_stanza(
            VALID_POLICY,
            'path "auth/jwt-github/config" {\n'
            '  capabilities = ["create", "read", "update"]\n'
            "}\n",
        ),
    )


def case_missing_jwt_role_glob(root: Path) -> None:
    build_valid_tree(
        root,
        without_stanza(
            VALID_POLICY,
            'path "auth/jwt-github/role/deploy-*" {\n'
            '  capabilities = ["create", "read", "update", "delete"]\n'
            "}\n",
        ),
    )


def case_missing_deploy_policy_glob(root: Path) -> None:
    build_valid_tree(
        root,
        without_stanza(
            VALID_POLICY,
            'path "sys/policies/acl/deploy-*" {\n'
            '  capabilities = ["create", "read", "update", "delete"]\n'
            "}\n",
        ),
    )


def case_jwt_role_glob_over_broad(root: Path) -> None:
    build_valid_tree(
        root,
        VALID_POLICY.replace(
            'path "auth/jwt-github/role/deploy-*"',
            'path "auth/jwt-github/role/*"',
            1,
        ),
    )


def case_jwt_config_over_capable(root: Path) -> None:
    build_valid_tree(
        root,
        VALID_POLICY.replace(
            'capabilities = ["create", "read", "update"]',
            'capabilities = ["create", "read", "update", "delete"]',
            1,
        ),
    )


def case_jwt_role_glob_over_capable(root: Path) -> None:
    build_valid_tree(
        root,
        VALID_POLICY.replace(
            'path "auth/jwt-github/role/deploy-*" {\n'
            '  capabilities = ["create", "read", "update", "delete"]',
            'path "auth/jwt-github/role/deploy-*" {\n'
            '  capabilities = ["create", "read", "update", "delete", "list"]',
            1,
        ),
    )


def case_deploy_policy_glob_over_capable(root: Path) -> None:
    build_valid_tree(
        root,
        VALID_POLICY.replace(
            'path "sys/policies/acl/deploy-*" {\n'
            '  capabilities = ["create", "read", "update", "delete"]',
            'path "sys/policies/acl/deploy-*" {\n'
            '  capabilities = ["create", "read", "update", "delete", "list"]',
            1,
        ),
    )


def case_jwt_grant_case_variant(root: Path) -> None:
    build_valid_tree(
        root,
        VALID_POLICY.replace(
            'path "auth/jwt-github/config"',
            'path "AUTH/JWT-GITHUB/CONFIG"',
            1,
        ),
    )


def case_unratified_exact_deploy_role(root: Path) -> None:
    build_valid_tree(
        root,
        VALID_POLICY
        + 'path "auth/jwt-github/role/deploy-example" '
        '{ capabilities = ["create", "read", "update", "delete"] }\n',
    )


def case_jwt_config_path_not_ratified(root: Path) -> None:
    build_valid_tree(root)
    managed = (
        guard.paths_for_root(root).cluster_root
        / "apps/vault/vault-config/managed/jwtoidcauthengineconfig-jwt-github.yaml"
    )
    managed.write_text(
        managed.read_text(encoding="utf-8").replace(
            "  path: jwt-github\n", "  path: jwt-other\n", 1
        ),
        encoding="utf-8",
    )


def case_clean_with_deploy_role_and_policy(root: Path) -> None:
    build_valid_tree(root)
    managed = (
        guard.paths_for_root(root).cluster_root
        / "apps/vault/vault-config/managed"
    )
    write(
        managed / "policy-deploy-example.yaml",
        (
            "apiVersion: redhatcop.redhat.io/v1alpha1\n"
            "kind: Policy\n"
            "metadata:\n"
            "  name: deploy-example\n"
            "spec:\n"
            "  policy: |\n"
            '    path "secret/data/deploy/example/*" { capabilities = ["read"] }\n'
        ),
    )
    write(
        managed / "jwtoidcauthenginerole-deploy-example.yaml",
        (
            "apiVersion: redhatcop.redhat.io/v1alpha1\n"
            "kind: JWTOIDCAuthEngineRole\n"
            "metadata:\n"
            "  name: deploy-example\n"
            "spec:\n"
            "  name: deploy-example\n"
            "  path: jwt-github\n"
        ),
    )


def case_jwt_role_outside_ratified_prefix(root: Path) -> None:
    build_valid_tree(root)
    managed = (
        guard.paths_for_root(root).cluster_root
        / "apps/vault/vault-config/managed"
    )
    write(
        managed / "jwtoidcauthenginerole-admin.yaml",
        (
            "apiVersion: redhatcop.redhat.io/v1alpha1\n"
            "kind: JWTOIDCAuthEngineRole\n"
            "metadata:\n"
            "  name: admin\n"
            "spec:\n"
            "  name: admin\n"
            "  path: jwt-github\n"
        ),
    )


def case_unknown_managed_redhatcop_kind(root: Path) -> None:
    build_valid_tree(root)
    managed = (
        guard.paths_for_root(root).cluster_root
        / "apps/vault/vault-config/managed/unknown.yaml"
    )
    write(
        managed,
        (
            "apiVersion: redhatcop.redhat.io/v1alpha1\n"
            "kind: FuturePrivilegeWriter\n"
            "metadata:\n"
            "  name: surprise\n"
            "spec: {}\n"
        ),
    )


CASES = [
    ("clean", case_clean, True),
    ("missing-jwt-config-grant", case_missing_jwt_config_grant, False),
    ("missing-jwt-role-glob", case_missing_jwt_role_glob, False),
    ("missing-deploy-policy-glob", case_missing_deploy_policy_glob, False),
    ("jwt-role-glob-over-broad", case_jwt_role_glob_over_broad, False),
    ("jwt-config-over-capable", case_jwt_config_over_capable, False),
    ("jwt-role-glob-over-capable", case_jwt_role_glob_over_capable, False),
    ("deploy-policy-glob-over-capable", case_deploy_policy_glob_over_capable, False),
    ("jwt-grant-case-variant", case_jwt_grant_case_variant, False),
    ("unratified-exact-deploy-role", case_unratified_exact_deploy_role, False),
    ("jwt-config-path-not-ratified", case_jwt_config_path_not_ratified, False),
    ("clean-with-deploy-role-and-policy", case_clean_with_deploy_role_and_policy, True),
    ("jwt-role-outside-ratified-prefix", case_jwt_role_outside_ratified_prefix, False),
    ("unknown-managed-redhatcop-kind", case_unknown_managed_redhatcop_kind, False),
    ("missing-bootstrap-policy", case_missing_policy, False),
    ("bootstrap-grants-sudo", case_grants_sudo, False),
    ("bootstrap-wildcard-root-path", case_wildcard_root_path, False),
    ("bootstrap-root-slash", case_root_slash, False),
    ("self-grant-own-policy", case_self_grant_policy, False),
    ("self-grant-own-role", case_self_grant_role, False),
    ("self-grant-policy-wildcard", case_self_grant_policy_wildcard, False),
    ("mgmt-plane-wildcard-role", case_mgmt_plane_wildcard_role, False),
    ("over-grant-unmanaged", case_over_grant_unmanaged, False),
    ("missing-enumeration", case_missing_enumeration, False),
    ("delete-on-real-path", case_delete_on_real_path, False),
    ("identity-as-managed-hcl", case_identity_managed_hcl, False),
    ("identity-as-policy-cr", case_identity_policy_cr, False),
    ("identity-as-kaer-cr", case_identity_kaer_cr, False),
    ("identity-cr-specname-bypass", case_identity_cr_specname_bypass, False),
    ("clean-cr-only-managed-set", case_clean_cr_only, True),
    ("cr-missing-enumeration", case_cr_missing_enumeration, False),
    ("cr-specname-enumeration", case_cr_specname_enumeration, False),
    ("vault-admin-as-policy-cr", case_vault_admin_policy_cr, False),
    ("vault-admin-specname-bypass", case_vault_admin_specname_bypass, False),
    ("bootstrap-grants-vault-admin-path", case_bootstrap_grants_vault_admin_path, False),
    ("vault-admin-list-envelope-bypass", case_vault_admin_list_envelope_bypass, False),
    ("vault-admin-case-fold-bypass", case_vault_admin_case_fold_bypass, False),
    ("bootstrap-grants-vault-admin-case-path", case_bootstrap_grants_vault_admin_case_path, False),
    ("clean-with-vault-admin-capture", case_clean_with_vault_admin_capture, True),
    ("bootstrap-referenced-by-kustomization", case_bootstrap_in_kustomization, False),
]


def main() -> int:
    failures = []
    for name, builder, expect_clean in CASES:
        with tempfile.TemporaryDirectory(prefix="vco-bootstrap-guard-") as tmp:
            root = Path(tmp)
            builder(root)
            ensure_render_scaffold(root)
            inventory = guard.rendered_inventory.load_rendered_inventory(root)
            findings = guard.evaluate(root, s0, inventory)
            object_count = len(inventory.documents)
        ok = (not findings) if expect_clean else bool(findings)
        status = "PASS" if ok else "FAIL"
        guard_status = "PASS" if not findings else "FAIL"
        print(
            f"{status}  {name:<40} "
            f"guard={guard_status} findings={len(findings)} "
            f"rendered_objects={object_count}"
        )
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
