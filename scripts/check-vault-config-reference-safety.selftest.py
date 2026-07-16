#!/usr/bin/env python3
"""Regression self-test for the S6b vault-config reference-safety guard.

Each case builds a MINIMAL fixture repo in a temp dir (managed CRs, capture
JSONs, cluster consumers, the pinned-consumer stub files) and runs the guard
with --root against it, asserting exit code + a finding fragment. The guard
itself has NO test-only bypass: fixtures must satisfy the same pinned-consumer
anchors the real tree does.
"""

from __future__ import annotations

import contextlib
import io
import importlib.util
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-vault-config-reference-safety.py"

MANAGED = "clusters/talos-cluster/apps/vault/vault-config/managed"
CAPTURES = "clusters/talos-cluster/apps/vault/vault-config/auth/kubernetes/roles"
PIN_CRON = "clusters/talos-cluster/apps/source-rotator/cronjob.yaml"
PIN_DRILL = "clusters/talos-cluster/apps/vault/restore-drill/s0-restore-generate-root.sh"


def load_guard():
    spec = importlib.util.spec_from_file_location("ref_safety_guard", GUARD)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = load_guard()


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")


def base_fixture(root: Path) -> None:
    """A minimal healthy tree: 2 policies, 1 managed role, 1 capture role,
    1 mount + 1 PKI role, 1 issuer + 1 certificate, both pinned consumers."""
    write(root, f"{MANAGED}/policy-source-minter-hwg.yaml", """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: Policy
        metadata: {name: source-minter-hwg}
        spec: {type: acl, policy: "path \\"x\\" {}"}
    """)
    write(root, f"{MANAGED}/policy-tenant-read.yaml", """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: Policy
        metadata: {name: tenant-read}
        spec: {type: acl, policy: "path \\"y\\" {}"}
    """)
    write(root, f"{MANAGED}/policy-vault-snapshot-backup.yaml", """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: Policy
        metadata: {name: vault-snapshot-backup}
        spec: {type: acl, policy: "path \\"z\\" {}"}
    """)
    write(root, f"{MANAGED}/role-source-minter-hwg.yaml", """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: KubernetesAuthEngineRole
        metadata: {name: source-minter-hwg}
        spec:
          policies: [source-minter-hwg]
    """)
    write(root, f"{MANAGED}/role-vault-snapshot-backup.yaml", """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: KubernetesAuthEngineRole
        metadata: {name: vault-snapshot-backup}
        spec:
          policies: [vault-snapshot-backup]
    """)
    write(root, f"{MANAGED}/secretenginemount-pki-int-tcn.yaml", """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: SecretEngineMount
        metadata: {name: pki-int-tcn}
        spec: {type: pki}
    """)
    write(root, f"{MANAGED}/pkirole-vault-server.yaml", """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: PKISecretEngineRole
        metadata: {name: vault-server}
        spec: {}
    """)
    write(root, f"{CAPTURES}/tenant.json", '{"token_policies": ["tenant-read"]}\n')
    write(root, "clusters/talos-cluster/apps/vso/vaultauth-tenant.yaml", """
        apiVersion: secrets.hashicorp.com/v1beta1
        kind: VaultAuth
        metadata: {name: tenant}
        spec:
          kubernetes: {role: tenant}
    """)
    write(root, "clusters/talos-cluster/apps/vault-tls-cm/clusterissuer.yaml", """
        apiVersion: cert-manager.io/v1
        kind: ClusterIssuer
        metadata: {name: vault-server}
        spec:
          vault: {path: pki-int-tcn/sign/vault-server}
    """)
    write(root, "clusters/talos-cluster/apps/vault-tls-cm/certificate.yaml", """
        apiVersion: cert-manager.io/v1
        kind: Certificate
        metadata: {name: vault-serving-cert-cm}
        spec:
          issuerRef: {name: vault-server, kind: ClusterIssuer}
    """)
    write(root, PIN_CRON, "env:\n  - name: VAULT_ROLE\n    value: source-minter-hwg\n")
    write(root, PIN_DRILL, 'login with {"role": "vault-snapshot-backup", "jwt": j}\n')


def run_guard(root: Path) -> tuple[int, str]:
    argv = sys.argv
    sys.argv = ["guard", "--root", str(root)]
    stdout, stderr = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                rc = guard.main()
            except SystemExit as exc:
                rc = int(exc.code or 0)
    finally:
        sys.argv = argv
    return rc, stdout.getvalue() + "\n" + stderr.getvalue()


CASES = []


def case(name, expected_rc, mutate, *fragments):
    CASES.append((name, expected_rc, mutate, fragments))


def no_mutation(root):
    pass


case("healthy-tree-passes", 0, no_mutation, "PASS", "reference edge(s)")


def drop_referenced_policy(root):
    (root / f"{MANAGED}/policy-source-minter-hwg.yaml").unlink()


case(
    "removing-a-role-bound-policy-fails",
    1,
    drop_referenced_policy,
    "references policy 'source-minter-hwg'",
)


def drop_capture_referenced_policy(root):
    (root / f"{MANAGED}/policy-tenant-read.yaml").unlink()


case(
    "removing-a-capture-bound-policy-fails",
    1,
    drop_capture_referenced_policy,
    "capture-only role 'tenant'",
)


def drop_capture_role(root):
    (root / f"{CAPTURES}/tenant.json").unlink()


case(
    "removing-a-vaultauth-bound-role-fails",
    1,
    drop_capture_role,
    "VaultAuth 'tenant' references k8s-auth role 'tenant'",
)


def drop_pki_role(root):
    (root / f"{MANAGED}/pkirole-vault-server.yaml").unlink()


case(
    "removing-the-issuer-pki-role-fails",
    1,
    drop_pki_role,
    "signs via PKI role 'vault-server'",
)


def drop_mount(root):
    (root / f"{MANAGED}/secretenginemount-pki-int-tcn.yaml").unlink()


case(
    "removing-the-mount-fails-twice",
    1,
    drop_mount,
    "signs on mount 'pki-int-tcn'",
    "strands them",
)


def drop_issuer(root):
    (root / "clusters/talos-cluster/apps/vault-tls-cm/clusterissuer.yaml").unlink()


case(
    "removing-the-clusterissuer-fails",
    1,
    drop_issuer,
    "references ClusterIssuer 'vault-server'",
)


def drop_pinned_role(root):
    (root / f"{MANAGED}/role-source-minter-hwg.yaml").unlink()


case(
    "removing-a-pinned-consumer-role-fails",
    1,
    drop_pinned_role,
    "pinned consumer references k8s-auth role 'source-minter-hwg'",
)


def drop_unreferenced_role(root):
    # vault-snapshot-backup policy stays; remove nothing else. Add an extra
    # UNREFERENCED policy, then remove it again — a no-op — plus remove a
    # genuinely unreferenced managed role? All fixture roles are referenced
    # (pinned consumers). Instead: an EXTRA policy no consumer references may
    # be freely absent — the healthy tree passing without it (it never
    # existed) is the property; assert an added-then-referenced-nowhere
    # policy also passes.
    write(root, f"{MANAGED}/policy-unused.yaml", """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: Policy
        metadata: {name: unused-extra}
        spec: {type: acl, policy: "path \\"q\\" {}"}
    """)


case("unreferenced-provider-is-prunable", 0, drop_unreferenced_role, "PASS")


def list_envelope_reference(root):
    # A VaultAuth hidden in a kind:List envelope must still be scanned
    # (kustomize expands Lists — the #312 lesson). It references a missing
    # role, so the guard must FAIL; a top-level-only scanner would pass.
    write(root, "clusters/talos-cluster/apps/vso/vaultauth-list.yaml", """
        apiVersion: v1
        kind: List
        items:
          - apiVersion: secrets.hashicorp.com/v1beta1
            kind: VaultAuth
            metadata: {name: enveloped}
            spec:
              kubernetes: {role: ghost-role}
    """)


case(
    "list-envelope-is-descended",
    1,
    list_envelope_reference,
    "VaultAuth 'enveloped' references k8s-auth role 'ghost-role'",
)


def case_folded_policy(root):
    # Vault lowercases policy names: a role referencing TENANT-READ must
    # resolve against the tenant-read Policy CR (case-folded compare).
    write(root, f"{MANAGED}/role-case.yaml", """
        apiVersion: redhatcop.redhat.io/v1alpha1
        kind: KubernetesAuthEngineRole
        metadata: {name: case-role}
        spec:
          policies: [TENANT-READ]
    """)


case("policy-compare-is-case-folded", 0, case_folded_policy, "PASS")


def comma_string_token_policies(root):
    write(root, f"{CAPTURES}/vso-org-pull-hwg.json",
          '{"token_policies": "tenant-read,vault-snapshot-backup"}\n')


case("comma-string-token-policies-split", 0, comma_string_token_policies, "PASS")


def comma_string_dangling(root):
    write(root, f"{CAPTURES}/vso-org-pull-nwp.json",
          '{"token_policies": "tenant-read,ghost-policy"}\n')


case(
    "comma-string-dangling-policy-fails",
    1,
    comma_string_dangling,
    "references policy 'ghost-policy'",
)


def malformed_sign_path(root):
    write(root, "clusters/talos-cluster/apps/vault-tls-cm/clusterissuer.yaml", """
        apiVersion: cert-manager.io/v1
        kind: ClusterIssuer
        metadata: {name: vault-server}
        spec:
          vault: {path: pki-int-tcn/issue/vault-server}
    """)


case(
    "non-sign-issuer-path-fails-closed",
    1,
    malformed_sign_path,
    "not <mount>/sign/<role>",
)


def pinned_consumer_missing(root):
    (root / PIN_CRON).unlink()


case(
    "pinned-consumer-file-missing-is-tooling-error",
    2,
    pinned_consumer_missing,
    "pinned consumer file missing",
)


def pinned_consumer_moved_reference(root):
    write(root, PIN_CRON, "env:\n  - name: VAULT_ROLE\n    value: renamed-role\n")


case(
    "pinned-consumer-drifted-is-tooling-error",
    2,
    pinned_consumer_moved_reference,
    "no longer contains",
)


def missing_managed_dir(root):
    import shutil

    shutil.rmtree(root / MANAGED)


case(
    "missing-managed-dir-is-tooling-error",
    2,
    missing_managed_dir,
    "managed dir not found",
)


def main() -> int:
    failures = 0
    for name, expected_rc, mutate, fragments in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_fixture(root)
            mutate(root)
            rc, output = run_guard(root)
            ok = rc == expected_rc and all(f in output for f in fragments)
            print(f"{'PASS' if ok else 'FAIL'}  {name} (rc={rc}, want {expected_rc})")
            if not ok:
                failures += 1
                missing = [f for f in fragments if f not in output]
                if missing:
                    print(f"      missing fragments: {missing}")
                print(textwrap.indent(output.strip()[:1200], "      | "))
    print()
    if failures:
        print(f"SELFTEST FAIL ({failures} case(s))")
        return 1
    print("SELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
