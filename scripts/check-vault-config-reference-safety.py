#!/usr/bin/env python3
"""CP-4 S6b — reference-safety guard for the managed Vault-config set.

THE CONTROL THIS IMPLEMENTS (design decision #3, [[feedback_reliability_zero
compromises]]): before Flux prune is armed (S7), deleting a managed CR file
must not be able to cascade into a live break. The S0 escalation guard cannot
catch a deletion (removing a file is not "bad content"), so THIS guard proves
REFERENTIAL INTEGRITY of the whole tree on every CI run: every Vault-object
reference in git must resolve to an existing in-git provider. Removing a
still-referenced policy/role/mount/issuer therefore FAILS CI at the PR that
removes it — before prune (or a reconcile) can delete the live object under
a consumer.

Reference edges checked (consumers -> providers):
  1. managed KubernetesAuthEngineRole CR spec.policies[]       -> managed Policy CR names
  2. capture-only role JSONs token_policies (str|list)         -> managed Policy CR names
  3. VaultAuth spec.kubernetes.role                            -> managed KubernetesAuthEngineRole names
                                                                  or capture-only role names
  4. pinned external consumers (env/scripts, see PINNED_CONSUMERS)
                                                               -> role names (same provider set as 3)
  5. ClusterIssuer spec.vault.path "<mount>/sign/<role>"       -> managed SecretEngineMount name
                                                                  + managed PKISecretEngineRole name
  5b. ClusterIssuer spec.vault.auth.kubernetes.role            -> managed KubernetesAuthEngineRole
                                                                  or capture-only role names
      (the issuer's LOGIN identity — pruning it would 403 every issuance and
      the renewal halts silently until the renewBefore window; audit-S find)
  6. Certificate spec.issuerRef (kind ClusterIssuer)           -> ClusterIssuer names
  7. managed PKISecretEngineRole/SecretEngineMount consistency: every PKI role's
     implicit mount (pki-int-tcn today) must exist as a managed SecretEngineMount.

Design notes:
  - Tree-integrity formulation (no diff base needed): the guard runs on any
    checkout, exactly like the other CI guards. A deletion PR breaks an edge
    and fails; a deletion of a genuinely UNREFERENCED object passes (that is
    the intended prune workflow: retire consumers first, then the provider).
  - kind: List envelopes are descended (kustomize expands them — the #312
    audit lesson; a guard that reads only top-level docs scans past them).
  - ACL policy-name comparisons are case-folded (Vault lowercases policy
    names on write — also a #312 lesson). Role/mount/issuer names stay exact
    (Kubernetes object names are case-sensitive).
  - PINNED_CONSUMERS anchor the consumers whose references live in
    unstructured content (a CronJob env value, a shell script). If a pinned
    file disappears or no longer contains its expected reference, that is a
    LOUD tooling error (exit 2) — never a silent scope loss.
  - The operator's own bootstrap identity is deliberately OUT of scope here
    (never managed, never prunable — enforced by
    check-vault-config-operator-bootstrap-invariants.py).

Exit codes: 0 = all references resolve; 1 = a broken/dangling reference
(the prune-safety finding); 2 = tooling/usage error (fail closed).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    print(f"ERROR: PyYAML is required: {exc}", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parents[1]
MANAGED_DIR = Path("clusters/talos-cluster/apps/vault/vault-config/managed")
CAPTURE_ROLE_DIR = Path("clusters/talos-cluster/apps/vault/vault-config/auth/kubernetes/roles")
CLUSTERS_DIR = Path("clusters")

# The consumers whose Vault-role references live in unstructured content.
# (path, expected substring, role name it references)
PINNED_CONSUMERS: tuple[tuple[str, str, str], ...] = (
    (
        "clusters/talos-cluster/apps/source-rotator/cronjob-hwg.yaml",
        "source-minter-hwg",
        "source-minter-hwg",
    ),
    (
        "clusters/talos-cluster/apps/source-rotator/cronjob-nwp.yaml",
        "source-minter-nwp",
        "source-minter-nwp",
    ),
    (
        "clusters/talos-cluster/apps/vault/restore-drill/s0-restore-generate-root.sh",
        '"role": "vault-snapshot-backup"',
        "vault-snapshot-backup",
    ),
)


def fail_usage(message: str) -> SystemExit:
    print(f"ERROR: {message}", file=sys.stderr)
    return SystemExit(2)


def _flatten_docs(docs):
    """Descend kind:List envelopes recursively (#312 audit lesson)."""
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        items = doc.get("items")
        if isinstance(kind, str) and kind.endswith("List") and isinstance(items, list):
            yield from _flatten_docs(items)
            continue
        yield doc


def iter_yaml_docs(root: Path):
    """Yield (path, doc) for every YAML document under root (or a file)."""
    paths = [root] if root.is_file() else sorted(
        p
        for p in root.rglob("*")
        if p.suffix in {".yaml", ".yml"} and p.is_file()
    )
    for path in paths:
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (OSError, yaml.YAMLError) as exc:
            raise fail_usage(f"failed to parse {path}: {exc}")
        for doc in _flatten_docs(docs):
            yield path, doc


def effective_name(doc: dict) -> str:
    # spec.name overrides metadata.name ONLY for redhatcop CRs (the operator's
    # own convention); every other kind resolves by metadata.name (a stray
    # spec.name on e.g. a cert-manager kind must not mislead the guard).
    name = None
    if str(doc.get("apiVersion", "")).startswith("redhatcop.redhat.io/"):
        name = (doc.get("spec") or {}).get("name")
    name = name or (doc.get("metadata") or {}).get("name")
    if not isinstance(name, str) or not name:
        raise fail_usage(f"document of kind {doc.get('kind')!r} has no resolvable name")
    return name


def norm_policy(name: str) -> str:
    # Vault lowercases ACL policy names on write (#312 lesson).
    return name.strip().lower()


def load_providers(repo: Path):
    managed_policies: set[str] = set()
    managed_roles: set[str] = set()
    managed_mounts: set[str] = set()
    managed_pki_roles: set[str] = set()

    managed_root = repo / MANAGED_DIR
    if not managed_root.is_dir():
        raise fail_usage(f"managed dir not found: {managed_root}")
    for path, doc in iter_yaml_docs(managed_root):
        if not isinstance(doc, dict):
            continue
        api = str(doc.get("apiVersion", ""))
        if not api.startswith("redhatcop.redhat.io/"):
            continue
        kind = doc.get("kind")
        if kind == "Policy":
            managed_policies.add(norm_policy(effective_name(doc)))
        elif kind == "KubernetesAuthEngineRole":
            managed_roles.add(effective_name(doc))
        elif kind == "SecretEngineMount":
            managed_mounts.add(effective_name(doc))
        elif kind == "PKISecretEngineRole":
            managed_pki_roles.add(effective_name(doc))
        # unknown redhatcop kinds are the parity guard's problem, not ours

    capture_roles: set[str] = set()
    capture_dir = repo / CAPTURE_ROLE_DIR
    if capture_dir.is_dir():
        for path in sorted(capture_dir.glob("*.json")):
            capture_roles.add(path.stem)

    return managed_policies, managed_roles, managed_mounts, managed_pki_roles, capture_roles


def token_policies_of(raw) -> list[str]:
    """Normalize Vault token_policies: comma-string or list."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return [p for p in (s.strip() for s in raw.split(",")) if p]
    if isinstance(raw, list):
        out: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                raise fail_usage(f"non-string token_policies entry: {item!r}")
            out.extend(p for p in (s.strip() for s in item.split(",")) if p)
        return out
    raise fail_usage(f"unsupported token_policies shape: {type(raw).__name__}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify every Vault-object reference in the tree resolves to an "
            "in-git provider (the S6b prune-safety property)."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repo root to scan (selftest fixtures only; default: the real repo)",
    )
    return parser.parse_args()


def main() -> int:
    repo = parse_args().root.resolve()
    if not repo.is_dir():
        raise fail_usage(f"--root does not exist: {repo}")
    findings: list[str] = []
    edges = 0

    (
        managed_policies,
        managed_roles,
        managed_mounts,
        managed_pki_roles,
        capture_roles,
    ) = load_providers(repo)
    role_providers = managed_roles | capture_roles

    # Edge 1: managed role CRs -> policies
    for path, doc in iter_yaml_docs(repo / MANAGED_DIR):
        if not isinstance(doc, dict) or doc.get("kind") != "KubernetesAuthEngineRole":
            continue
        name = effective_name(doc)
        for pol in (doc.get("spec") or {}).get("policies") or []:
            edges += 1
            if norm_policy(pol) not in managed_policies:
                findings.append(
                    f"{path.relative_to(repo)}: managed role {name!r} references "
                    f"policy {pol!r} which is not a managed Policy CR — removing "
                    "the policy while the role binds it would break every login "
                    "on that role"
                )

    # Edge 2: capture-only role JSONs -> policies
    capture_dir = repo / CAPTURE_ROLE_DIR
    if capture_dir.is_dir():
        for path in sorted(capture_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise fail_usage(f"failed to parse {path}: {exc}")
            for pol in token_policies_of(data.get("token_policies")):
                edges += 1
                if norm_policy(pol) not in managed_policies:
                    findings.append(
                        f"{path.relative_to(repo)}: capture-only role "
                        f"{path.stem!r} references policy {pol!r} which is not a "
                        "managed Policy CR — the live selector role still binds "
                        "it (TD-0008), so removing the policy breaks tenant/VSO "
                        "logins"
                    )

    # Edges 3, 5, 6, 7: structured cluster-wide consumers
    cluster_issuers: set[str] = set()
    issuer_refs: list[tuple[Path, str, str]] = []  # (path, cert name, issuer name)
    for path, doc in iter_yaml_docs(repo / CLUSTERS_DIR):
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        api = str(doc.get("apiVersion", ""))
        spec = doc.get("spec") or {}

        if kind == "VaultAuth" and api.startswith("secrets.hashicorp.com/"):
            kub = spec.get("kubernetes") or {}
            role = kub.get("role")
            if isinstance(role, str) and role:
                edges += 1
                if role not in role_providers:
                    findings.append(
                        f"{path.relative_to(repo)}: VaultAuth "
                        f"{effective_name(doc)!r} references k8s-auth role "
                        f"{role!r} which exists neither as a managed role CR nor "
                        "as a capture-only role — VSO logins on it would 403"
                    )

        elif kind == "ClusterIssuer" and api.startswith("cert-manager.io/"):
            cluster_issuers.add(effective_name(doc))
            vault_spec = spec.get("vault") or {}
            # Edge 5b: the issuer's OWN login identity (audit-S find — missing
            # this edge let a role-CR deletion pass while cert-manager still
            # logged in with it; renewal would halt silently for weeks).
            auth_role = ((vault_spec.get("auth") or {}).get("kubernetes") or {}).get(
                "role"
            )
            if isinstance(auth_role, str) and auth_role:
                edges += 1
                if auth_role not in role_providers:
                    findings.append(
                        f"{path.relative_to(repo)}: ClusterIssuer "
                        f"{effective_name(doc)!r} logs in with k8s-auth role "
                        f"{auth_role!r} which exists neither as a managed role "
                        "CR nor as a capture-only role — every issuance/renewal "
                        "would 403"
                    )
            sign_path = vault_spec.get("path")
            if isinstance(sign_path, str) and sign_path:
                edges += 1
                match = re.fullmatch(r"([^/]+)/sign/([^/]+)", sign_path)
                if not match:
                    findings.append(
                        f"{path.relative_to(repo)}: ClusterIssuer "
                        f"{effective_name(doc)!r} has a sign path {sign_path!r} "
                        "that is not <mount>/sign/<role> — cannot prove its "
                        "providers exist"
                    )
                else:
                    mount, pki_role = match.groups()
                    if mount not in managed_mounts:
                        findings.append(
                            f"{path.relative_to(repo)}: ClusterIssuer "
                            f"{effective_name(doc)!r} signs on mount {mount!r} "
                            "which is not a managed SecretEngineMount — removing "
                            "the mount CR kills every issuance/renewal"
                        )
                    if pki_role not in managed_pki_roles:
                        findings.append(
                            f"{path.relative_to(repo)}: ClusterIssuer "
                            f"{effective_name(doc)!r} signs via PKI role "
                            f"{pki_role!r} which is not a managed "
                            "PKISecretEngineRole — removing the role CR kills "
                            "every issuance/renewal"
                        )

        elif kind == "Certificate" and api.startswith("cert-manager.io/"):
            ref = spec.get("issuerRef") or {}
            if ref.get("kind", "Issuer") == "ClusterIssuer":
                issuer_refs.append(
                    (path, effective_name(doc), str(ref.get("name", "")))
                )

    # Edge 6 resolution (after the full walk so ordering cannot matter)
    for path, cert_name, issuer_name in issuer_refs:
        edges += 1
        if issuer_name not in cluster_issuers:
            findings.append(
                f"{path.relative_to(repo)}: Certificate {cert_name!r} references "
                f"ClusterIssuer {issuer_name!r} which does not exist in the tree "
                "— renewal would halt at the next renewBefore window"
            )

    # Edge 4: pinned unstructured consumers (loud tooling error if moved)
    for rel, expected, role in PINNED_CONSUMERS:
        path = repo / rel
        if not path.is_file():
            raise fail_usage(
                f"pinned consumer file missing: {rel} — if the consumer moved, "
                "update PINNED_CONSUMERS (silent scope loss is not allowed)"
            )
        content = path.read_text(encoding="utf-8")
        if expected not in content:
            raise fail_usage(
                f"pinned consumer {rel} no longer contains {expected!r} — if the "
                "consumer changed its role reference, update PINNED_CONSUMERS"
            )
        edges += 1
        if role not in role_providers:
            findings.append(
                f"{rel}: pinned consumer references k8s-auth role {role!r} which "
                "exists neither as a managed role CR nor as a capture-only role"
            )

    # Edge 7: every managed PKI role's mount must be managed. The redhat-cop
    # PKISecretEngineRole addresses its mount via the CR's authentication/
    # path convention; in this repo every PKI role lives on pki-int-tcn. We
    # derive the constraint structurally: if ANY PKI role exists, the managed
    # mount set must be non-empty, and (today) must contain pki-int-tcn.
    if managed_pki_roles:
        edges += 1
        if "pki-int-tcn" not in managed_mounts:
            findings.append(
                f"{MANAGED_DIR}: {len(managed_pki_roles)} managed "
                "PKISecretEngineRole CR(s) exist but the pki-int-tcn "
                "SecretEngineMount CR is absent — removing the mount while "
                "roles target it strands them (and prune would try to unmount "
                "the CA)"
            )

    if findings:
        print(
            "FAIL: dangling Vault-config references (prune/removal would break "
            "a live consumer):",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1

    print(
        f"PASS: vault-config reference-safety guard verified {edges} reference "
        f"edge(s); every consumer resolves to an in-git provider "
        f"({len(managed_policies)} policies, {len(managed_roles)}+"
        f"{len(capture_roles)} roles, {len(managed_mounts)} mount(s), "
        f"{len(managed_pki_roles)} PKI role(s), {len(cluster_issuers)} "
        f"issuer(s))."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — tooling failures must exit 2
        print(f"ERROR: tooling failure: {exc!r}", file=sys.stderr)
        sys.exit(2)
