#!/usr/bin/env python3
"""Enforce the vault-config-operator bootstrap paradox invariants (ADR-0028).

The operator's OWN Vault identity (`sys/policies/acl/vault-config-operator` +
`auth/kubernetes/role/vault-config-operator`) is the single owned, out-of-band
exception: it must never be self-managed (a redhatcop Policy /
KubernetesAuthEngineRole CR the operator reconciles) and never GitOps-applied.
If the operator could rewrite its own policy it would self-escalate; if it could
prune its own role it would self-lock-out.

This guard is fail-closed and asserts:

1. The bootstrap policy HCL exists at the expected path and is NOT inside the S0
   managed-policy scan scope (`apps/vault/vault-config/policies/`).
2. The bootstrap policy grants no `sudo` capability and no root `path "*"` /
   `path "/"` stanza (design: path-scoped, no sudo) — parsed with the S0 guard's
   HCL tokenizer.
3. The operator's own identity is never a MANAGED object: no
   redhatcop.redhat.io/v1alpha1 `Policy` or `KubernetesAuthEngineRole` CR named
   `vault-config-operator`, and no managed policy HCL named
   `vault-config-operator.hcl` under the managed policy dir.
4. Nothing under the bootstrap dir is referenced by any kustomization.yaml
   `resources`/`components`/`bases` list (so Flux/kustomize can never apply it).
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover - CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc

ROOT = Path(__file__).resolve().parents[1]
OPERATOR_IDENTITY_NAME = "vault-config-operator"
# Identities that must NEVER be operator-managed (no redhatcop Policy /
# KubernetesAuthEngineRole CR may carry these names) and that the bootstrap
# policy must never cover: the operator's own identity (self-escalation /
# self-lockout, ADR-0028) and the break-glass admin policy (a git compromise
# must not be able to rewrite the recovery identity; owner decision
# 2026-07-15, captured out-of-band in bootstrap/vault-admin.policy.hcl).
# All name/path comparisons in this guard are CASE-FOLDED: Vault lowercases
# ACL policy names on write, so a CR named VAULT-ADMIN lands on vault-admin
# live — a case-sensitive compare is a green bypass (#312 audit FAIL-2).
PROTECTED_IDENTITY_NAMES = (OPERATOR_IDENTITY_NAME, "vault-admin")


def _fold(name: str) -> str:
    return name.strip().lower()
# Compared against S0-normalized paths (leading slash stripped), so `path "/"`
# and `path ""` both normalize to "" and `path "/*"` to "*".
ROOT_PATHS = {"", "*", "sys/*", "auth/*", "identity/*"}
MANAGED_POLICY_PREFIX = "sys/policies/acl/"
MANAGED_ROLE_PREFIX = "auth/kubernetes/role/"
# Forward-looking managed objects that the operator will create later (S5) — not
# yet a file in the managed tree, but allowed in the bootstrap enumeration.
# Empty since CP-5b: vault-server became a managed-in-git Policy/Role CR pair,
# so nothing is forward-declared anymore. Names go here ONLY between the PR
# that grants them in the bootstrap policy and the PR that lands their CRs.
FORWARD_LOOKING_NAMES: set[str] = set()
# Throwaway S3 smoke objects: the only names allowed to carry `delete` before
# prune is armed (S7). Any managed-plane path containing this marker is smoke.
SMOKE_MARKER = "smoke"
YAML_SUFFIXES = {".yaml", ".yml"}
KUSTOMIZATION_NAMES = {"kustomization.yaml", "kustomization.yml"}
REFERENCE_KEYS = ("resources", "components", "bases")


@dataclass(frozen=True)
class BootstrapPaths:
    root: Path
    cluster_root: Path
    managed_policy_dir: Path
    bootstrap_dir: Path
    bootstrap_policy: Path
    bootstrap_role: Path


def paths_for_root(root: Path) -> BootstrapPaths:
    cluster_root = root / "clusters/talos-cluster"
    bootstrap_dir = cluster_root / "apps/vault/vault-config/bootstrap"
    return BootstrapPaths(
        root=root,
        cluster_root=cluster_root,
        managed_policy_dir=cluster_root / "apps/vault/vault-config/policies",
        bootstrap_dir=bootstrap_dir,
        bootstrap_policy=bootstrap_dir / "vault-config-operator.policy.hcl",
        bootstrap_role=bootstrap_dir / "vault-config-operator.role.json",
    )


def _load_s0_guard():
    guard_path = ROOT / "scripts/check-vault-policy-no-escalation.py"
    spec = importlib.util.spec_from_file_location("_s0_guard", guard_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {guard_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _display(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def check_bootstrap_present_and_out_of_scope(
    paths: BootstrapPaths, findings: list[str]
) -> None:
    if not paths.bootstrap_policy.is_file():
        findings.append(
            f"missing bootstrap policy: {_display(paths.bootstrap_policy, paths.root)}"
        )
    if not paths.bootstrap_role.is_file():
        findings.append(
            f"missing bootstrap role: {_display(paths.bootstrap_role, paths.root)}"
        )
    if paths.managed_policy_dir.resolve() in paths.bootstrap_dir.resolve().parents:
        findings.append(
            f"bootstrap dir {_display(paths.bootstrap_dir, paths.root)} is inside "
            f"the S0 managed scan scope {_display(paths.managed_policy_dir, paths.root)}"
        )


def _managed_names(paths: BootstrapPaths) -> tuple[set[str], set[str]]:
    policy_names = (
        {_fold(p.stem) for p in paths.managed_policy_dir.glob("*.hcl")}
        if paths.managed_policy_dir.is_dir()
        else set()
    )
    roles_dir = paths.cluster_root / "apps/vault/vault-config/auth/kubernetes/roles"
    role_names = (
        {_fold(p.stem) for p in roles_dir.glob("*.json")} if roles_dir.is_dir() else set()
    )
    # CP-4 S4a: managed objects live as redhatcop CRs (GitOps-reconciled). The
    # effective Vault object name is spec.name when set, else metadata.name
    # (mirrors the operator's GetPath()). The operator's own identity is
    # excluded here — check_identity_never_managed flags it as its own finding
    # rather than letting it satisfy the bootstrap enumeration.
    if paths.cluster_root.is_dir():
        for path in sorted(paths.cluster_root.rglob("*")):
            if not path.is_file() or path.suffix not in YAML_SUFFIXES:
                continue
            for doc in _iter_yaml_docs(path):
                if doc.get("apiVersion") != "redhatcop.redhat.io/v1alpha1":
                    continue
                kind = doc.get("kind")
                if kind not in {"Policy", "KubernetesAuthEngineRole"}:
                    continue
                spec = doc.get("spec") or {}
                metadata = doc.get("metadata") or {}
                name = spec.get("name") or metadata.get("name")
                if not isinstance(name, str) or not name:
                    continue
                name = _fold(name)
                if name in PROTECTED_IDENTITY_NAMES:
                    continue
                if kind == "Policy":
                    policy_names.add(name)
                else:
                    role_names.add(name)
    return policy_names, role_names


def check_bootstrap_policy_content(
    paths: BootstrapPaths, findings: list[str], s0
) -> None:
    """Content-level checks on the bootstrap policy (design §7 + the paradox).

    The bootstrap policy is deliberately outside the S0 managed-policy content
    guard, so THIS is the only guard on what it grants. It must:
      - be sudo-free and never grant a root/wildcard path (incl. `path "/"`);
      - never grant a path that COVERS its own identity (self-escalation);
      - on the management plane (sys/policies/acl, auth/kubernetes/role) use
        EXACT names only (no wildcard) and only names that are managed-in-git,
        forward-looking (vault-server), or throwaway *-smoke;
      - enumerate EVERY managed policy/role name (else the operator cannot adopt
        it — a runtime break);
      - grant `delete` ONLY on throwaway *-smoke paths (no live-object delete
        until prune is armed in S7).
    """
    if not paths.bootstrap_policy.is_file():
        return
    source = s0.PolicySource(
        label=_display(paths.bootstrap_policy, paths.root),
        content=paths.bootstrap_policy.read_text(encoding="utf-8"),
    )
    try:
        stanzas = s0.parse_hcl_source(source)
    except s0.GuardUsageError as exc:
        findings.append(f"bootstrap policy does not parse as Vault HCL: {exc}")
        return

    policy_names, role_names = _managed_names(paths)
    self_policy = f"{MANAGED_POLICY_PREFIX}{OPERATOR_IDENTITY_NAME}"
    self_role = f"{MANAGED_ROLE_PREFIX}{OPERATOR_IDENTITY_NAME}"
    seen_policy: set[str] = set()
    seen_role: set[str] = set()

    for stanza in stanzas:
        # Case-fold the granted path before every comparison (audit FAIL-2):
        # Vault lowercases ACL policy names, so `sys/policies/acl/VAULT-ADMIN`
        # writes to vault-admin live — the fold makes the guard see it.
        norm = _fold(s0.normalize_vault_path(stanza.path))
        folded_path = _fold(stanza.path)
        caps = {c.lower() for c in stanza.capabilities}
        where = f"path {stanza.path!r} line {stanza.line}"

        if "sudo" in caps:
            findings.append(
                f"bootstrap policy grants sudo ({where}); it must be sudo-free"
            )
        if norm in ROOT_PATHS:
            findings.append(
                f"bootstrap policy grants a root/wildcard path ({where}); it "
                "must be path-scoped"
            )
        # Self-escalation: any path that COVERS the operator's own identity.
        if s0.covers(folded_path, self_policy) or s0.covers(folded_path, self_role):
            findings.append(
                f"bootstrap policy grants a path that COVERS its own identity "
                f"({OPERATOR_IDENTITY_NAME}) — the operator could rewrite its own "
                f"policy/role and self-escalate ({where})"
            )
        # Break-glass protection: the operator must never be able to touch
        # the vault-admin recovery policy (or a role of that name).
        if s0.covers(folded_path, f"{MANAGED_POLICY_PREFIX}vault-admin") or s0.covers(
            folded_path, f"{MANAGED_ROLE_PREFIX}vault-admin"
        ):
            findings.append(
                f"bootstrap policy grants a path that COVERS the break-glass "
                f"vault-admin identity — a compromised operator could rewrite "
                f"the recovery policy ({where})"
            )
        # delete only on throwaway smoke objects.
        if "delete" in caps and SMOKE_MARKER not in norm:
            findings.append(
                f"bootstrap policy grants delete on a non-smoke path ({where}); "
                "delete on a live object is prohibited until prune is armed (S7)"
            )
        # Management-plane exactness + known-name.
        for prefix, allowed, seen in (
            (MANAGED_POLICY_PREFIX, policy_names, seen_policy),
            (MANAGED_ROLE_PREFIX, role_names, seen_role),
        ):
            if not norm.startswith(prefix):
                continue
            name = norm[len(prefix):]
            if not name or "*" in name or "+" in name:
                findings.append(
                    f"bootstrap policy uses a non-exact/wildcard management-plane "
                    f"path ({where}); exact enumeration is required so the grant "
                    "cannot silently cover an unmanaged object"
                )
                continue
            if name in PROTECTED_IDENTITY_NAMES:
                continue  # already flagged by the covering-path checks
            if SMOKE_MARKER in name:
                continue  # throwaway; permitted
            if name not in allowed and name not in FORWARD_LOOKING_NAMES:
                findings.append(
                    f"bootstrap policy grants {prefix}{name} which is not a "
                    f"managed object in git ({where}) — drift/over-grant"
                )
            seen.add(name)

    # Enumeration completeness: every managed name must be granted.
    for name in sorted(policy_names):
        if name not in seen_policy:
            findings.append(
                f"managed policy {name!r} has no bootstrap "
                f"{MANAGED_POLICY_PREFIX}{name} grant — the operator could not "
                "adopt it (S4 runtime break)"
            )
    for name in sorted(role_names):
        if name not in seen_role:
            findings.append(
                f"managed role {name!r} has no bootstrap "
                f"{MANAGED_ROLE_PREFIX}{name} grant — the operator could not "
                "adopt it (S4 runtime break)"
            )


def _iter_yaml_docs(path: Path):
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as exc:
        raise SystemExit(f"failed to parse {path}: {exc}")
    yield from _flatten_docs(docs)


def _flatten_docs(docs):
    # kubectl kustomize (Flux's builder) EXPANDS a k8s List envelope
    # (kind: List / kind: <Type>List with an items: array) into standalone
    # resources, so a CR wrapped in a List IS applied to the cluster. A guard
    # that only looks at top-level documents scans right past it (#312 audit
    # FAIL-1) — descend into items (recursively, Lists can nest).
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        items = doc.get("items")
        if isinstance(kind, str) and kind.endswith("List") and isinstance(items, list):
            yield from _flatten_docs(items)
            continue
        yield doc


def check_identity_never_managed(paths: BootstrapPaths, findings: list[str]) -> None:
    for protected in PROTECTED_IDENTITY_NAMES:
        managed_self = paths.managed_policy_dir / f"{protected}.hcl"
        if managed_self.exists():
            findings.append(
                f"protected identity {protected!r} is a MANAGED policy: "
                f"{_display(managed_self, paths.root)} (must live only in the "
                "out-of-band bootstrap dir)"
            )
    if not paths.cluster_root.is_dir():
        return
    # Assumption: the operator's CRDs are redhatcop.redhat.io/v1alpha1 and the
    # only kinds that write sys/policies/acl/* or auth/<mount>/role/* are Policy
    # and KubernetesAuthEngineRole. Revisit if the operator bumps its API version
    # or adds a new config-writing kind.
    for path in sorted(paths.cluster_root.rglob("*")):
        if not path.is_file() or path.suffix not in YAML_SUFFIXES:
            continue
        for doc in _iter_yaml_docs(path):
            if doc.get("apiVersion") != "redhatcop.redhat.io/v1alpha1":
                continue
            kind = doc.get("kind")
            if kind not in {"Policy", "KubernetesAuthEngineRole"}:
                continue
            name = (doc.get("metadata") or {}).get("name")
            spec = doc.get("spec") or {}
            candidates = {
                _fold(c) for c in (name, spec.get("name")) if isinstance(c, str)
            }
            for protected in PROTECTED_IDENTITY_NAMES:
                if protected in candidates:
                    findings.append(
                        f"protected identity {protected!r} is a MANAGED {kind} "
                        f"CR: {_display(path, paths.root)} — the operator must "
                        "never manage its own identity or the break-glass "
                        "vault-admin policy"
                    )


def _reference_targets_bootstrap(
    kustomization: Path, ref: object, paths: BootstrapPaths
) -> bool:
    if not isinstance(ref, str):
        return False
    target = (kustomization.parent / ref).resolve()
    bootstrap = paths.bootstrap_dir.resolve()
    return (
        target == bootstrap
        or bootstrap in target.parents
        or target in (paths.bootstrap_policy.resolve(), paths.bootstrap_role.resolve())
    )


def check_bootstrap_never_flux_applied(
    paths: BootstrapPaths, findings: list[str]
) -> None:
    for path in sorted(paths.root.rglob("*")):
        if not path.is_file() or path.name not in KUSTOMIZATION_NAMES:
            continue
        for doc in _iter_yaml_docs(path):
            for key in REFERENCE_KEYS:
                for ref in doc.get(key, []) or []:
                    if _reference_targets_bootstrap(path, ref, paths):
                        findings.append(
                            f"bootstrap dir is referenced by "
                            f"{_display(path, paths.root)} ({key}: {ref!r}) — it "
                            "must never be GitOps-applied"
                        )


def evaluate(root: Path, s0) -> list[str]:
    paths = paths_for_root(root)
    findings: list[str] = []
    check_bootstrap_present_and_out_of_scope(paths, findings)
    check_bootstrap_policy_content(paths, findings, s0)
    check_identity_never_managed(paths, findings)
    check_bootstrap_never_flux_applied(paths, findings)
    return findings


def main() -> int:
    s0 = _load_s0_guard()
    findings = evaluate(ROOT, s0)
    if findings:
        print(
            "ERROR: vault-config-operator bootstrap invariant guard failed:",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(
        "PASS: vault-config-operator bootstrap identity is out-of-band, "
        "sudo-free, never self-managed, and never GitOps-applied."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
