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
ROOT_PATHS = {"*", "/", "/*", "sys/*", "auth/*"}
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


def check_bootstrap_no_sudo(paths: BootstrapPaths, findings: list[str], s0) -> None:
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
    for stanza in stanzas:
        caps = {c.lower() for c in stanza.capabilities}
        if "sudo" in caps:
            findings.append(
                f"bootstrap policy grants sudo (path {stanza.path!r} line "
                f"{stanza.line}); the bootstrap identity must be sudo-free"
            )
        if s0.normalize_vault_path(stanza.path) in ROOT_PATHS:
            findings.append(
                f"bootstrap policy grants a root/wildcard path {stanza.path!r} "
                f"(line {stanza.line}); it must be path-scoped"
            )


def _iter_yaml_docs(path: Path):
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as exc:
        raise SystemExit(f"failed to parse {path}: {exc}")
    for doc in docs:
        if isinstance(doc, dict):
            yield doc


def check_identity_never_managed(paths: BootstrapPaths, findings: list[str]) -> None:
    managed_self = paths.managed_policy_dir / f"{OPERATOR_IDENTITY_NAME}.hcl"
    if managed_self.exists():
        findings.append(
            f"operator identity is a MANAGED policy: "
            f"{_display(managed_self, paths.root)} (must live only in the "
            "out-of-band bootstrap dir)"
        )
    if not paths.cluster_root.is_dir():
        return
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
            candidates = {name, spec.get("name")}
            if OPERATOR_IDENTITY_NAME in candidates:
                findings.append(
                    f"operator identity is a MANAGED {kind} CR: "
                    f"{_display(path, paths.root)} (name "
                    f"{OPERATOR_IDENTITY_NAME!r}) — the operator must never "
                    "manage its own identity"
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
    check_bootstrap_no_sudo(paths, findings, s0)
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
