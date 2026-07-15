#!/usr/bin/env python3
"""Verify live Vault matches the managed vault-config CRs (CP-4 S4 adoption).

Run BEFORE merging an adoption change (proves the translation: live == CR, so
the operator's first reconcile cannot semantically rewrite anything) and AFTER
the first reconcile (proves the adoption converged; role reconciles are
idempotent RE-WRITES — the operator's equivalence check never matches for
roles — so parity is proven by read-back, not by an absent write).

Checks, per managed CR under clusters/talos-cluster/apps/vault/vault-config/managed/:
- Policy CR: live ``sys/policies/acl/<name>`` policy is BYTE-EXACT equal to
  ``spec.policy``.
- KubernetesAuthEngineRole CR: every field of the operator's write projection
  (``VRole.toMap()``: bound SA names/namespaces, alias_name_source, token_*)
  equals the live ``auth/kubernetes/role/<name>`` value.

Read-only: needs VAULT_ADDR + VAULT_TOKEN (a read-capable token) and
VAULT_CACERT. Never prints token material; prints unified diffs of POLICY
content only (public repo content). Exit 0 = full parity; 1 = mismatch;
2 = tooling/usage error.
"""

from __future__ import annotations

import difflib
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2)

MANAGED_DIR = Path("clusters/talos-cluster/apps/vault/vault-config/managed")
API_VERSION = "redhatcop.redhat.io/v1alpha1"


def fail_usage(message: str) -> "SystemExit":
    print(f"ERROR: {message}", file=sys.stderr)
    return SystemExit(2)


def vault_get(path: str) -> dict | None:
    addr = os.environ.get("VAULT_ADDR", "").rstrip("/")
    token = os.environ.get("VAULT_TOKEN", "")
    cacert = os.environ.get("VAULT_CACERT", "")
    if not addr or not token:
        raise fail_usage("VAULT_ADDR and VAULT_TOKEN must be set (read-only token is enough)")
    ctx = ssl.create_default_context(cafile=cacert or None)
    request = urllib.request.Request(
        f"{addr}/v1/{path.lstrip('/')}", headers={"X-Vault-Token": token}
    )
    try:
        with urllib.request.urlopen(request, context=ctx) as response:
            return json.loads(response.read().decode("utf-8")).get("data")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def role_projection(spec: dict) -> dict:
    """Mirror the operator's VRole.toMap() write payload (v0.8.49)."""
    target_ns = (spec.get("targetNamespaces") or {}).get("targetNamespaces")
    if not target_ns:
        raise fail_usage(
            "selector-based roles are not in the managed set (S4b pending); "
            "expected a static targetNamespaces list"
        )
    projection = {
        "bound_service_account_names": spec["targetServiceAccounts"],
        "bound_service_account_namespaces": target_ns,
        "alias_name_source": spec.get("aliasNameSource", "serviceaccount_uid"),
        "token_ttl": spec.get("tokenTTL", 0),
        "token_max_ttl": spec.get("tokenMaxTTL", 0),
        "token_policies": spec["policies"],
        "token_bound_cidrs": spec.get("tokenBoundCIDRs") or [],
        "token_explicit_max_ttl": spec.get("tokenExplicitMaxTTL", 0),
        "token_no_default_policy": spec.get("tokenNoDefaultPolicy", False),
        "token_num_uses": spec.get("tokenNumUses", 0),
        "token_period": spec.get("tokenPeriod", 0),
        "token_type": spec.get("tokenType", "default"),
    }
    if spec.get("audience"):
        projection["audience"] = spec["audience"]
    return projection


def iter_managed_docs(managed_dir: Path):
    if not managed_dir.is_dir():
        raise fail_usage(f"{managed_dir} does not exist (run from the repo root)")
    for path in sorted(managed_dir.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if not isinstance(doc, dict) or doc.get("apiVersion") != API_VERSION:
                continue
            if doc.get("kind") in {"Policy", "KubernetesAuthEngineRole"}:
                yield path, doc


def effective_name(doc: dict) -> str:
    spec = doc.get("spec") or {}
    return spec.get("name") or doc["metadata"]["name"]


def check_policy(name: str, spec: dict) -> list[str]:
    live = vault_get(f"sys/policies/acl/{name}")
    if live is None:
        return [f"policy {name!r}: MISSING live (sys/policies/acl/{name} = 404)"]
    if live.get("policy") == spec["policy"]:
        return []
    diff = "\n".join(
        difflib.unified_diff(
            (live.get("policy") or "").splitlines(),
            spec["policy"].splitlines(),
            fromfile=f"live/{name}",
            tofile=f"git/{name}",
            lineterm="",
        )
    )
    return [f"policy {name!r}: CONTENT MISMATCH\n{diff}"]


def check_role(name: str, spec: dict) -> list[str]:
    live = vault_get(f"auth/kubernetes/role/{name}")
    if live is None:
        return [f"role {name!r}: MISSING live (auth/kubernetes/role/{name} = 404)"]
    findings = []
    for key, want in role_projection(spec).items():
        got = live.get(key)
        if got != want:
            findings.append(
                f"role {name!r}: field {key!r} live={got!r} git={want!r}"
            )
    return findings


def main() -> int:
    findings: list[str] = []
    checked = 0
    for path, doc in iter_managed_docs(MANAGED_DIR):
        name = effective_name(doc)
        spec = doc["spec"]
        if doc["kind"] == "Policy":
            findings.extend(check_policy(name, spec))
        else:
            findings.extend(check_role(name, spec))
        checked += 1
    if checked == 0:
        raise fail_usage(f"no managed CRs found under {MANAGED_DIR}")
    if findings:
        print("FAIL: live Vault does not match the managed CRs:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(f"PASS: {checked} managed CR(s) verified — live Vault matches git byte/field-exact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
