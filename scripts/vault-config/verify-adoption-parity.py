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
- PKISecretEngineRole CR (CP-4 S5): every field of the operator's write
  projection (``PKIRole.toMap()``, v0.8.49 — 38 keys, durations converted to
  seconds) equals the live ``<path>/roles/<name>`` value, AND every live field
  OUTSIDE the projection equals the Vault 2.0 write-default (the operator's
  role write is a full replace: a live field not in the payload gets
  re-defaulted, so live != default would be a silent semantic rewrite).
  The CR must set every projected field EXPLICITLY — this script reads the
  git YAML, not the server-defaulted object, so an omitted field (whose value
  the API server would fill from a CRD default) is a tooling error (exit 2).
- SecretEngineMount CR (CP-4 S5): the live resolved tune config
  (``sys/mounts/<path>/tune``) equals the CR's config projection
  (``MountConfig.toMap()``), the live mount type matches spec.type, and
  listing_visibility honours the documented unset ≡ "hidden" equivalence.

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


CHECKED_KINDS = {
    "Policy",
    "KubernetesAuthEngineRole",
    "PKISecretEngineRole",
    "SecretEngineMount",
}


def iter_managed_docs(managed_dir: Path):
    if not managed_dir.is_dir():
        raise fail_usage(f"{managed_dir} does not exist (run from the repo root)")
    for path in sorted(managed_dir.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if not isinstance(doc, dict) or doc.get("apiVersion") != API_VERSION:
                continue
            kind = doc.get("kind")
            if kind in CHECKED_KINDS:
                yield path, doc
            else:
                # Fail-closed: a redhatcop kind this script has no checker for
                # must not silently skip parity (it would read as "verified").
                raise fail_usage(
                    f"{path}: unsupported managed kind {kind!r} — extend "
                    "verify-adoption-parity.py before adopting this kind"
                )


def effective_name(doc: dict) -> str:
    spec = doc.get("spec") or {}
    return spec.get("name") or doc["metadata"]["name"]


def check_policy(name: str, spec: dict) -> list[str]:
    live = vault_get(f"sys/policies/acl/{name}")
    if live is None:
        return [f"policy {name!r}: MISSING live (sys/policies/acl/{name} = 404)"]
    live_policy = live.get("policy") or ""
    git_policy = spec["policy"]
    if live_policy == git_policy:
        return []
    diff = "\n".join(
        difflib.unified_diff(
            live_policy.splitlines(),
            git_policy.splitlines(),
            fromfile=f"live/{name}",
            tofile=f"git/{name}",
            lineterm="",
        )
    )
    # A byte-only difference (CRLF, trailing newlines) renders as an EMPTY
    # line diff — exactly the class this tool exists to surface, so show the
    # bytes explicitly instead of a blank hunk.
    if not diff:
        diff = (
            "whitespace-only byte difference: "
            f"live={len(live_policy)}B tail={live_policy[-8:]!r} vs "
            f"git={len(git_policy)}B tail={git_policy[-8:]!r}"
        )
    return [f"policy {name!r}: CONTENT MISMATCH\n{diff}"]


# Live role keys that may exist outside the operator's write projection
# without signalling drift, but ONLY while they hold these benign/empty
# values. Anything else live-set outside the projection would be silently
# WIPED by the operator's full-document role write and must be flagged.
BENIGN_EXTRA_ROLE_VALUES = (None, "", [], {}, 0, False)
KNOWN_EXTRA_ROLE_KEYS = {"alias_metadata", "bound_service_account_namespace_selector"}


def check_role(name: str, spec: dict) -> list[str]:
    live = vault_get(f"auth/kubernetes/role/{name}")
    if live is None:
        return [f"role {name!r}: MISSING live (auth/kubernetes/role/{name} = 404)"]
    findings = []
    projection = role_projection(spec)
    for key, want in projection.items():
        got = live.get(key)
        if got != want:
            findings.append(
                f"role {name!r}: field {key!r} live={got!r} git={want!r}"
            )
    # Reverse direction: a live-set field the projection does not carry would
    # be RESET by the operator's full-document upsert — that is a semantic
    # rewrite the adoption must not perform silently (audit finding R3).
    for key, got in sorted(live.items()):
        if key in projection:
            continue
        if got in BENIGN_EXTRA_ROLE_VALUES:
            continue
        if key in KNOWN_EXTRA_ROLE_KEYS:
            findings.append(
                f"role {name!r}: live field {key!r}={got!r} is set but the CR "
                "cannot express it — adoption would rewrite it (S4b class)"
            )
        else:
            findings.append(
                f"role {name!r}: live-only field {key!r}={got!r} is outside "
                "the operator write projection and would be RESET on reconcile"
            )
    return findings


_DURATION_UNITS = {"h": 3600, "m": 60, "s": 1}


def parse_go_duration(value: object, where: str) -> int:
    """Convert a CR duration (metav1.Duration string like '2160h'/'30s', or a
    bare integer meaning seconds) into whole seconds, mirroring how Vault
    stores what the operator writes."""
    if isinstance(value, bool):
        raise fail_usage(f"{where}: boolean is not a duration")
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value:
        raise fail_usage(f"{where}: expected a duration string, got {value!r}")
    text = value.strip()
    if text.isdigit():
        return int(text)
    total = 0
    number = ""
    for char in text:
        if char.isdigit():
            number += char
        elif char in _DURATION_UNITS and number:
            total += int(number) * _DURATION_UNITS[char]
            number = ""
        else:
            raise fail_usage(f"{where}: unsupported duration {value!r}")
    if number:
        raise fail_usage(f"{where}: trailing number without unit in {value!r}")
    return total


# The operator's PKIRole.toMap() payload (v0.8.49, source-verified): live Vault
# role key -> (CR spec key, converter). EVERY key here is written on every
# reconcile (full-replace role write), so EVERY key must be explicit in the CR
# and equal live.
PKI_ROLE_FIELDS = {
    "ttl": ("TTL", "duration"),
    "max_ttl": ("maxTTL", "duration"),
    "not_before_duration": ("notBeforeDuration", "duration"),
    "allow_localhost": ("allowLocalhost", None),
    "allowed_domains": ("allowedDomains", None),
    "allowed_domains_template": ("allowedDomainsTemplate", None),
    "allow_bare_domains": ("allowBareDomains", None),
    "allow_subdomains": ("allowSubdomains", None),
    "allow_glob_domains": ("allowGlobDomains", None),
    "allow_any_name": ("allowAnyName", None),
    "enforce_hostnames": ("enforceHostnames", None),
    "allow_ip_sans": ("allowIPSans", None),
    "allowed_uri_sans": ("allowedURISans", None),
    "allowed_other_sans": ("allowedOtherSans", None),
    "server_flag": ("serverFlag", None),
    "client_flag": ("clientFlag", None),
    "code_signing_flag": ("codeSigningFlag", None),
    "email_protection_flag": ("emailProtectionFlag", None),
    "key_type": ("keyType", None),
    "key_bits": ("keyBits", None),
    "key_usage": ("keyUsage", None),
    "ext_key_usage": ("extKeyUsage", None),
    "ext_key_usage_oids": ("extKeyUsageOids", None),
    "use_csr_common_name": ("useCSRCommonName", None),
    "use_csr_sans": ("useCSRSans", None),
    "ou": ("ou", None),
    "organization": ("organization", None),
    "country": ("country", None),
    "locality": ("locality", None),
    "province": ("province", None),
    "street_address": ("streetAddress", None),
    "postal_code": ("postalCode", None),
    "serial_number": ("serialNumber", None),
    "generate_lease": ("generateLease", None),
    "no_store": ("noStore", None),
    "require_cn": ("requireCn", None),
    "policy_identifiers": ("policyIdentifiers", None),
    "basic_constraints_valid_for_non_ca": ("basicConstraintsValidForNonCa", None),
}

# Vault 2.0 pki role WRITE defaults for fields the operator payload cannot
# express. The operator's role write is a full replace: these fields are
# re-defaulted on every reconcile, so adoption is only parity-safe while the
# live value already equals the default. Live != default => the reconcile
# would silently rewrite it => finding (the S4b class).
EXPECTED_PKI_ROLE_DEFAULTS = {
    "issuer_ref": "default",
    "allow_wildcard_certificates": True,
    "cn_validations": ["email", "hostname"],
    "allow_token_displayname": False,
    "allowed_serial_numbers": [],
    "allowed_user_ids": [],
    "allowed_uri_sans_template": False,
    "signature_bits": 0,
    "use_pss": False,
    "not_after": "",
    "serial_number_source": "json-csr",
}


def pki_role_projection(name: str, spec: dict) -> dict:
    projection = {}
    for live_key, (spec_key, conv) in PKI_ROLE_FIELDS.items():
        if spec_key not in spec:
            raise fail_usage(
                f"pki role {name!r}: spec.{spec_key} must be EXPLICIT (this "
                "script reads git YAML, not the server-defaulted object; an "
                "omitted field hides what the operator will write)"
            )
        value = spec[spec_key]
        if conv == "duration":
            value = parse_go_duration(value, f"pki role {name!r} spec.{spec_key}")
        projection[live_key] = value
    return projection


def check_pki_role(name: str, spec: dict) -> list[str]:
    engine_path = spec.get("path")
    if not isinstance(engine_path, str) or not engine_path:
        raise fail_usage(f"pki role {name!r}: spec.path is required")
    live = vault_get(f"{engine_path}/roles/{name}")
    if live is None:
        return [f"pki role {name!r}: MISSING live ({engine_path}/roles/{name} = 404)"]
    findings = []
    projection = pki_role_projection(name, spec)
    for key, want in projection.items():
        got = live.get(key)
        if got != want:
            findings.append(
                f"pki role {name!r}: field {key!r} live={got!r} git={want!r}"
            )
    for key, got in sorted(live.items()):
        if key in projection:
            continue
        if key in EXPECTED_PKI_ROLE_DEFAULTS:
            want = EXPECTED_PKI_ROLE_DEFAULTS[key]
            if got != want:
                findings.append(
                    f"pki role {name!r}: live field {key!r}={got!r} differs "
                    f"from the Vault write-default {want!r} — the operator's "
                    "full-replace write would silently re-default it"
                )
            continue
        if got in BENIGN_EXTRA_ROLE_VALUES:
            continue
        findings.append(
            f"pki role {name!r}: live-only field {key!r}={got!r} is outside "
            "the operator write projection and its write-default is unknown "
            "to this script — extend EXPECTED_PKI_ROLE_DEFAULTS after "
            "source-verifying the default"
        )
    return findings


def check_mount(name: str, spec: dict) -> list[str]:
    findings = []
    mounts = vault_get("sys/mounts") or {}
    entry = mounts.get(f"{name}/")
    if not isinstance(entry, dict):
        return [f"mount {name!r}: MISSING live (no sys/mounts entry)"]
    want_type = spec.get("type")
    if entry.get("type") != want_type:
        findings.append(
            f"mount {name!r}: type live={entry.get('type')!r} git={want_type!r}"
        )
    tune = vault_get(f"sys/mounts/{name}/tune")
    if tune is None:
        return findings + [f"mount {name!r}: sys/mounts/{name}/tune unreadable"]
    config = spec.get("config") or {}
    for spec_key, live_key in (
        ("defaultLeaseTTL", "default_lease_ttl"),
        ("maxLeaseTTL", "max_lease_ttl"),
    ):
        if spec_key not in config:
            raise fail_usage(
                f"mount {name!r}: spec.config.{spec_key} must be EXPLICIT — "
                "the operator's tune write always sends it, and an omitted "
                "value would re-tune the mount to the system default"
            )
        want = parse_go_duration(
            config[spec_key], f"mount {name!r} spec.config.{spec_key}"
        )
        got = tune.get(live_key)
        if got != want:
            findings.append(
                f"mount {name!r}: tune field {live_key!r} live={got!r} "
                f"git={want!r} (resolved seconds)"
            )
    want_fnc = bool(config.get("forceNoCache", False))
    if bool(tune.get("force_no_cache")) != want_fnc:
        findings.append(
            f"mount {name!r}: force_no_cache live={tune.get('force_no_cache')!r} "
            f"git={want_fnc!r}"
        )
    live_description = tune.get("description") or ""
    want_description = spec.get("description") or ""
    if live_description != want_description:
        findings.append(
            f"mount {name!r}: description live={live_description!r} "
            f"git={want_description!r} (tune does not write description — "
            "align the CR to live)"
        )
    # listing_visibility: the operator always tunes the CRD default "hidden";
    # Vault treats unset as hidden, so unset/""/"hidden" are all parity with a
    # CR saying "hidden". Anything else (e.g. "unauth") would be rewritten.
    want_lv = config.get("listingVisibility", "hidden")
    live_lv = (entry.get("config") or {}).get("listing_visibility") or "hidden"
    if live_lv != want_lv:
        findings.append(
            f"mount {name!r}: listing_visibility live={live_lv!r} git={want_lv!r}"
        )
    # The tune payload also always writes the three header/audit list params
    # the CRD leaves unset (nil -> empty). A live NON-EMPTY value would be
    # wiped by the first reconcile.
    for live_key in (
        "audit_non_hmac_request_keys",
        "audit_non_hmac_response_keys",
        "passthrough_request_headers",
        "allowed_response_headers",
    ):
        got = tune.get(live_key)
        if got and got not in BENIGN_EXTRA_ROLE_VALUES:
            findings.append(
                f"mount {name!r}: live tune field {live_key!r}={got!r} is set "
                "but the CR cannot express it — the operator's tune write "
                "would wipe it"
            )
    return findings


CHECKERS = {
    "Policy": check_policy,
    "KubernetesAuthEngineRole": check_role,
    "PKISecretEngineRole": check_pki_role,
    "SecretEngineMount": check_mount,
}


def main() -> int:
    findings: list[str] = []
    checked = 0
    for path, doc in iter_managed_docs(MANAGED_DIR):
        name = effective_name(doc)
        spec = doc["spec"]
        findings.extend(CHECKERS[doc["kind"]](name, spec))
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
    # rc 1 is reserved for a real parity mismatch; every tooling failure —
    # unreachable/TLS-broken Vault, non-404 HTTP errors, malformed YAML,
    # missing CR keys — must exit 2 so callers can't mistake a broken check
    # for a clean-or-dirty verdict.
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        OSError,
        ssl.SSLError,
        yaml.YAMLError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"ERROR: tooling failure: {exc!r}", file=sys.stderr)
        sys.exit(2)
