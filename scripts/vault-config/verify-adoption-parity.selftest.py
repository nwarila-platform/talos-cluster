#!/usr/bin/env python3
"""Offline regression self-test for verify-adoption-parity.py (CP-4 S5).

The parity script is the load-bearing proof tool for every Vault-config
adoption (a wrong projection = a false PASS = a silent semantic rewrite of
live Vault config), so its projections are pinned here with fixtures. No
network: ``vault_get`` is monkeypatched per case.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/vault-config/verify-adoption-parity.py"


def load_module():
    spec = importlib.util.spec_from_file_location("_parity", SCRIPT)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


parity = load_module()


# A PKISecretEngineRole spec with every projected field explicit — mirrors the
# live vault-server role shape (EC P-256 server role, 90d, CSR-driven).
def pki_spec() -> dict:
    return {
        "path": "pki-int-tcn",
        "TTL": "2160h",
        "maxTTL": "2160h",
        "notBeforeDuration": "30s",
        "allowLocalhost": False,
        "allowedDomains": ["vault.example.svc"],
        "allowedDomainsTemplate": False,
        "allowBareDomains": True,
        "allowSubdomains": False,
        "allowGlobDomains": False,
        "allowAnyName": False,
        "enforceHostnames": True,
        "allowIPSans": True,
        "allowedURISans": [],
        "allowedOtherSans": [],
        "serverFlag": True,
        "clientFlag": False,
        "codeSigningFlag": False,
        "emailProtectionFlag": False,
        "keyType": "ec",
        "keyBits": 256,
        "keyUsage": ["DigitalSignature", "KeyAgreement", "KeyEncipherment"],
        "extKeyUsage": [],
        "extKeyUsageOids": [],
        "useCSRCommonName": True,
        "useCSRSans": True,
        "ou": [],
        "organization": [],
        "country": [],
        "locality": [],
        "province": [],
        "streetAddress": [],
        "postalCode": [],
        "serialNumber": "",
        "generateLease": False,
        "noStore": False,
        "requireCn": True,
        "policyIdentifiers": [],
        "basicConstraintsValidForNonCa": False,
    }


def pki_live() -> dict:
    live = {
        "ttl": 7776000,
        "max_ttl": 7776000,
        "not_before_duration": 30,
        "allow_localhost": False,
        "allowed_domains": ["vault.example.svc"],
        "allowed_domains_template": False,
        "allow_bare_domains": True,
        "allow_subdomains": False,
        "allow_glob_domains": False,
        "allow_any_name": False,
        "enforce_hostnames": True,
        "allow_ip_sans": True,
        "allowed_uri_sans": [],
        "allowed_other_sans": [],
        "server_flag": True,
        "client_flag": False,
        "code_signing_flag": False,
        "email_protection_flag": False,
        "key_type": "ec",
        "key_bits": 256,
        "key_usage": ["DigitalSignature", "KeyAgreement", "KeyEncipherment"],
        "ext_key_usage": [],
        "ext_key_usage_oids": [],
        "use_csr_common_name": True,
        "use_csr_sans": True,
        "ou": [],
        "organization": [],
        "country": [],
        "locality": [],
        "province": [],
        "street_address": [],
        "postal_code": [],
        # serial_number deliberately ABSENT: Vault 2.0 accepts the deprecated
        # write param but does not store/return it (live-verified).
        "generate_lease": False,
        "no_store": False,
        "require_cn": True,
        "policy_identifiers": [],
        "basic_constraints_valid_for_non_ca": False,
    }
    live.update(parity.EXPECTED_PKI_ROLE_DEFAULTS)
    return live


def mount_fixtures() -> tuple[dict, dict, dict]:
    spec = {
        "type": "pki",
        "config": {
            "defaultLeaseTTL": "2764800",
            "maxLeaseTTL": "315360000",
            "forceNoCache": False,
        },
    }
    mounts = {"pki-int-tcn/": {"type": "pki", "config": {}}}
    tune = {
        "default_lease_ttl": 2764800,
        "max_lease_ttl": 315360000,
        "force_no_cache": False,
        "description": "",
    }
    return spec, mounts, tune


def with_vault(responses: dict):
    def fake_vault_get(path: str):
        return responses.get(path)

    parity.vault_get = fake_vault_get


REAL_VAULT_GET = parity.vault_get
FAILURES: list[str] = []


def expect(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"{status}  {name}{'  ' + detail if detail and not condition else ''}")
    if not condition:
        FAILURES.append(name)


def expect_usage_error(name: str, fn) -> None:
    try:
        fn()
    except SystemExit as exc:
        expect(name, exc.code == 2, f"exit={exc.code}")
        return
    expect(name, False, "no SystemExit raised")


def main() -> int:
    # --- duration parsing ---
    expect("duration-2160h", parity.parse_go_duration("2160h", "t") == 7776000)
    expect("duration-30s", parity.parse_go_duration("30s", "t") == 30)
    expect("duration-composite", parity.parse_go_duration("1h30m", "t") == 5400)
    expect("duration-bare-seconds", parity.parse_go_duration("2764800", "t") == 2764800)
    expect_usage_error(
        "duration-garbage", lambda: parity.parse_go_duration("soon", "t")
    )

    # --- pki role ---
    with_vault({"pki-int-tcn/roles/vault-server": pki_live()})
    expect(
        "pki-role-clean",
        parity.check_pki_role("vault-server", pki_spec()) == [],
        repr(parity.check_pki_role("vault-server", pki_spec())),
    )

    live = pki_live()
    live["allow_ip_sans"] = False
    with_vault({"pki-int-tcn/roles/vault-server": live})
    findings = parity.check_pki_role("vault-server", pki_spec())
    expect(
        "pki-role-field-mismatch",
        len(findings) == 1 and "allow_ip_sans" in findings[0],
        repr(findings),
    )

    live = pki_live()
    live["issuer_ref"] = "other-issuer"
    with_vault({"pki-int-tcn/roles/vault-server": live})
    findings = parity.check_pki_role("vault-server", pki_spec())
    expect(
        "pki-role-nondefault-inexpressible",
        len(findings) == 1 and "issuer_ref" in findings[0] and "re-default" in findings[0],
        repr(findings),
    )

    live = pki_live()
    live["some_future_field"] = "surprising"
    with_vault({"pki-int-tcn/roles/vault-server": live})
    findings = parity.check_pki_role("vault-server", pki_spec())
    expect(
        "pki-role-unknown-live-field",
        len(findings) == 1 and "some_future_field" in findings[0],
        repr(findings),
    )

    with_vault({"pki-int-tcn/roles/vault-server": pki_live()})
    incomplete = pki_spec()
    del incomplete["clientFlag"]
    expect_usage_error(
        "pki-role-missing-explicit-field",
        lambda: parity.check_pki_role("vault-server", incomplete),
    )

    with_vault({})
    findings = parity.check_pki_role("vault-server", pki_spec())
    expect(
        "pki-role-missing-live",
        len(findings) == 1 and "MISSING live" in findings[0],
        repr(findings),
    )

    # serial_number is write-only in Vault 2.0: "" in git + absent live = parity;
    # any other git value is unverifiable and must be flagged.
    with_vault({"pki-int-tcn/roles/vault-server": pki_live()})
    noisy = pki_spec()
    noisy["serialNumber"] = "sneaky-value"
    findings = parity.check_pki_role("vault-server", noisy)
    expect(
        "pki-role-write-only-nondefault",
        len(findings) == 1 and "write-only" in findings[0],
        repr(findings),
    )

    # --- mount ---
    spec, mounts, tune = mount_fixtures()
    with_vault({"sys/mounts": mounts, "sys/mounts/pki-int-tcn/tune": tune})
    expect(
        "mount-clean",
        parity.check_mount("pki-int-tcn", spec) == [],
        repr(parity.check_mount("pki-int-tcn", spec)),
    )

    spec, mounts, tune = mount_fixtures()
    tune["max_lease_ttl"] = 2764800
    with_vault({"sys/mounts": mounts, "sys/mounts/pki-int-tcn/tune": tune})
    findings = parity.check_mount("pki-int-tcn", spec)
    expect(
        "mount-maxttl-mismatch",
        len(findings) == 1 and "max_lease_ttl" in findings[0],
        repr(findings),
    )

    spec, mounts, tune = mount_fixtures()
    mounts["pki-int-tcn/"]["config"]["listing_visibility"] = "unauth"
    with_vault({"sys/mounts": mounts, "sys/mounts/pki-int-tcn/tune": tune})
    findings = parity.check_mount("pki-int-tcn", spec)
    expect(
        "mount-listing-visibility-drift",
        len(findings) == 1 and "listing_visibility" in findings[0],
        repr(findings),
    )

    spec, mounts, tune = mount_fixtures()
    tune["audit_non_hmac_request_keys"] = ["secret_key"]
    with_vault({"sys/mounts": mounts, "sys/mounts/pki-int-tcn/tune": tune})
    findings = parity.check_mount("pki-int-tcn", spec)
    expect(
        "mount-live-only-tune-field",
        len(findings) == 1 and "audit_non_hmac_request_keys" in findings[0],
        repr(findings),
    )

    spec, mounts, tune = mount_fixtures()
    del spec["config"]["maxLeaseTTL"]
    with_vault({"sys/mounts": mounts, "sys/mounts/pki-int-tcn/tune": tune})
    expect_usage_error(
        "mount-missing-explicit-maxttl",
        lambda: parity.check_mount("pki-int-tcn", spec),
    )

    spec, mounts, tune = mount_fixtures()
    with_vault({"sys/mounts": {}, "sys/mounts/pki-int-tcn/tune": tune})
    findings = parity.check_mount("pki-int-tcn", spec)
    expect(
        "mount-missing-live",
        len(findings) == 1 and "MISSING live" in findings[0],
        repr(findings),
    )

    # --- existing kinds still verified (regression) ---
    with_vault({"sys/policies/acl/tenant-read": {"policy": "path \"a\" {}"}})
    expect(
        "policy-clean",
        parity.check_policy("tenant-read", {"policy": 'path "a" {}'}) == [],
    )
    findings = parity.check_policy("tenant-read", {"policy": 'path "b" {}'})
    expect(
        "policy-mismatch",
        len(findings) == 1 and "CONTENT MISMATCH" in findings[0],
        repr(findings),
    )

    # --- unsupported managed kind fails closed ---
    with tempfile.TemporaryDirectory() as tmp:
        managed = Path(tmp)
        (managed / "rogue.yaml").write_text(
            "apiVersion: redhatcop.redhat.io/v1alpha1\n"
            "kind: RandomSecretEngineConfig\n"
            "metadata:\n  name: rogue\n"
            "spec: {}\n",
            encoding="utf-8",
        )
        expect_usage_error(
            "unsupported-kind-fails-closed",
            lambda: list(parity.iter_managed_docs(managed)),
        )

    parity.vault_get = REAL_VAULT_GET
    if FAILURES:
        print(f"\nSELFTEST FAIL ({len(FAILURES)}): {', '.join(FAILURES)}", file=sys.stderr)
        return 1
    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
