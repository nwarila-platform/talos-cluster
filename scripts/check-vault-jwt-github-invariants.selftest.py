#!/usr/bin/env python3
"""Focused offline fixtures for the jwt-github foundation guard."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = ROOT / "scripts/check-vault-jwt-github-invariants.py"


def load_guard():
    spec = importlib.util.spec_from_file_location("_jwt_guard", GUARD_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {GUARD_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = load_guard()


def write_yaml(root: Path, rel: Path | str, doc: dict) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(doc, sort_keys=False, width=180),
        encoding="utf-8",
    )


def config_doc() -> dict:
    return {
        "apiVersion": guard.API_VERSION,
        "kind": "JWTOIDCAuthEngineConfig",
        "metadata": {
            "name": "jwt-github",
            "namespace": "vault-config-operator",
        },
        "spec": {
            "path": "jwt-github",
            "authentication": copy.deepcopy(guard.AUTHENTICATION),
            "OIDCDiscoveryURL": guard.OIDC_URL,
            "boundIssuer": guard.OIDC_URL,
            "JWTSupportedAlgs": ["RS256"],
        },
    }


def flux_doc() -> dict:
    return {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": {"name": "vault-config-managed", "namespace": "flux-system"},
        "spec": {
            "healthCheckExprs": [
                {
                    "apiVersion": guard.API_VERSION,
                    "kind": "JWTOIDCAuthEngineConfig",
                    "current": guard.HEALTH_CURRENT,
                },
                {
                    "apiVersion": guard.API_VERSION,
                    "kind": "JWTOIDCAuthEngineRole",
                    "current": guard.HEALTH_CURRENT,
                },
            ]
        },
    }


def good_role_doc() -> dict:
    name = "deploy-example"
    return {
        "apiVersion": guard.API_VERSION,
        "kind": "JWTOIDCAuthEngineRole",
        "metadata": {"name": name, "namespace": "vault-config-operator"},
        "spec": {
            "path": "jwt-github",
            "authentication": copy.deepcopy(guard.AUTHENTICATION),
            "name": name,
            "roleType": "jwt",
            "userClaim": "repository_id",
            "boundAudiences": [guard.AUDIENCE],
            "boundClaimsType": "string",
            "boundClaims": {
                "workflow_ref": "NWarila/example/.github/workflows/deploy.yml@refs/heads/main",
                "repository_id": "123456",
                "repository_owner_id": "7890",
                "event_name": ["push", "workflow_dispatch"],
            },
            "claimMappings": copy.deepcopy(guard.CLAIM_MAPPINGS),
            "tokenType": "batch",
            "tokenTTL": "15m",
            "tokenPeriod": 0,
            "tokenNoDefaultPolicy": True,
            "tokenPolicies": [name],
        },
    }


def base_fixture(root: Path, with_role: bool = False) -> None:
    write_yaml(root, guard.CONFIG_FILE, config_doc())
    write_yaml(
        root,
        guard.MANAGED_KUSTOMIZATION,
        {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": [guard.CONFIG_FILE.name],
        },
    )
    write_yaml(root, guard.CNP_FILE, guard.expected_cnp())
    write_yaml(
        root,
        guard.VAULT_BASE_KUSTOMIZATION,
        {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": [guard.CNP_FILE.name],
        },
    )
    write_yaml(root, guard.FLUX_KUSTOMIZATION, flux_doc())
    if with_role:
        write_yaml(
            root,
            guard.MANAGED_DIR / "jwtoidcauthenginerole-deploy-example.yaml",
            good_role_doc(),
        )


def load_doc(root: Path, rel: Path) -> dict:
    return yaml.safe_load((root / rel).read_text(encoding="utf-8"))


def mutate_doc(root: Path, rel: Path, mutate) -> None:
    doc = load_doc(root, rel)
    mutate(doc)
    write_yaml(root, rel, doc)


def mutate_role(root: Path, mutate) -> None:
    mutate_doc(
        root,
        guard.MANAGED_DIR / "jwtoidcauthenginerole-deploy-example.yaml",
        mutate,
    )


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
    return rc, (stdout.getvalue() + stderr.getvalue()).strip()


CASES: list[tuple[str, bool, int, object, str]] = []


def case(name: str, with_role: bool, mutate, fragment: str, expected_rc: int = 1) -> None:
    CASES.append((name, with_role, expected_rc, mutate, fragment))


def no_mutation(root: Path) -> None:
    pass


case("foundation-good", False, no_mutation, "PASS:", 0)
case("role-good", True, no_mutation, "PASS:", 0)


def config_mutator(callback):
    return lambda root: mutate_doc(root, guard.CONFIG_FILE, callback)


case(
    "config-path-wrong",
    False,
    config_mutator(lambda d: d["spec"].__setitem__("path", "jwt")),
    "spec.path",
)
case(
    "config-discovery-wrong",
    False,
    config_mutator(lambda d: d["spec"].__setitem__("OIDCDiscoveryURL", "https://github.com")),
    "OIDCDiscoveryURL",
)
case(
    "config-issuer-wrong",
    False,
    config_mutator(lambda d: d["spec"].__setitem__("boundIssuer", "https://github.com")),
    "boundIssuer",
)
case(
    "config-algorithm-wrong",
    False,
    config_mutator(lambda d: d["spec"].__setitem__("JWTSupportedAlgs", ["HS256"])),
    "JWTSupportedAlgs",
)
for forbidden in ("JWKSURL", "JWTValidationPubKeys", "defaultRole"):
    case(
        f"config-forbids-{forbidden}",
        False,
        config_mutator(lambda d, key=forbidden: d["spec"].__setitem__(key, "forbidden")),
        "spec keys must be exactly",
    )


def remove_health(kind: str):
    def mutate(root: Path) -> None:
        mutate_doc(
            root,
            guard.FLUX_KUSTOMIZATION,
            lambda d: d["spec"].__setitem__(
                "healthCheckExprs",
                [e for e in d["spec"]["healthCheckExprs"] if e["kind"] != kind],
            ),
        )

    return mutate


case(
    "health-config-missing",
    False,
    remove_health("JWTOIDCAuthEngineConfig"),
    "JWTOIDCAuthEngineConfig health entry",
)
case(
    "health-role-missing",
    False,
    remove_health("JWTOIDCAuthEngineRole"),
    "JWTOIDCAuthEngineRole health entry",
)


def cnp_mutator(callback):
    return lambda root: mutate_doc(root, guard.CNP_FILE, callback)


case(
    "cnp-match-pattern-forbidden",
    False,
    cnp_mutator(
        lambda d: d["spec"]["egress"][0]["toPorts"][0]["rules"].__setitem__(
            "dns", [{"matchPattern": "*.githubusercontent.com"}]
        )
    ),
    "matchPattern",
)
case(
    "cnp-wildcard-host-forbidden",
    False,
    cnp_mutator(
        lambda d: d["spec"]["egress"][1].__setitem__(
            "toFQDNs", [{"matchName": "*.actions.githubusercontent.com"}]
        )
    ),
    "policy must be the exact-host",
)
case(
    "cnp-github-wide-domain-forbidden",
    False,
    cnp_mutator(
        lambda d: d["spec"]["egress"][1].__setitem__(
            "toFQDNs", [{"matchName": "github.com"}]
        )
    ),
    "policy must be the exact-host",
)
case(
    "cnp-cidr-forbidden",
    False,
    cnp_mutator(
        lambda d: d["spec"]["egress"].append({"toCIDR": ["192.0.2.1/32"]})
    ),
    "CIDRs",
)
case(
    "cnp-world-forbidden",
    False,
    cnp_mutator(
        lambda d: d["spec"]["egress"].append({"toEntities": ["world"]})
    ),
    "entities/world",
)
case(
    "cnp-default-route-forbidden",
    False,
    cnp_mutator(
        lambda d: d["spec"]["egress"].append({"toCIDR": ["0.0.0.0/0"]})
    ),
    "default routes",
)


def role_mutator(callback):
    return lambda root: mutate_role(root, callback)


case(
    "role-name-prefix",
    True,
    role_mutator(lambda d: d["metadata"].__setitem__("name", "example")),
    "metadata.name must match deploy-<repo>",
)
case(
    "role-name-parity",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("name", "deploy-other")),
    "spec.name must exactly equal metadata.name",
)
case(
    "role-path",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("path", "jwt")),
    "spec.path",
)
case(
    "role-authentication",
    True,
    role_mutator(lambda d: d["spec"]["authentication"].__setitem__("role", "other")),
    "spec.authentication",
)
case(
    "role-type-non-jwt",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("roleType", "oidc")),
    "spec.roleType",
)
case(
    "role-user-claim",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("userClaim", "sub")),
    "spec.userClaim",
)
case(
    "role-audience-missing",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("boundAudiences", [])),
    "spec.boundAudiences",
)
case(
    "role-audience-extra",
    True,
    role_mutator(
        lambda d: d["spec"].__setitem__(
            "boundAudiences", [guard.AUDIENCE, "extra"]
        )
    ),
    "spec.boundAudiences",
)
case(
    "role-bound-claims-type",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("boundClaimsType", "glob")),
    "spec.boundClaimsType",
)

for claim in ("workflow_ref", "repository_id", "repository_owner_id", "event_name"):
    case(
        f"role-bound-claim-missing-{claim}",
        True,
        role_mutator(lambda d, key=claim: d["spec"]["boundClaims"].pop(key)),
        "boundClaims keys must be exactly",
    )

case(
    "role-event-list-exact",
    True,
    role_mutator(
        lambda d: d["spec"]["boundClaims"].__setitem__(
            "event_name", ["workflow_dispatch", "push"]
        )
    ),
    "boundClaims.event_name must be exactly",
)
case(
    "role-scalar-claim-as-list",
    True,
    role_mutator(
        lambda d: d["spec"]["boundClaims"].__setitem__(
            "repository_id", ["123456"]
        )
    ),
    "boundClaims.repository_id must be a non-empty scalar string",
)
case(
    "role-claim-mapping-missing",
    True,
    role_mutator(lambda d: d["spec"]["claimMappings"].pop("sha")),
    "spec.claimMappings",
)
case(
    "role-claim-mapping-wrong",
    True,
    role_mutator(lambda d: d["spec"]["claimMappings"].__setitem__("sha", "ref")),
    "spec.claimMappings",
)
case(
    "role-token-ttl-zero",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenTTL", "0s")),
    "tokenTTL must be strictly positive",
)
case(
    "role-token-ttl-negative",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenTTL", "-1s")),
    "tokenTTL must be strictly positive",
)
case(
    "role-token-ttl-unparseable",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenTTL", "fifteen minutes")),
    "tokenTTL is not a valid Go-duration",
)
case(
    "role-token-ttl-over-900s",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenTTL", "901s")),
    "tokenTTL must be no greater than 900s",
)
case(
    "role-token-max-ttl-zero",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenMaxTTL", "0s")),
    "tokenMaxTTL must be strictly positive",
)
case(
    "role-token-max-ttl-over-token-ttl",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenMaxTTL", "16m")),
    "tokenMaxTTL must be no greater than tokenTTL",
)
case(
    "role-token-explicit-max-ttl-negative",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenExplicitMaxTTL", "-1s")),
    "tokenExplicitMaxTTL must be strictly positive",
)
case(
    "role-token-explicit-max-ttl-unparseable",
    True,
    role_mutator(
        lambda d: d["spec"].__setitem__("tokenExplicitMaxTTL", "later")
    ),
    "tokenExplicitMaxTTL is not a valid Go-duration",
)
case(
    "role-token-explicit-max-ttl-over-token-ttl",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenExplicitMaxTTL", "16m")),
    "tokenExplicitMaxTTL must be no greater than tokenTTL",
)
case(
    "role-token-period",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenPeriod", 1)),
    "tokenPeriod must be the integer 0",
)
case(
    "role-token-type",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenType", "service")),
    "spec.tokenType",
)
case(
    "role-token-default-policy",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenNoDefaultPolicy", False)),
    "tokenNoDefaultPolicy must be true",
)
case(
    "role-token-policies-zero",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("tokenPolicies", [])),
    "tokenPolicies must contain exactly one",
)
case(
    "role-token-policies-multiple",
    True,
    role_mutator(
        lambda d: d["spec"].__setitem__(
            "tokenPolicies", ["deploy-example", "deploy-other"]
        )
    ),
    "tokenPolicies must contain exactly one",
)
case(
    "role-unratified-extra-field",
    True,
    role_mutator(lambda d: d["spec"].__setitem__("boundSubject", "extra")),
    "unratified role spec fields",
)


def main() -> int:
    failures = 0
    for name, with_role, expected_rc, mutate, fragment in CASES:
        with tempfile.TemporaryDirectory(prefix="jwt-github-guard-") as tmp:
            root = Path(tmp)
            base_fixture(root, with_role=with_role)
            mutate(root)
            rc, output = run_guard(root)
        ok = rc == expected_rc and fragment in output
        observed = "PASS" if rc == 0 else "FAIL" if rc == 1 else "ERROR"
        print(
            f"{'PASS' if ok else 'FAIL'}  {name:<48} "
            f"guard={observed}(rc={rc})"
        )
        if not ok:
            failures += 1
            print(f"      expected rc={expected_rc}, fragment={fragment!r}")
            print(f"      output={output[:1000]!r}")
    print()
    if failures:
        print(f"SELFTEST FAIL ({failures} case(s))")
        return 1
    print("SELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
