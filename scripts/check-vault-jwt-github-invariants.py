#!/usr/bin/env python3
"""Fail-closed AR4a invariants for the shared GitHub-OIDC Vault foundation.

The guard selects the effective ``vault-config-managed`` Flux Kustomization
from the cluster-root render and validates its rendered applied inventory with
Flux-compatible unrestricted load semantics. The root includes a remote
Gateway API base, so this guard requires network access and fails closed when
the render cannot be reproduced (TD-0020).

It pins four security-bearing shapes:

1. The v0.8.49 JWTOIDCAuthEngineConfig uses the exact jwt-github discovery
   contract and no mutually exclusive key source/default role.
2. Both JWT operator kinds have the repository's observed-generation-aware
   Flux health expression.
3. Vault's GitHub OIDC egress is one exact-host DNS + TCP/443 CNP.
4. Every JWTOIDCAuthEngineRole in the rendered, Flux-applied prune-armed
   inventory matches the ratified D9 contract, including exact claims and
   strictly bounded Go-duration token lifetimes.

No role CR exists in AR4a; role validation is deliberately vacuous until the
first consumer is authored, while the self-test proves every field rejects a
focused malformed fixture.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover - CI dependency
    print(f"ERROR: PyYAML is required: {exc}", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parents[1]
MANAGED_DIR = Path("clusters/talos-cluster/apps/vault/vault-config/managed")
CONFIG_FILE = MANAGED_DIR / "jwtoidcauthengineconfig-jwt-github.yaml"
MANAGED_KUSTOMIZATION = MANAGED_DIR / "kustomization.yaml"
VAULT_BASE_DIR = Path("clusters/talos-cluster/apps/vault/base")
CNP_FILE = VAULT_BASE_DIR / "ciliumnetworkpolicy-egress-github-oidc.yaml"
VAULT_BASE_KUSTOMIZATION = VAULT_BASE_DIR / "kustomization.yaml"
FLUX_KUSTOMIZATION = Path(
    "clusters/talos-cluster/apps/kustomization-vault-config-managed.yaml"
)

API_VERSION = "redhatcop.redhat.io/v1alpha1"
OIDC_HOST = "token.actions.githubusercontent.com"
OIDC_URL = f"https://{OIDC_HOST}"
AUDIENCE = "vault.deploy-vault.svc.cluster.local"
HEALTH_CURRENT = (
    "has(status.conditions) && status.conditions.exists(c, c.type == "
    "'ReconcileSuccessful' && c.status == 'True' && "
    "c.observedGeneration == metadata.generation)"
)
AUTHENTICATION = {
    "path": "kubernetes",
    "role": "vault-config-operator",
    "serviceAccount": {"name": "vault-config-operator-vault"},
}
CLAIM_MAPPINGS = {
    "run_id": "run_id",
    "run_attempt": "run_attempt",
    "actor": "actor",
    "sha": "sha",
    "workflow_ref": "workflow_ref",
}
BOUND_CLAIM_KEYS = {
    "workflow_ref",
    "repository_id",
    "repository_owner_id",
    "event_name",
}
CONFIG_SPEC_KEYS = {
    "path",
    "authentication",
    "OIDCDiscoveryURL",
    "boundIssuer",
    "JWTSupportedAlgs",
}
ROLE_SPEC_KEYS = {
    "path",
    "authentication",
    "name",
    "roleType",
    "userClaim",
    "boundAudiences",
    "boundClaimsType",
    "boundClaims",
    "claimMappings",
    "tokenType",
    "tokenTTL",
    "tokenMaxTTL",
    "tokenExplicitMaxTTL",
    "tokenPeriod",
    "tokenNoDefaultPolicy",
    "tokenPolicies",
}
ROLE_NAME_RE = re.compile(r"deploy-[a-z0-9](?:[-a-z0-9]*[a-z0-9])?")
DURATION_PART_RE = re.compile(
    r"(?P<number>(?:\d+(?:\.\d*)?|\.\d+))"
    r"(?P<unit>ns|us|µs|μs|ms|s|m|h)"
)
DURATION_UNITS_NS = {
    "ns": Decimal(1),
    "us": Decimal(1_000),
    "µs": Decimal(1_000),
    "μs": Decimal(1_000),
    "ms": Decimal(1_000_000),
    "s": Decimal(1_000_000_000),
    "m": Decimal(60_000_000_000),
    "h": Decimal(3_600_000_000_000),
}
MAX_TOKEN_TTL_NS = Decimal(900_000_000_000)


def _load_rendered_inventory_helper():
    helper_path = REPO_ROOT / "scripts/rendered-inventory.py"
    spec = importlib.util.spec_from_file_location("_rendered_inventory", helper_path)
    if spec is None or spec.loader is None:
        raise fail_usage(f"cannot load rendered-inventory helper: {helper_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fail_usage(message: str) -> SystemExit:
    print(f"ERROR: {message}", file=sys.stderr)
    return SystemExit(2)


rendered_inventory = _load_rendered_inventory_helper()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the jwt-github Vault foundation contract against the "
            "Flux-rendered managed inventory."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repo root to scan (self-test fixtures only; default: real repo)",
    )
    return parser.parse_args()


def load_yaml_documents(path: Path) -> list[dict]:
    if not path.is_file():
        raise fail_usage(f"required file is missing: {path}")
    try:
        raw = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as exc:
        raise fail_usage(f"failed to parse {path}: {exc}")
    docs = [doc for doc in raw if isinstance(doc, dict)]
    if len(docs) != len([doc for doc in raw if doc is not None]):
        raise fail_usage(f"{path} contains a non-mapping YAML document")
    return docs


def load_one(path: Path) -> dict:
    docs = load_yaml_documents(path)
    if len(docs) != 1:
        raise fail_usage(f"{path} must contain exactly one YAML document")
    return docs[0]


def parse_go_duration(value: str) -> Decimal:
    """Parse Go time.ParseDuration syntax into nanoseconds.

    Go accepts the special literal "0"; all non-zero durations are a signed
    sequence of decimal number+unit parts using ns/us/µs/μs/ms/s/m/h.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("duration must be a non-empty string")
    if value == "0":
        return Decimal(0)
    sign = Decimal(1)
    body = value
    if body[0] in "+-":
        if body[0] == "-":
            sign = Decimal(-1)
        body = body[1:]
    if not body:
        raise ValueError("duration has no value")
    position = 0
    total = Decimal(0)
    while position < len(body):
        match = DURATION_PART_RE.match(body, position)
        if match is None:
            raise ValueError(f"invalid duration syntax at {body[position:]!r}")
        try:
            number = Decimal(match.group("number"))
        except InvalidOperation as exc:
            raise ValueError("invalid decimal duration") from exc
        total += number * DURATION_UNITS_NS[match.group("unit")]
        position = match.end()
    return sign * total


def check_exact(value, expected, label: str, findings: list[str]) -> None:
    if value != expected:
        findings.append(f"{label} must equal {expected!r}; found {value!r}")


def check_kustomization_reference(
    path: Path, resource: str, label: str, findings: list[str]
) -> None:
    doc = load_one(path)
    resources = doc.get("resources")
    if not isinstance(resources, list) or resources.count(resource) != 1:
        findings.append(
            f"{label} must reference {resource!r} exactly once; found "
            f"{resources!r}"
        )


def check_config(inventory, findings: list[str]) -> None:
    configs = [
        doc
        for doc in inventory.documents
        if doc.get("apiVersion") == API_VERSION
        and doc.get("kind") == "JWTOIDCAuthEngineConfig"
    ]
    if len(configs) != 1:
        return  # applied_inventory_findings reports the ratified cardinality
    doc = configs[0]
    label = rendered_inventory.rendered_document_label(doc)
    check_exact(doc.get("apiVersion"), API_VERSION, f"{label}: apiVersion", findings)
    check_exact(doc.get("kind"), "JWTOIDCAuthEngineConfig", f"{label}: kind", findings)
    metadata = doc.get("metadata") or {}
    check_exact(metadata.get("name"), "jwt-github", f"{label}: metadata.name", findings)
    check_exact(
        metadata.get("namespace"),
        "vault-config-operator",
        f"{label}: metadata.namespace",
        findings,
    )
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        findings.append(f"{label}: spec must be a mapping")
        return
    if set(spec) != CONFIG_SPEC_KEYS:
        findings.append(
            f"{label}: spec keys must be exactly "
            f"{sorted(CONFIG_SPEC_KEYS)!r}; found {sorted(spec)!r}"
        )
    check_exact(spec.get("path"), "jwt-github", f"{label}: spec.path", findings)
    check_exact(
        spec.get("authentication"),
        AUTHENTICATION,
        f"{label}: spec.authentication",
        findings,
    )
    check_exact(
        spec.get("OIDCDiscoveryURL"),
        OIDC_URL,
        f"{label}: spec.OIDCDiscoveryURL",
        findings,
    )
    check_exact(
        spec.get("boundIssuer"),
        OIDC_URL,
        f"{label}: spec.boundIssuer",
        findings,
    )
    check_exact(
        spec.get("JWTSupportedAlgs"),
        ["RS256"],
        f"{label}: spec.JWTSupportedAlgs",
        findings,
    )
    for forbidden in ("JWKSURL", "JWTValidationPubKeys", "defaultRole"):
        if forbidden in spec:
            findings.append(
                f"{label}: mutually exclusive/default field "
                f"{forbidden!r} must be absent"
            )


def check_health(flux_kustomization: dict, findings: list[str]) -> None:
    doc = flux_kustomization
    label = rendered_inventory.rendered_document_label(doc)
    expressions = ((doc.get("spec") or {}).get("healthCheckExprs"))
    if not isinstance(expressions, list):
        findings.append(f"{label}: spec.healthCheckExprs must be a list")
        return
    for kind in ("JWTOIDCAuthEngineConfig", "JWTOIDCAuthEngineRole"):
        expected = {
            "apiVersion": API_VERSION,
            "kind": kind,
            "current": HEALTH_CURRENT,
        }
        matches = [entry for entry in expressions if isinstance(entry, dict) and entry.get("kind") == kind]
        if matches != [expected]:
            findings.append(
                f"{label}: {kind} health entry must occur exactly "
                f"once with the observed-generation expression; found {matches!r}"
            )


def expected_cnp() -> dict:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "vault-egress-github-oidc"},
        "spec": {
            "endpointSelector": {
                "matchLabels": {"app.kubernetes.io/name": "vault"}
            },
            "egress": [
                {
                    "toEndpoints": [
                        {
                            "matchLabels": {
                                "io.kubernetes.pod.namespace": "kube-system",
                                "k8s-app": "kube-dns",
                            }
                        }
                    ],
                    "toPorts": [
                        {
                            "ports": [{"port": "53", "protocol": "ANY"}],
                            "rules": {
                                "dns": [{"matchName": OIDC_HOST}]
                            },
                        }
                    ],
                },
                {
                    "toFQDNs": [{"matchName": OIDC_HOST}],
                    "toPorts": [
                        {
                            "ports": [{"port": "443", "protocol": "TCP"}]
                        }
                    ],
                },
            ],
        },
    }


def check_cnp(repo: Path, findings: list[str]) -> None:
    doc = load_one(repo / CNP_FILE)
    if doc != expected_cnp():
        findings.append(
            f"{CNP_FILE}: policy must be the exact-host DNS plus TCP/443 "
            "contract; matchPattern, wildcards, broader domains, CIDRs, "
            "entities/world, default routes, and extra rules are forbidden"
        )
    check_kustomization_reference(
        repo / VAULT_BASE_KUSTOMIZATION,
        CNP_FILE.name,
        str(VAULT_BASE_KUSTOMIZATION),
        findings,
    )


def duration_value(spec: dict, field: str, findings: list[str]) -> Decimal | None:
    value = spec.get(field)
    if not isinstance(value, str) or not value:
        findings.append(f"{field} must be a non-empty Go-duration string")
        return None
    try:
        return parse_go_duration(value)
    except ValueError as exc:
        findings.append(f"{field} is not a valid Go-duration string: {value!r} ({exc})")
        return None


def check_role(label: str, doc: dict, findings: list[str]) -> None:
    if doc.get("apiVersion") != API_VERSION:
        findings.append(f"{label}: apiVersion must be {API_VERSION!r}")
    metadata = doc.get("metadata") or {}
    name = metadata.get("name")
    if not isinstance(name, str) or ROLE_NAME_RE.fullmatch(name) is None:
        findings.append(f"{label}: metadata.name must match deploy-<repo>")
    if metadata.get("namespace") != "vault-config-operator":
        findings.append(f"{label}: metadata.namespace must be 'vault-config-operator'")

    spec = doc.get("spec")
    if not isinstance(spec, dict):
        findings.append(f"{label}: spec must be a mapping")
        return
    unexpected = set(spec) - ROLE_SPEC_KEYS
    missing = ROLE_SPEC_KEYS - {"tokenMaxTTL", "tokenExplicitMaxTTL"} - set(spec)
    if unexpected:
        findings.append(f"{label}: unratified role spec fields: {sorted(unexpected)!r}")
    if missing:
        findings.append(f"{label}: missing role spec fields: {sorted(missing)!r}")

    if spec.get("name") != name:
        findings.append(f"{label}: spec.name must exactly equal metadata.name")
    check_exact(spec.get("path"), "jwt-github", f"{label}: spec.path", findings)
    check_exact(
        spec.get("authentication"),
        AUTHENTICATION,
        f"{label}: spec.authentication",
        findings,
    )
    check_exact(spec.get("roleType"), "jwt", f"{label}: spec.roleType", findings)
    check_exact(
        spec.get("userClaim"),
        "repository_id",
        f"{label}: spec.userClaim",
        findings,
    )
    check_exact(
        spec.get("boundAudiences"),
        [AUDIENCE],
        f"{label}: spec.boundAudiences",
        findings,
    )
    check_exact(
        spec.get("boundClaimsType"),
        "string",
        f"{label}: spec.boundClaimsType",
        findings,
    )

    claims = spec.get("boundClaims")
    if not isinstance(claims, dict):
        findings.append(f"{label}: spec.boundClaims must be a mapping")
    else:
        if set(claims) != BOUND_CLAIM_KEYS:
            findings.append(
                f"{label}: boundClaims keys must be exactly "
                f"{sorted(BOUND_CLAIM_KEYS)!r}; found {sorted(claims)!r}"
            )
        for key in ("workflow_ref", "repository_id", "repository_owner_id"):
            value = claims.get(key)
            if not isinstance(value, str) or not value:
                findings.append(
                    f"{label}: boundClaims.{key} must be a non-empty scalar string"
                )
        if claims.get("event_name") != ["push", "workflow_dispatch"]:
            findings.append(
                f"{label}: boundClaims.event_name must be exactly "
                "['push', 'workflow_dispatch']"
            )

    check_exact(
        spec.get("claimMappings"),
        CLAIM_MAPPINGS,
        f"{label}: spec.claimMappings",
        findings,
    )
    check_exact(spec.get("tokenType"), "batch", f"{label}: spec.tokenType", findings)
    if spec.get("tokenNoDefaultPolicy") is not True:
        findings.append(f"{label}: tokenNoDefaultPolicy must be true")
    if type(spec.get("tokenPeriod")) is not int or spec.get("tokenPeriod") != 0:
        findings.append(f"{label}: tokenPeriod must be the integer 0")
    if spec.get("tokenPolicies") != [name]:
        findings.append(
            f"{label}: tokenPolicies must contain exactly one entry equal to "
            f"metadata.name ({name!r})"
        )

    ttl = duration_value(spec, "tokenTTL", findings)
    if ttl is not None:
        if ttl <= 0:
            findings.append(f"{label}: tokenTTL must be strictly positive and non-zero")
        elif ttl > MAX_TOKEN_TTL_NS:
            findings.append(f"{label}: tokenTTL must be no greater than 900s")
    for field in ("tokenMaxTTL", "tokenExplicitMaxTTL"):
        value = spec.get(field)
        if value is None or value == "":
            continue
        parsed = duration_value(spec, field, findings)
        if parsed is None:
            continue
        if parsed <= 0:
            findings.append(f"{label}: {field} must be strictly positive when set")
        elif ttl is not None and ttl > 0 and parsed > ttl:
            findings.append(f"{label}: {field} must be no greater than tokenTTL")


def check_roles(inventory, findings: list[str]) -> int:
    count = 0
    for doc in inventory.documents:
        if (
            doc.get("apiVersion") == API_VERSION
            and doc.get("kind") == "JWTOIDCAuthEngineRole"
        ):
            count += 1
            check_role(
                rendered_inventory.rendered_document_label(doc),
                doc,
                findings,
            )
    return count


def evaluate(repo: Path) -> tuple[list[str], int, int]:
    try:
        inventory = rendered_inventory.load_rendered_inventory(repo)
    except rendered_inventory.InventoryError as exc:
        raise fail_usage(f"cannot determine rendered inventory: {exc}")
    findings = list(inventory.flux_findings)
    findings.extend(inventory.containment_findings)
    findings.extend(rendered_inventory.applied_inventory_findings(inventory))
    check_config(inventory, findings)
    check_health(inventory.flux_kustomization, findings)
    check_cnp(repo, findings)
    roles = check_roles(inventory, findings)
    supported = sum(
        1
        for doc in inventory.documents
        if doc.get("apiVersion") == API_VERSION
        and doc.get("kind")
        in rendered_inventory.SUPPORTED_MANAGED_REDHATCOP_KINDS
    )
    return findings, roles, supported


def main() -> int:
    repo = parse_args().root.resolve()
    if not repo.is_dir():
        raise fail_usage(f"--root does not exist: {repo}")
    findings, roles, supported = evaluate(repo)
    if findings:
        print("FAIL: jwt-github foundation invariant guard:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(
        "PASS: jwt-github config, generation-aware health, exact-host CNP, "
        f"and {roles} JWT role contract(s) across {supported} rendered managed "
        "object(s) satisfy the ratified AR4a shape."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - tooling errors fail closed
        print(f"ERROR: tooling failure: {exc!r}", file=sys.stderr)
        sys.exit(2)
