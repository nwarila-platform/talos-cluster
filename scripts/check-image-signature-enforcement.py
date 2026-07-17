#!/usr/bin/env python3
"""Fail if first-party GHCR images are not signature-verified by Kyverno.

This guard scans raw YAML files under the configured roots, including standalone
trees such as apps/vault/restore-drill/ that are intentionally not rendered by
Flux validation.

The required verifyImages action is parameterized by FIRST_PARTY_ENFORCEMENT_MODE
(currently the interim ``Audit`` — see that constant). Restore it to ``Enforce``
after the Kyverno upgrade lands offline bundle verification; every "Enforce" in
the prose/messages below tracks that constant.

Deliberate scope:
- Extract inline ``image:`` string scalars.
- Extract kustomize ``images:`` list entries carrying ``name`` and/or
  ``newName``.
- Normalize extracted image refs to the bare repository name, with tag and
  digest stripped.
- Ignore extracted values containing ``*`` because those are match patterns,
  not concrete deployed images.
- Discover Kyverno Policy/ClusterPolicy ``verifyImages`` blocks and require
  first-party GHCR orgs plus deployed first-party image refs to be covered by
  the effective FIRST_PARTY_ENFORCEMENT_MODE action.
- Require the first-party ``verifyImages`` policy to carry the exact
  guard-generated first-party Pod matchConditions expression.
- Reject fail-closed mutate/verifyImages policies with empty matchConditions
  because Kyverno places them in the shared cluster-wide fail webhook.
- Reject first-party images in namespaces covered by Kyverno's exemption
  surface: the inherited webhook namespaceSelector plus Kyverno resourceFilters.
  Also reject Kyverno HelmRelease defaultRegistry values that would break the
  raw-image CEL versus normalized-image glob superset invariant.

Deliberately out of scope:
- Verifying image digests or tags. That is check-image-digest-sync.py's job.
- HelmRelease-injected upstream images. This guard only covers the declared
  first-party GHCR orgs.
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    import yaml
    from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


DEFAULT_ROOTS = (Path("clusters"), Path("addons"))
FIRST_PARTY_ORG_GLOBS = (
    "ghcr.io/nwarila/*",
    "ghcr.io/nwarila-platform/*",
    "ghcr.io/the-hero-wars-guys/*",
)
FIRST_PARTY_IMAGE_PREFIXES = tuple(
    org_glob[:-1] for org_glob in FIRST_PARTY_ORG_GLOBS
)
FIRST_PARTY_MATCH_CONDITION_NAME = "first-party-image-present"
CANONICAL_FIRST_PARTY_ATTESTORS = {
    "ghcr.io/nwarila/*": {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectRegExp": (
            "^https://github\\.com/[Nn][Ww]arila/.+/\\.github/workflows/"
            ".+@refs/(heads/main|tags/v.*)$"
        ),
    },
    "ghcr.io/nwarila-platform/*": {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectRegExp": (
            "^https://github\\.com/nwarila-platform/.+/\\.github/workflows/"
            ".+@refs/(heads/main|tags/v.*)$"
        ),
    },
    "ghcr.io/the-hero-wars-guys/*": {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectRegExp": (
            "^https://github\\.com/the-hero-wars-guys/.+/\\.github/workflows/"
            ".+@refs/(heads/main|tags/v.*)$"
        ),
    },
}
# Offline keyless verification pins (Sigstore public-good keys) that REPLACE the
# online rekor.url. The enforced policy verifies the embedded cosign bundle SET
# against REKOR_PUBKEY_PEM (no online Rekor GET), the Fulcio leaf chain against
# FULCIO_ROOTS_PEM (Sigstore root+intermediate), and the Fulcio SCT against
# CTFE_PUBKEY_PEM; ignoreTlog/ignoreSCT stay false so both log proofs are checked
# offline. These MUST stay byte-identical to the PEMs inlined in
# verify-image-signatures-enforced.yaml (this guard exact-matches them). To be rotated
# by the sigstore-TUF-root drift-watcher (a follow-up PR, before the Enforce flip; not
# built yet). Sources: Sigstore TUF trusted_root targets
# rekor.pub / ctfe_2022.pub / fulcio_v1.crt.pem + fulcio_intermediate_v1.crt.pem.
FULCIO_ROOTS_PEM = "\n".join([
    '-----BEGIN CERTIFICATE-----',
    'MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw',
    'KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y',
    'MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl',
    'LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7',
    'XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex',
    'X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j',
    'YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY',
    'wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ',
    'KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM',
    'WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9',
    'TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ',
    '-----END CERTIFICATE-----',
    '-----BEGIN CERTIFICATE-----',
    'MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw',
    'KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y',
    'MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl',
    'LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C',
    'AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7',
    '7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS',
    '0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB',
    'BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp',
    'KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI',
    'zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR',
    'nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP',
    'mygUY7Ii2zbdCdliiow=',
    '-----END CERTIFICATE-----',
])
REKOR_PUBKEY_PEM = "\n".join([
    '-----BEGIN PUBLIC KEY-----',
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr',
    'kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
    '-----END PUBLIC KEY-----',
])
CTFE_PUBKEY_PEM = "\n".join([
    '-----BEGIN PUBLIC KEY-----',
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNK',
    'AaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==',
    '-----END PUBLIC KEY-----',
])

# OFFLINE-PINS re-arm (2026-07-17). The online-Rekor dependency that BRICKED first-party
# pod creation (Vault + the hwg tenant) on 2026-07-14 is REMOVED: the canonical attestors
# above verify keyless signatures OFFLINE against the pinned Sigstore keys (rekor.pubkey +
# ctlog.pubkey + Fulcio roots), no admission-path online GET. The first-party rules are
# STILL non-blocking in this change (failureAction Audit + failurePolicy Ignore) as a live
# canary: the offline PolicyReports must PASS before the Enforce/Fail flip. This guard fully
# verifies the rule SHAPE (canonical offline attestors, matchConditions, first-party scoping,
# background, exempt-ns, required, no skip/exclude/preconditions) and pins the offline
# material. FLIP both constants below (Enforce / Fail) in the next PR once the Audit canary
# proves out. See vault_live_admin_lockout / cp1_offline_verify_decision.
FIRST_PARTY_ENFORCEMENT_MODE = "Audit"  # restore-target: "Enforce"
FIRST_PARTY_REQUIRED_FAILURE_POLICY = "Ignore"  # restore-target: "Fail"
# The dedicated first-party signature policy. Scoping the first-party checks by
# this name (not just the action) keeps the third-party Audit policy
# (verify-image-signatures) out of the first-party enforcement checks now that
# first-party is also Audit during the interim.
FIRST_PARTY_ENFORCED_POLICY_NAME = "verify-image-signatures-enforced"
EXPECTED_ENFORCE_RULE_MATCH = {"any": [{"resources": {"kinds": ["Pod"]}}]}
IMAGE_SIGNATURE_POLICY_NAMES = (
    "verify-image-signatures",
    "verify-image-signatures-enforced",
)
AUTOGEN_CONTROLLERS_ANNOTATION = "pod-policies.kyverno.io/autogen-controllers"
AUTOGEN_CONTROLLERS_VALUE = "none"
KYVERNO_EXEMPTION_SURFACE_NAMESPACES = {
    "kube-system",
    "kyverno",
    "kube-public",
    "kube-node-lease",
}
KYVERNO_DEFAULT_REGISTRY = "docker.io"
YAML_SUFFIXES = {".yaml", ".yml"}
KUSTOMIZATION_FILENAMES = ("kustomization.yaml", "kustomization.yml")
KYVERNO_POLICY_KINDS = {"ClusterPolicy", "Policy"}


@dataclass(frozen=True)
class ImageRef:
    name: str
    path: Path
    line: int
    value: str
    source: str
    namespace: str | None


@dataclass(frozen=True)
class MatchCondition:
    name: str | None
    expression: str
    line: int


@dataclass(frozen=True)
class VerifyImagesBlock:
    image_references: tuple[str, ...]
    skip_image_references: tuple[str, ...]
    skip_image_references_line: int | None
    action: str
    required: str | None
    attestors: object | None
    path: Path
    line: int
    policy_name: str
    rule_name: str
    rule_line: int
    rule_match: object | None
    rule_match_line: int | None
    rule_exclude_line: int | None
    rule_preconditions_line: int | None


@dataclass(frozen=True)
class PolicyDocument:
    name: str
    kind: str
    path: Path
    line: int
    background: str | None
    autogen_controllers: str | None
    failure_policy: str | None
    match_conditions: tuple[MatchCondition, ...]
    verify_images_blocks: tuple[VerifyImagesBlock, ...]
    has_mutate_rules: bool


@dataclass(frozen=True)
class KyvernoDefaultRegistrySetting:
    path: Path
    line: int
    value: str


@dataclass(frozen=True)
class GuardResult:
    paths: list[Path]
    refs: list[ImageRef]
    first_party_refs: list[ImageRef]
    policies: list[PolicyDocument]
    verify_images_blocks: list[VerifyImagesBlock]
    enforce_blocks: list[VerifyImagesBlock]
    kyverno_default_registry_settings: list[KyvernoDefaultRegistrySetting]
    findings: list[str]


class GuardUsageError(Exception):
    """A tooling or input error that should exit with code 2."""


def assert_first_party_attestor_constants_consistent() -> None:
    org_globs = set(FIRST_PARTY_ORG_GLOBS)
    attestor_orgs = set(CANONICAL_FIRST_PARTY_ATTESTORS)
    missing = sorted(org_globs - attestor_orgs)
    extra = sorted(attestor_orgs - org_globs)
    if not missing and not extra:
        return

    problems = [
        *(f"missing canonical entry for {org_glob!r}" for org_glob in missing),
        *(f"extra canonical entry for {org_glob!r}" for org_glob in extra),
    ]
    raise GuardUsageError(
        "FIRST_PARTY_ORG_GLOBS and CANONICAL_FIRST_PARTY_ATTESTORS disagree: "
        + "; ".join(problems)
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan raw YAML for first-party GHCR image refs that are not covered "
            "by Kyverno verifyImages rules with the effective "
            "FIRST_PARTY_ENFORCEMENT_MODE action (interim: Audit)."
        )
    )
    parser.add_argument(
        "roots",
        nargs="*",
        type=Path,
        help="YAML roots to scan (default: clusters addons)",
    )
    return parser.parse_args()


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def iter_yaml_paths(roots: Iterable[Path]) -> list[Path]:
    paths: set[Path] = set()
    for root in roots:
        if not root.exists():
            raise GuardUsageError(f"{root} does not exist")
        if root.is_file():
            if root.suffix in YAML_SUFFIXES:
                paths.add(root)
            continue
        if not root.is_dir():
            raise GuardUsageError(f"{root} is neither a file nor a directory")
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in YAML_SUFFIXES:
                paths.add(path)
    return sorted(paths)


def scalar_value(node: Node) -> str | None:
    if isinstance(node, ScalarNode):
        return node.value
    return None


def node_line(node: Node) -> int:
    return node.start_mark.line + 1


def split_tag_ref(value: str) -> tuple[str, str | None]:
    slash_index = value.rfind("/")
    colon_index = value.rfind(":")
    if colon_index > slash_index and colon_index < len(value) - 1:
        return value[:colon_index], value[colon_index + 1 :]
    return value, None


def normalize_image_name(value: str) -> str:
    name = value.split("@", 1)[0]
    name, _tag = split_tag_ref(name)
    return name


def parse_inline_image(
    value: str, path: Path, line: int, namespace: str | None
) -> ImageRef | None:
    value = value.strip()
    if not value or "*" in value:
        return None

    name = normalize_image_name(value)
    if not name:
        return None

    return ImageRef(
        name=name,
        path=path,
        line=line,
        value=value,
        source="inline image",
        namespace=namespace,
    )


def mapping_fields(node: MappingNode) -> dict[str, tuple[Node, int]]:
    fields: dict[str, tuple[Node, int]] = {}
    for key_node, value_node in node.value:
        key = scalar_value(key_node)
        if key is not None:
            fields[key] = (value_node, node_line(value_node))
    return fields


def parse_kustomize_images(
    sequence: SequenceNode, path: Path, namespace: str | None
) -> list[ImageRef]:
    refs: list[ImageRef] = []
    for item in sequence.value:
        if not isinstance(item, MappingNode):
            continue

        fields = mapping_fields(item)
        name_pair = fields.get("newName") or fields.get("name")
        if name_pair is None:
            continue
        name_node, name_line = name_pair
        raw_name = scalar_value(name_node)
        if raw_name is None:
            continue

        raw_name = raw_name.strip()
        if not raw_name or "*" in raw_name:
            continue

        name = normalize_image_name(raw_name)
        if not name:
            continue

        refs.append(
            ImageRef(
                name=name,
                path=path,
                line=name_line,
                value=raw_name,
                source="kustomize images",
                namespace=namespace,
            )
        )
    return refs


def extract_refs_from_node(
    node: Node, path: Path, namespace: str | None
) -> list[ImageRef]:
    refs: list[ImageRef] = []
    seen: set[int] = set()

    def walk(current: Node) -> None:
        node_id = id(current)
        if node_id in seen:
            return
        seen.add(node_id)

        if isinstance(current, MappingNode):
            for key_node, value_node in current.value:
                key = scalar_value(key_node)
                if key == "image" and isinstance(value_node, ScalarNode):
                    ref = parse_inline_image(
                        value_node.value, path, node_line(value_node), namespace
                    )
                    if ref is not None:
                        refs.append(ref)
                elif key == "images" and isinstance(value_node, SequenceNode):
                    refs.extend(parse_kustomize_images(value_node, path, namespace))
                walk(value_node)
        elif isinstance(current, SequenceNode):
            for item in current.value:
                walk(item)

    walk(node)
    return refs


def string_list(node: Node | None) -> tuple[str, ...]:
    if node is None:
        return ()
    if isinstance(node, ScalarNode):
        value = node.value.strip()
        return (value,) if value else ()
    if not isinstance(node, SequenceNode):
        return ()

    values: list[str] = []
    for item in node.value:
        value = scalar_value(item)
        if value is not None:
            value = value.strip()
            if value:
                values.append(value)
    return tuple(values)


def node_to_data(node: Node | None) -> object | None:
    if node is None:
        return None
    if isinstance(node, ScalarNode):
        return node.value
    if isinstance(node, SequenceNode):
        return [node_to_data(item) for item in node.value]
    if isinstance(node, MappingNode):
        data: dict[str, object | None] = {}
        for key_node, value_node in node.value:
            key = scalar_value(key_node)
            if key is not None:
                data[key] = node_to_data(value_node)
        return data
    return None


def scalar_field(
    fields: dict[str, tuple[Node, int]], key: str, default: str | None = None
) -> str | None:
    pair = fields.get(key)
    if pair is None:
        return default
    value = scalar_value(pair[0])
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def mapping_field(
    fields: dict[str, tuple[Node, int]], key: str
) -> tuple[MappingNode, int] | None:
    pair = fields.get(key)
    if pair is None or not isinstance(pair[0], MappingNode):
        return None
    return pair[0], pair[1]


def sequence_field(
    fields: dict[str, tuple[Node, int]], key: str
) -> tuple[SequenceNode, int] | None:
    pair = fields.get(key)
    if pair is None or not isinstance(pair[0], SequenceNode):
        return None
    return pair[0], pair[1]


def document_metadata_name_namespace(
    document_fields: dict[str, tuple[Node, int]],
) -> tuple[str, str | None]:
    metadata_pair = mapping_field(document_fields, "metadata")
    if metadata_pair is None:
        return "<unnamed>", None

    metadata_fields = mapping_fields(metadata_pair[0])
    name = scalar_field(metadata_fields, "name", "<unnamed>") or "<unnamed>"
    namespace = scalar_field(metadata_fields, "namespace")
    return name, namespace


def kustomization_path_for_directory(directory: Path) -> Path | None:
    for filename in KUSTOMIZATION_FILENAMES:
        candidate = directory / filename
        if candidate.is_file():
            return candidate
    return None


def kustomization_namespace(path: Path) -> str | None:
    try:
        with path.open(encoding="utf-8") as handle:
            documents = list(yaml.safe_load_all(handle))
    except (OSError, yaml.YAMLError) as exc:
        raise GuardUsageError(f"failed to parse {path}: {exc}") from exc

    for document in documents:
        if not isinstance(document, dict):
            continue
        if document.get("kind") != "Kustomization":
            continue
        namespace = document.get("namespace")
        if isinstance(namespace, str) and namespace.strip():
            return namespace.strip()
    return None


def nearest_kustomization_namespace(path: Path) -> str | None:
    for directory in (path.parent, *path.parent.parents):
        kustomization_path = kustomization_path_for_directory(directory)
        if kustomization_path is None:
            continue
        namespace = kustomization_namespace(kustomization_path)
        if namespace is not None:
            return namespace
    return None


def effective_document_namespace(
    document_fields: dict[str, tuple[Node, int]], path: Path
) -> tuple[str, str | None]:
    name, namespace = document_metadata_name_namespace(document_fields)
    return name, namespace or nearest_kustomization_namespace(path)


def kustomization_resource_entries(path: Path) -> tuple[str, ...]:
    try:
        with path.open(encoding="utf-8") as handle:
            documents = list(yaml.safe_load_all(handle))
    except (OSError, yaml.YAMLError) as exc:
        raise GuardUsageError(f"failed to parse {path}: {exc}") from exc

    resources: list[str] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        if document.get("kind") != "Kustomization":
            continue
        document_resources = document.get("resources")
        if not isinstance(document_resources, list):
            continue
        for resource in document_resources:
            if isinstance(resource, str) and resource.strip():
                resources.append(resource.strip())
    return tuple(resources)


def kustomization_resource_targets(
    directory: Path, resources: tuple[str, ...]
) -> set[Path]:
    targets: set[Path] = set()
    for resource in resources:
        if "://" in resource:
            continue
        targets.add((directory / resource).resolve())
    return targets


def normalize_whitespace(value: str) -> str:
    return " ".join(value.split())


def first_party_startswith_terms() -> str:
    return " ||\n      ".join(
        f"c.image.startsWith('{prefix}')" for prefix in FIRST_PARTY_IMAGE_PREFIXES
    )


def canonical_first_party_match_expression() -> str:
    terms = first_party_startswith_terms()
    container_clauses = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        container_clauses.append(
            f"(has(object.spec.{field}) && object.spec.{field}.exists(c,\n"
            f"      {terms}))"
        )
    return "object != null && (\n  " + " ||\n  ".join(container_clauses) + "\n)"


def canonical_first_party_match_expression_normalized() -> str:
    return normalize_whitespace(canonical_first_party_match_expression())


def canonical_attestors_for(org_glob: str) -> object:
    # node_to_data returns raw scalar strings, so booleans are the strings "false".
    attestor = CANONICAL_FIRST_PARTY_ATTESTORS[org_glob]
    return [
        {
            "entries": [
                {
                    "keyless": {
                        "issuer": attestor["issuer"],
                        "subjectRegExp": attestor["subjectRegExp"],
                        "roots": FULCIO_ROOTS_PEM,
                        "rekor": {"ignoreTlog": "false", "pubkey": REKOR_PUBKEY_PEM},
                        "ctlog": {"ignoreSCT": "false", "pubkey": CTFE_PUBKEY_PEM},
                    }
                }
            ]
        }
    ]


def extract_match_conditions(
    webhook_fields: dict[str, tuple[Node, int]]
) -> tuple[MatchCondition, ...]:
    match_conditions_pair = sequence_field(webhook_fields, "matchConditions")
    if match_conditions_pair is None:
        return ()

    conditions: list[MatchCondition] = []
    for condition in match_conditions_pair[0].value:
        if not isinstance(condition, MappingNode):
            continue
        condition_fields = mapping_fields(condition)
        expression = scalar_field(condition_fields, "expression")
        if expression is None:
            continue
        conditions.append(
            MatchCondition(
                name=scalar_field(condition_fields, "name"),
                expression=expression,
                line=node_line(condition),
            )
        )
    return tuple(conditions)


def extract_policy_from_document(document: Node, path: Path) -> PolicyDocument | None:
    if not isinstance(document, MappingNode):
        return None

    document_fields = mapping_fields(document)
    api_version = scalar_field(document_fields, "apiVersion")
    kind = scalar_field(document_fields, "kind")
    if (
        api_version is None
        or not api_version.startswith("kyverno.io/")
        or kind not in KYVERNO_POLICY_KINDS
    ):
        return None

    metadata_pair = mapping_field(document_fields, "metadata")
    metadata_fields = mapping_fields(metadata_pair[0]) if metadata_pair is not None else {}
    name = scalar_field(metadata_fields, "name", "<unnamed>") or "<unnamed>"
    annotations_pair = mapping_field(metadata_fields, "annotations")
    annotation_fields = (
        mapping_fields(annotations_pair[0]) if annotations_pair is not None else {}
    )
    autogen_controllers = scalar_field(
        annotation_fields, AUTOGEN_CONTROLLERS_ANNOTATION
    )

    spec_pair = mapping_field(document_fields, "spec")
    if spec_pair is None:
        return None

    spec_fields = mapping_fields(spec_pair[0])
    background = scalar_field(spec_fields, "background")
    policy_action = scalar_field(spec_fields, "validationFailureAction", "Audit")
    webhook_pair = mapping_field(spec_fields, "webhookConfiguration")
    webhook_fields = mapping_fields(webhook_pair[0]) if webhook_pair is not None else {}
    failure_policy = scalar_field(webhook_fields, "failurePolicy")
    match_conditions = extract_match_conditions(webhook_fields)
    rules_pair = sequence_field(spec_fields, "rules")
    if rules_pair is None:
        return PolicyDocument(
            name=name,
            kind=kind,
            path=path,
            line=node_line(document),
            background=background,
            autogen_controllers=autogen_controllers,
            failure_policy=failure_policy,
            match_conditions=match_conditions,
            verify_images_blocks=(),
            has_mutate_rules=False,
        )

    blocks: list[VerifyImagesBlock] = []
    has_mutate_rules = False
    for rule in rules_pair[0].value:
        if not isinstance(rule, MappingNode):
            continue
        rule_fields = mapping_fields(rule)
        rule_name = scalar_field(rule_fields, "name", "<unnamed>") or "<unnamed>"
        rule_match_pair = mapping_field(rule_fields, "match")
        rule_match = (
            node_to_data(rule_match_pair[0]) if rule_match_pair is not None else None
        )
        rule_match_line = rule_match_pair[1] if rule_match_pair is not None else None
        rule_exclude_line = (
            rule_fields["exclude"][1] if "exclude" in rule_fields else None
        )
        rule_preconditions_line = (
            rule_fields["preconditions"][1]
            if "preconditions" in rule_fields
            else None
        )
        if "mutate" in rule_fields:
            has_mutate_rules = True
        verify_images_pair = rule_fields.get("verifyImages")
        if verify_images_pair is None or not isinstance(
            verify_images_pair[0], SequenceNode
        ):
            continue

        for block in verify_images_pair[0].value:
            if not isinstance(block, MappingNode):
                continue
            block_fields = mapping_fields(block)
            image_references = string_list(
                block_fields.get("imageReferences", (None, 0))[0]
            )
            skip_image_references_pair = block_fields.get("skipImageReferences")
            skip_image_references = string_list(
                skip_image_references_pair[0]
                if skip_image_references_pair is not None
                else None
            )
            skip_image_references_line = (
                skip_image_references_pair[1]
                if skip_image_references_pair is not None
                else None
            )
            action = scalar_field(block_fields, "failureAction", policy_action)
            required = scalar_field(block_fields, "required")
            attestors = node_to_data(block_fields.get("attestors", (None, 0))[0])
            blocks.append(
                VerifyImagesBlock(
                    image_references=image_references,
                    skip_image_references=skip_image_references,
                    skip_image_references_line=skip_image_references_line,
                    action=action or "Audit",
                    required=required,
                    attestors=attestors,
                    path=path,
                    line=node_line(block),
                    policy_name=name,
                    rule_name=rule_name,
                    rule_line=node_line(rule),
                    rule_match=rule_match,
                    rule_match_line=rule_match_line,
                    rule_exclude_line=rule_exclude_line,
                    rule_preconditions_line=rule_preconditions_line,
                )
            )
    return PolicyDocument(
        name=name,
        kind=kind,
        path=path,
        line=node_line(document),
        background=background,
        autogen_controllers=autogen_controllers,
        failure_policy=failure_policy,
        match_conditions=match_conditions,
        verify_images_blocks=tuple(blocks),
        has_mutate_rules=has_mutate_rules,
    )


def extract_kyverno_default_registry(
    document: Node, path: Path
) -> KyvernoDefaultRegistrySetting | None:
    if not isinstance(document, MappingNode):
        return None

    document_fields = mapping_fields(document)
    api_version = scalar_field(document_fields, "apiVersion")
    kind = scalar_field(document_fields, "kind")
    if (
        api_version is None
        or not api_version.startswith("helm.toolkit.fluxcd.io/")
        or kind != "HelmRelease"
    ):
        return None

    name, namespace = document_metadata_name_namespace(document_fields)
    if name != "kyverno" or namespace != "kyverno":
        return None

    spec_pair = mapping_field(document_fields, "spec")
    if spec_pair is None:
        return None
    spec_fields = mapping_fields(spec_pair[0])
    values_pair = mapping_field(spec_fields, "values")
    if values_pair is None:
        return None
    values_fields = mapping_fields(values_pair[0])
    config_pair = mapping_field(values_fields, "config")
    if config_pair is None:
        return None
    config_fields = mapping_fields(config_pair[0])
    default_registry_pair = config_fields.get("defaultRegistry")
    if default_registry_pair is None:
        return None
    default_registry = scalar_value(default_registry_pair[0])
    if default_registry is None:
        default_registry = ""
    return KyvernoDefaultRegistrySetting(
        path=path,
        line=default_registry_pair[1],
        value=default_registry.strip(),
    )


def parse_yaml_file(
    path: Path,
) -> tuple[list[ImageRef], list[PolicyDocument], list[KyvernoDefaultRegistrySetting]]:
    try:
        with path.open(encoding="utf-8") as handle:
            documents = list(yaml.compose_all(handle, Loader=yaml.SafeLoader))
    except (OSError, yaml.YAMLError) as exc:
        raise GuardUsageError(f"failed to parse {path}: {exc}") from exc

    refs: list[ImageRef] = []
    policies: list[PolicyDocument] = []
    kyverno_default_registry_settings: list[KyvernoDefaultRegistrySetting] = []
    for document in documents:
        if document is None:
            continue
        document_fields = mapping_fields(document) if isinstance(document, MappingNode) else {}
        _name, namespace = effective_document_namespace(document_fields, path)
        refs.extend(extract_refs_from_node(document, path, namespace))
        policy = extract_policy_from_document(document, path)
        if policy is not None:
            policies.append(policy)
        default_registry = extract_kyverno_default_registry(document, path)
        if default_registry is not None:
            kyverno_default_registry_settings.append(default_registry)
    return refs, policies, kyverno_default_registry_settings


def is_first_party(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in FIRST_PARTY_IMAGE_PREFIXES)


def is_first_party_image_reference(image_reference: str) -> bool:
    return any(
        image_reference.startswith(prefix) for prefix in FIRST_PARTY_IMAGE_PREFIXES
    )


def org_probe(org_glob: str) -> str:
    if not org_glob.endswith("*"):
        raise ValueError(f"first-party org glob must end with '*': {org_glob}")
    return f"{org_glob[:-1]}__enforce_probe__"


def block_covers(block: VerifyImagesBlock, image_name: str) -> bool:
    matched = any(
        fnmatch.fnmatch(image_name, image_glob)
        for image_glob in block.image_references
    )
    if not matched:
        return False
    return not any(
        fnmatch.fnmatch(image_name, skip_glob)
        for skip_glob in block.skip_image_references
    )


def find_violations(
    first_party_refs: list[ImageRef],
    policies: list[PolicyDocument],
    enforce_blocks: list[VerifyImagesBlock],
    kyverno_default_registry_settings: list[KyvernoDefaultRegistrySetting],
) -> list[str]:
    findings: list[str] = []
    if not enforce_blocks:
        findings.append(
            "no first-party image-signature policy with failureAction: "
            f"{FIRST_PARTY_ENFORCEMENT_MODE} found"
        )

    canonical_expression = canonical_first_party_match_expression_normalized()
    enforce_policies = [
        policy
        for policy in policies
        if policy.name == FIRST_PARTY_ENFORCED_POLICY_NAME
        and any(
            block.action == FIRST_PARTY_ENFORCEMENT_MODE
            for block in policy.verify_images_blocks
        )
    ]

    image_signature_policies = {
        policy.name: policy
        for policy in policies
        if policy.name in IMAGE_SIGNATURE_POLICY_NAMES
    }
    for policy_name in IMAGE_SIGNATURE_POLICY_NAMES:
        policy = image_signature_policies.get(policy_name)
        if policy is None:
            findings.append(f"image-signature ClusterPolicy {policy_name} not found")
            continue

        policy_ref = f"{display_path(policy.path)}:{policy.line} ({policy.name})"
        if policy.background != "true":
            found = policy.background if policy.background is not None else "<unset>"
            findings.append(
                f"image-signature ClusterPolicy must set spec.background: true: "
                f"{policy_ref} (found {found})"
            )
        if policy.autogen_controllers != AUTOGEN_CONTROLLERS_VALUE:
            found = (
                policy.autogen_controllers
                if policy.autogen_controllers is not None
                else "<unset>"
            )
            findings.append(
                "image-signature ClusterPolicy must set metadata.annotations["
                f"{AUTOGEN_CONTROLLERS_ANNOTATION}]: "
                f"{AUTOGEN_CONTROLLERS_VALUE}: {policy_ref} (found {found})"
            )

    for policy in enforce_policies:
        policy_ref = f"{display_path(policy.path)}:{policy.line} ({policy.name})"
        if policy.failure_policy != FIRST_PARTY_REQUIRED_FAILURE_POLICY:
            found = policy.failure_policy if policy.failure_policy is not None else "<unset>"
            findings.append(
                "first-party verifyImages policy must set "
                "webhookConfiguration.failurePolicy: "
                f"{FIRST_PARTY_REQUIRED_FAILURE_POLICY}: {policy_ref} "
                f"(found {found})"
            )

        if len(policy.match_conditions) != 1:
            findings.append(
                "Enforce verifyImages policy must declare exactly one "
                f"matchCondition with the canonical first-party expression: "
                f"{policy_ref} (found {len(policy.match_conditions)})"
            )
        else:
            condition = policy.match_conditions[0]
            if condition.name != FIRST_PARTY_MATCH_CONDITION_NAME:
                found = condition.name if condition.name is not None else "<unset>"
                findings.append(
                    "Enforce verifyImages policy matchCondition has unexpected "
                    f"name: {display_path(policy.path)}:{condition.line} "
                    f"(found {found})"
                )
            if normalize_whitespace(condition.expression) != canonical_expression:
                findings.append(
                    "Enforce verifyImages policy matchConditions expression "
                    "does not exactly match the canonical first-party Pod CEL: "
                    f"{display_path(policy.path)}:{condition.line} ({policy.name})"
                )

    for block in enforce_blocks:
        block_ref = (
            f"{display_path(block.path)}:{block.line} "
            f"({block.policy_name}/{block.rule_name})"
        )
        for skip_image_reference in block.skip_image_references:
            line = block.skip_image_references_line or block.line
            findings.append(
                "Enforce verifyImages block must not declare "
                "skipImageReferences: "
                f"{display_path(block.path)}:{line} "
                f"({block.policy_name}/{block.rule_name}: "
                f"{skip_image_reference})"
            )

        if block.required != "true":
            found = block.required if block.required is not None else "<unset>"
            findings.append(
                f"Enforce verifyImages block must set required: true: "
                f"{block_ref} (found {found})"
            )

        if block.rule_exclude_line is not None:
            findings.append(
                "Enforce verifyImages rule must not declare rule-level exclude: "
                f"{display_path(block.path)}:{block.rule_exclude_line} "
                f"({block.policy_name}/{block.rule_name})"
            )
        if block.rule_preconditions_line is not None:
            findings.append(
                "Enforce verifyImages rule must not declare preconditions: "
                f"{display_path(block.path)}:{block.rule_preconditions_line} "
                f"({block.policy_name}/{block.rule_name})"
            )
        if block.rule_match != EXPECTED_ENFORCE_RULE_MATCH:
            line = block.rule_match_line or block.rule_line
            findings.append(
                "Enforce verifyImages rule match must exactly equal the "
                "unnarrowed Pod form match.any[].resources.kinds == ['Pod']: "
                f"{display_path(block.path)}:{line} "
                f"({block.policy_name}/{block.rule_name})"
            )

        for image_reference in block.image_references:
            if image_reference not in FIRST_PARTY_ORG_GLOBS:
                findings.append(
                    "Enforce verifyImages imageReferences entry is outside "
                    "FIRST_PARTY_ORG_GLOBS: "
                    f"{display_path(block.path)}:{block.line} "
                    f"({block.policy_name}: {image_reference})"
                )
                continue

            if block.attestors != canonical_attestors_for(image_reference):
                findings.append(
                    "Enforce verifyImages attestors must exactly match the "
                    "guard canonical offline keyless issuer/subjectRegExp/roots/rekor.pubkey/ctlog.pubkey "
                    f"triple for {image_reference}: {block_ref}"
                )

    for policy in policies:
        if policy.failure_policy == "Ignore":
            continue
        if not policy.has_mutate_rules and not policy.verify_images_blocks:
            continue
        if policy.match_conditions:
            continue
        findings.append(
            "failurePolicy: Fail/default-Fail policy with mutate or verifyImages "
            "rules must declare non-empty matchConditions to avoid Kyverno's "
            "shared cluster-wide fail webhook: "
            f"{display_path(policy.path)}:{policy.line} ({policy.name})"
        )

    for org_glob in FIRST_PARTY_ORG_GLOBS:
        probe = org_probe(org_glob)
        if not any(block_covers(block, probe) for block in enforce_blocks):
            findings.append(
                f"first-party org {org_glob} has no "
                f"{FIRST_PARTY_ENFORCEMENT_MODE} signature rule"
            )

    for ref in sorted(first_party_refs, key=lambda item: (display_path(item.path), item.line)):
        if not any(block_covers(block, ref.name) for block in enforce_blocks):
            findings.append(
                "first-party image not signature-covered "
                f"({FIRST_PARTY_ENFORCEMENT_MODE}): "
                f"{display_path(ref.path)}:{ref.line} ({ref.name})"
            )

        if ref.namespace in KYVERNO_EXEMPTION_SURFACE_NAMESPACES:
            findings.append(
                "first-party image is declared in a Kyverno-exempt "
                f"namespace ({ref.namespace}): "
                f"{display_path(ref.path)}:{ref.line} ({ref.name})"
            )

    for setting in kyverno_default_registry_settings:
        if setting.value != KYVERNO_DEFAULT_REGISTRY:
            findings.append(
                "Kyverno HelmRelease config.defaultRegistry must remain "
                f"{KYVERNO_DEFAULT_REGISTRY}: "
                f"{display_path(setting.path)}:{setting.line} "
                f"(found {setting.value or '<empty>'})"
            )

    return findings


def policy_resource_membership_findings(
    policies: list[PolicyDocument],
) -> list[str]:
    findings: list[str] = []
    policy_paths_by_directory: dict[Path, list[PolicyDocument]] = {}
    for policy in policies:
        policy_paths_by_directory.setdefault(policy.path.parent, []).append(policy)

    for directory, directory_policies in sorted(
        policy_paths_by_directory.items(), key=lambda item: display_path(item[0])
    ):
        kustomization_path = kustomization_path_for_directory(directory)
        unique_policy_paths = {
            policy.path: policy.line for policy in directory_policies
        }
        if kustomization_path is None:
            for policy_path, line in sorted(
                unique_policy_paths.items(), key=lambda item: display_path(item[0])
            ):
                findings.append(
                    "Kyverno policy file is in a directory without a "
                    "kustomization.yaml resources list: "
                    f"{display_path(policy_path)}:{line}"
                )
            continue

        resource_targets = kustomization_resource_targets(
            directory, kustomization_resource_entries(kustomization_path)
        )
        for policy_path, line in sorted(
            unique_policy_paths.items(), key=lambda item: display_path(item[0])
        ):
            if policy_path.resolve() in resource_targets:
                continue
            findings.append(
                "Kyverno policy file is not listed in its directory "
                "kustomization.yaml resources: "
                f"{display_path(policy_path)}:{line} "
                f"(kustomization: {display_path(kustomization_path)})"
            )

    return findings


def evaluate_roots(roots: Iterable[Path]) -> GuardResult:
    assert_first_party_attestor_constants_consistent()

    paths = iter_yaml_paths(roots)
    refs: list[ImageRef] = []
    policies: list[PolicyDocument] = []
    kyverno_default_registry_settings: list[KyvernoDefaultRegistrySetting] = []
    for path in paths:
        path_refs, path_policies, path_default_registry_settings = parse_yaml_file(path)
        refs.extend(path_refs)
        policies.extend(path_policies)
        kyverno_default_registry_settings.extend(path_default_registry_settings)

    first_party_refs = [ref for ref in refs if is_first_party(ref.name)]
    verify_images_blocks = [
        block for policy in policies for block in policy.verify_images_blocks
    ]
    enforce_blocks = [
        block
        for block in verify_images_blocks
        if block.action == FIRST_PARTY_ENFORCEMENT_MODE
        and block.policy_name == FIRST_PARTY_ENFORCED_POLICY_NAME
    ]
    findings = find_violations(
        first_party_refs,
        policies,
        enforce_blocks,
        kyverno_default_registry_settings,
    )
    findings.extend(policy_resource_membership_findings(policies))
    return GuardResult(
        paths=paths,
        refs=refs,
        first_party_refs=first_party_refs,
        policies=policies,
        verify_images_blocks=verify_images_blocks,
        enforce_blocks=enforce_blocks,
        kyverno_default_registry_settings=kyverno_default_registry_settings,
        findings=findings,
    )


def exit_code_for_findings(findings: list[str]) -> int:
    return 1 if findings else 0


def print_findings(findings: list[str]) -> None:
    for finding in findings:
        print(f"ERROR: {finding}", file=sys.stderr)


def print_pass(result: GuardResult) -> None:
    print(
        f"PASS: {len(result.first_party_refs)} first-party image refs covered "
        f"by {FIRST_PARTY_ENFORCEMENT_MODE} signature rules; "
        f"{len(FIRST_PARTY_ORG_GLOBS)} first-party orgs "
        f"{FIRST_PARTY_ENFORCEMENT_MODE}-locked across "
        f"{len(result.paths)} YAML files."
    )
    print("Covered first-party image refs:")
    for ref in sorted(
        result.first_party_refs, key=lambda item: (display_path(item.path), item.line)
    ):
        print(
            f"  - {display_path(ref.path)}:{ref.line} "
            f"({ref.source}: {ref.name})"
        )
    print(f"{FIRST_PARTY_ENFORCEMENT_MODE}-locked first-party org globs:")
    for org_glob in FIRST_PARTY_ORG_GLOBS:
        print(f"  - {org_glob}")


def main() -> int:
    args = parse_args()
    roots = tuple(args.roots) if args.roots else DEFAULT_ROOTS

    try:
        result = evaluate_roots(roots)
    except GuardUsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if result.findings:
        print_findings(result.findings)
        return exit_code_for_findings(result.findings)

    print_pass(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
