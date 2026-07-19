#!/usr/bin/env python3
"""Fail if first-party GHCR images are not signature-verified by Kyverno.

This guard scans raw YAML files under the configured roots, including standalone
trees such as apps/vault/restore-drill/ that are intentionally not rendered by
Flux validation.

The required verifyImages action is parameterized by FIRST_PARTY_ENFORCEMENT_MODE
(``Audit`` — see that constant). NOTE: several finding strings below say "Enforce
verifyImages ..." literally; that is fixed shorthand for "the first-party
signature rules", NOT a claim about the current mode. Only the checks that compare
against FIRST_PARTY_ENFORCEMENT_MODE track the mode. That legacy ClusterPolicy is NOT waiting on a Kyverno upgrade: the
offline keyless pins that were its original blocker landed in #333, and
first-party enforcement now runs on one merged ImageValidatingPolicy resource
instead. The legacy policy therefore stays non-blocking and guard-pinned until
the retire-legacy PR (PR-C2) removes it outright — it is not slated to return to
``Enforce``.

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
- Discover the single merged ``ImageValidatingPolicy`` (IVP) resource that
  carries first-party signature verification on the ADMISSION path and require it
  to pin the canonical offline attestors, admission+background evaluation,
  first-party CEL scoping, all org matchImageReferences globs, explicit autogen
  coverage, and the effective IVP_VALIDATION_ACTION. See the IVP constants block
  for why enforcement migrated off the legacy verifyImages ClusterPolicy.
- Reject fail-closed mutate/verifyImages policies (and Fail IVPs) with empty
  matchConditions because Kyverno places them in the shared cluster-wide fail
  webhook.
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
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import date
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


def first_party_glob_prefixes_longest_first(globs: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted((glob[:-1] for glob in globs), key=len, reverse=True))


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
# Offline keyless verification pins (Sigstore public-good keys). rekor.url is KEPT
# (Kyverno v1.18.2 rejects a keyless attestor without a non-empty rekor.url) but with
# a pinned pubkey + the embedded bundle it is a runtime DEAD FALLBACK, so verification
# is offline. The enforced policy verifies the embedded cosign bundle SET
# against REKOR_PUBKEY_PEM (no online Rekor GET), the Fulcio leaf chain against
# FULCIO_ROOTS_PEM (Sigstore root+intermediate), and the Fulcio SCT against
# CTFE_PUBKEY_PEM; ignoreTlog/ignoreSCT stay false so both log proofs are checked
# offline. These MUST stay byte-identical to the PEMs inlined in
# verify-image-signatures-enforced.yaml (this guard exact-matches them). Rotation is
# watched by scripts/check-sigstore-pin-verification.py (#334, BUILT and
# CI-wired). Note it inspects the legacy ClusterPolicy only — a sound proxy,
# since these same four pins are byte-identical in the merged verify-first-party
# IVP. There is NO pending Enforce flip for the legacy policy: it is retired by
# PR-C2. Sources: Sigstore TUF trusted_root targets rekor.pub / ctfe_2022.pub /
# fulcio_v1.crt.pem + fulcio_intermediate_v1.crt.pem.
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
# Schema-required (Kyverno rejects an empty rekor.url); a runtime dead fallback given
# the pinned pubkey + embedded bundle. Pinned so it cannot be repointed to a rogue log.
REKOR_URL = "https://rekor.sigstore.dev"

# OFFLINE-PINS re-arm (2026-07-17). The online-Rekor dependency that BRICKED first-party
# pod creation (Vault + the hwg tenant) on 2026-07-14 is REMOVED: the canonical attestors
# above verify keyless signatures OFFLINE against the pinned Sigstore keys (rekor.pubkey +
# ctlog.pubkey + Fulcio roots), no admission-path online GET. This LEGACY ClusterPolicy's
# rules stay non-blocking (failureAction Audit + failurePolicy Ignore) permanently.
# First-party admission verification moved to the merged ImageValidatingPolicy,
# currently canaried at [Audit]/failurePolicy:Ignore; its steady-state follow-up
# posture is [Deny]/failurePolicy:Fail. First-party blocking enforcement is NOT here.
# This guard fully verifies the rule SHAPE (canonical offline attestors,
# matchConditions, first-party scoping, background, exempt-ns, required, no
# skip/exclude/preconditions) and pins the offline material.
# ⚠️ DO NOT flip the two constants below to Enforce/Fail. This header previously instructed
# exactly that; re-arming the legacy verifyImages path is what BRICKED the cluster in #335
# (its mutating image-verification never runs under fine-grained webhooks, so every signed
# first-party pod is denied). The legacy policy is RETIRED by PR-C2, not restored.
# See vault_live_admin_lockout / cp1_offline_verify_decision.
FIRST_PARTY_ENFORCEMENT_MODE = "Audit"  # legacy policy: retire via PR-C2, not restore
FIRST_PARTY_REQUIRED_FAILURE_POLICY = "Ignore"  # legacy policy: retire via PR-C2, not restore
# The dedicated first-party signature policy. Scoping the first-party checks by
# this name (not just the action) keeps the third-party Audit policy
# (verify-image-signatures) out of the first-party checks, since this legacy
# first-party policy is also Audit (permanently — see the header above).
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
KUSTOMIZATION_KINDS = {"Kustomization", "Component"}
KUSTOMIZATION_WALKED_ENTRY_FIELDS = ("resources", "bases", "components")
KUSTOMIZATION_UNKNOWN_GRAPH_FIELDS = (
    "generators",
    "transformers",
    "helmCharts",
    "helmChartInflationGenerator",
    "crds",
)
KUSTOMIZATION_DIRECT_UNKNOWN_GRAPH_FIELDS = (
    "configMapGenerator",
    "secretGenerator",
)
KYVERNO_POLICY_KINDS = {"ClusterPolicy", "Policy"}

# ---- ImageValidatingPolicy (IVP) first-party admission-path verification ------
# The legacy verifyImages ClusterPolicy (verify-image-signatures-enforced) CANNOT
# verify first-party images on the ADMISSION path: a Kyverno v1.18.2 dispatch bug
# (legacy verifyImages + webhookConfiguration.matchConditions miscategorizes the
# policy so the mutating image-verification webhook never runs) leaves admitted
# pods unannotated, so at Enforce the validating webhook DENIES every signed
# first-party pod -> the #335 brick of 2026-07-17 (a DIFFERENT defect from the
# 2026-07-14 brick, which was an online Rekor query on the admission hot path).
# The first-party admission-path mechanism therefore migrated to an
# ``ImageValidatingPolicy`` resource, but
# Kyverno v1.18.2 IVP still uses a mutate->annotate->validate handoff. The
# mutating webhook does the cosign signature-verification work and writes
# ``kyverno.io/image-verification-outcomes``; on Kyverno v1.18.2 the validating
# webhook does not perform the cosign signature-verification work; it evaluates
# the result read back from that annotation. At
# pkg/cel/policies/ivpol/engine/engine.go:356, "policy not evaluated" means the
# annotation has no entry keyed by this policy name, causing RuleFail and a deny
# at the IVP's steady-state fail-closed setting; during this Audit/Ignore canary
# it is non-blocking telemetry. That is the same bug class as legacy verifyImages,
# with a different annotation key suffix
# (``image-verification-outcomes`` vs ``verify-images``), so the migration did
# not escape the class.
#
# This guard pins the single merged IVP shape used for first-party admission-path
# verification. Its steady-state target is fail-closed enforcement ([Deny]/Fail),
# but the current constants intentionally pin the temporary Audit/Ignore canary:
# exactly one IVP in source and in the rendered policy set; offline
# pins byte-identical to FULCIO_ROOTS_PEM/REKOR_PUBKEY_PEM/CTFE_PUBKEY_PEM; the
# admission path enabled; first-party CEL scoping (=> a scoped fine-grained
# webhook, never the shared cluster-wide fail webhook that would brick all pod
# creation); explicit default autogen controller coverage; and full first-party
# image coverage. The old three-IVP shape exposed two Kyverno v1.18.2 defects:
# annotation clobber between policy outcome entries, and global autogen slot
# collision under the "defaults"/"cronjobs" keys. The status-controller conflict
# loop is therefore indirectly on the admission data path: through that autogen
# collision it rotates which controller-level policy is live. The legacy
# verifyImages ClusterPolicy stays non-blocking (Audit/Ignore) and guard-pinned
# until the retire-legacy PR removes it. See cp1_offline_verify_decision.
IVP_API_VERSION = "policies.kyverno.io/v1beta1"
IVP_KIND = "ImageValidatingPolicy"
# The IVP posture stays a constant-pair source of truth the YAML must match
# exactly, so a half-flip fails CI. The steady-state target is [Deny]/Fail; the
# current value is the temporary merge-cutover canary at [Audit]/Ignore.
IVP_VALIDATION_ACTION = "Audit"  # CANARY (PR-2 live-verifies the merged policy); PR-3 flips to "Deny"
IVP_REQUIRED_FAILURE_POLICY = "Ignore"  # CANARY (PR-2); PR-3 flips to "Fail"
# Forgetting this canary should turn CI red, not leave first-party admission
# non-blocking forever. Once the IVP is in steady state ([Deny]/Fail), this date
# is inert and cannot break CI after the canary is over.
IVP_CANARY_EXPIRES = "2026-08-01"
IVP_STEADY_STATE_VALIDATION_ACTION = "Deny"
IVP_STEADY_STATE_FAILURE_POLICY = "Fail"
# The unnarrowed Pod CREATE/UPDATE match (node_to_data yields raw scalar strings).
IVP_MATCH_CONSTRAINTS = {
    "resourceRules": [
        {
            "apiGroups": [""],
            "apiVersions": ["v1"],
            "operations": ["CREATE", "UPDATE"],
            "resources": ["pods"],
        }
    ]
}
FIRST_PARTY_IVP_POLICY_NAME = "verify-first-party"
FIRST_PARTY_IVP_FILENAME = "ivp-verify-first-party.yaml"
FIRST_PARTY_IVP_CREDENTIALS = ("ghcr-pull",)
FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES = (
    "ghcr.io/the-hero-wars-guys/*",
    "ghcr.io/nwarila/*",
    "ghcr.io/nwarila-platform/*",
)
FIRST_PARTY_IVP_MATCH_PREFIXES = first_party_glob_prefixes_longest_first(
    FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES
)
FIRST_PARTY_IVP_AUTOGEN_CONTROLLERS = (
    "daemonsets",
    "deployments",
    "replicasets",
    "statefulsets",
    "jobs",
    "cronjobs",
)
FIRST_PARTY_IVP_EVALUATION = {
    "admission": {"enabled": "true"},
    "background": {"enabled": "true"},
}
FIRST_PARTY_IVP_AUTOGEN = {
    "podControllers": {"controllers": list(FIRST_PARTY_IVP_AUTOGEN_CONTROLLERS)}
}
FIRST_PARTY_IVP_CREDENTIALS_STRUCTURE = {
    "secrets": list(FIRST_PARTY_IVP_CREDENTIALS)
}
FIRST_PARTY_IVP_VALIDATION_MESSAGE = (
    "first-party image failed keyless signature verification "
    "(merged ImageValidatingPolicy)"
)
# Per first-party org glob: the CEL attestor identifier used in
# spec.validations (must be a valid CEL identifier -> underscore, never the org
# slug's hyphen). The merged IVP carries all three attestors in this exact order.
FIRST_PARTY_IVP_ATTESTORS = {
    "ghcr.io/the-hero-wars-guys/*": "hwg",
    "ghcr.io/nwarila-platform/*": "nwarila_platform",
    "ghcr.io/nwarila/*": "nwarila",
}
FIRST_PARTY_IVP_ATTESTOR_ORDER = (
    "ghcr.io/the-hero-wars-guys/*",
    "ghcr.io/nwarila-platform/*",
    "ghcr.io/nwarila/*",
)
FIRST_PARTY_IVP_ALLOWED_SPEC_KEYS = (
    "validationActions",
    "failurePolicy",
    "evaluation",
    "autogen",
    "matchConstraints",
    "matchConditions",
    "matchImageReferences",
    "credentials",
    "attestors",
    "validations",
)
FIRST_PARTY_IVP_ALLOWED_METADATA_KEYS = ("name", "annotations")
FIRST_PARTY_IVP_ALLOWED_ANNOTATION_KEYS = (
    "policies.kyverno.io/title",
    "policies.kyverno.io/category",
    "policies.kyverno.io/severity",
)
FLUX_KUSTOMIZATION_API_VERSION_PREFIX = "kustomize.toolkit.fluxcd.io/"
FLUX_KUSTOMIZATION_FORBIDDEN_POLICY_FIELDS = (
    "patches",
    "patchesStrategicMerge",
    "patchesJson6902",
    "components",
    "postBuild",
    "suspend",
)
FLUX_LOCAL_REPO_SOURCE_KIND = "GitRepository"
FLUX_LOCAL_REPO_SOURCE_NAME = "flux-system"
FLUX_LOCAL_REPO_SOURCE_NAMESPACE = "flux-system"
ROOT_FLUX_KUSTOMIZATION_NAME = "flux-system"
ROOT_FLUX_KUSTOMIZATION_NAMESPACE = "flux-system"
KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME = "kyverno-policies"
KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAMESPACE = "flux-system"
KYVERNO_POLICIES_REPO_PATH = "./clusters/talos-cluster/apps/kyverno/policies"
KYVERNO_POLICIES_REPO_DIRECTORY = Path(KYVERNO_POLICIES_REPO_PATH)
KYVERNO_POLICIES_REQUIRED_PRUNE = "true"
KUBECTL_KUSTOMIZE_TIMEOUT_SECONDS = 120
KYVERNO_IVP_FREE_REMOTE_BASES = {
    "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.1/standard-install.yaml": (
        "upstream Gateway API CRD bundle, pinned by version, supplies no "
        "Kyverno policies"
    ),
}
KUSTOMIZATION_LOCAL_ENUMERATED_ENTRY_FIELDS = (
    *KUSTOMIZATION_WALKED_ENTRY_FIELDS,
    "generators",
    "transformers",
    "crds",
)
KUSTOMIZATION_RENDER_REQUIRED_GRAPH_FIELDS = (
    *KUSTOMIZATION_UNKNOWN_GRAPH_FIELDS,
    *KUSTOMIZATION_DIRECT_UNKNOWN_GRAPH_FIELDS,
)


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
class ImageValidatingPolicyDocument:
    name: str
    path: Path
    line: int
    api_version: str | None
    metadata_key_lines: tuple[tuple[str, int], ...]
    annotation_key_lines: tuple[tuple[str, int], ...]
    spec_key_lines: tuple[tuple[str, int], ...]
    validation_actions: tuple[str, ...]
    failure_policy: str | None
    evaluation: object | None
    evaluation_key_lines: tuple[tuple[str, int], ...]
    evaluation_admission_key_lines: tuple[tuple[str, int], ...]
    evaluation_background_key_lines: tuple[tuple[str, int], ...]
    evaluation_mode_present: bool
    evaluation_mode: str | None
    admission_enabled: str | None
    background_enabled: str | None
    autogen: object | None
    autogen_key_lines: tuple[tuple[str, int], ...]
    autogen_pod_controllers_key_lines: tuple[tuple[str, int], ...]
    autogen_controllers: tuple[str, ...]
    match_constraints: object | None
    match_condition_entry_count: int
    match_condition_key_lines: tuple[tuple[str, int], ...]
    match_conditions: tuple[MatchCondition, ...]
    match_image_reference_entry_count: int
    match_image_reference_key_lines: tuple[tuple[str, int], ...]
    match_image_references: tuple[str, ...]
    credentials: object | None
    credentials_key_lines: tuple[tuple[str, int], ...]
    credentials_secrets: tuple[str, ...]
    attestors: object | None
    validation_entry_count: int
    validation_key_lines: tuple[tuple[str, int], ...]
    validation_expressions: tuple[str, ...]
    validation_messages: tuple[str, ...]


@dataclass(frozen=True)
class FluxKustomizationDocument:
    name: str
    namespace: str | None
    path: Path
    line: int
    spec_path: str | None
    spec_path_line: int | None
    spec_prune: str | None
    spec_prune_line: int | None
    spec_suspend: str | None
    spec_suspend_line: int | None
    source_kind: str | None
    source_name: str | None
    source_namespace: str | None
    forbidden_field_lines: tuple[tuple[str, int], ...]
    image_rewrites: tuple[FluxImageRewrite, ...]


@dataclass(frozen=True)
class FluxRenderedImageValidatingPolicies:
    flux: FluxKustomizationDocument
    directory: Path
    ivps: list[ImageValidatingPolicyDocument]
    flux_kustomizations: list[FluxKustomizationDocument]


@dataclass(frozen=True)
class KyvernoDefaultRegistrySetting:
    path: Path
    line: int
    value: str


@dataclass(frozen=True)
class FluxImageRewrite:
    name: str
    name_line: int
    new_name: str | None
    new_name_line: int | None


@dataclass(frozen=True)
class GuardResult:
    paths: list[Path]
    refs: list[ImageRef]
    first_party_refs: list[ImageRef]
    policies: list[PolicyDocument]
    ivps: list[ImageValidatingPolicyDocument]
    flux_kustomizations: list[FluxKustomizationDocument]
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
        pass
    else:
        problems = [
            *(f"missing canonical entry for {org_glob!r}" for org_glob in missing),
            *(f"extra canonical entry for {org_glob!r}" for org_glob in extra),
        ]
        raise GuardUsageError(
            "FIRST_PARTY_ORG_GLOBS and CANONICAL_FIRST_PARTY_ATTESTORS disagree: "
            + "; ".join(problems)
        )

    for org_glob in FIRST_PARTY_ORG_GLOBS:
        if not org_glob.endswith("*"):
            raise GuardUsageError(
                f"first-party org glob must end with '*': {org_glob!r}"
            )

    match_ref_orgs = set(FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES)
    match_ref_missing = sorted(org_globs - match_ref_orgs)
    match_ref_extra = sorted(match_ref_orgs - org_globs)
    if match_ref_missing or match_ref_extra:
        problems = [
            *(
                f"missing merged IVP matchImageReferences entry for {org_glob!r}"
                for org_glob in match_ref_missing
            ),
            *(
                f"extra merged IVP matchImageReferences entry for {org_glob!r}"
                for org_glob in match_ref_extra
            ),
        ]
        raise GuardUsageError(
            "FIRST_PARTY_ORG_GLOBS and FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES "
            "disagree: " + "; ".join(problems)
        )

    expected_match_prefixes = set(
        first_party_glob_prefixes_longest_first(FIRST_PARTY_ORG_GLOBS)
    )
    match_prefixes = set(FIRST_PARTY_IVP_MATCH_PREFIXES)
    match_prefix_missing = sorted(expected_match_prefixes - match_prefixes)
    match_prefix_extra = sorted(match_prefixes - expected_match_prefixes)
    if match_prefix_missing or match_prefix_extra:
        problems = [
            *(
                f"missing merged IVP match prefix for {prefix!r}"
                for prefix in match_prefix_missing
            ),
            *(
                f"extra merged IVP match prefix for {prefix!r}"
                for prefix in match_prefix_extra
            ),
        ]
        raise GuardUsageError(
            "FIRST_PARTY_ORG_GLOBS and FIRST_PARTY_IVP_MATCH_PREFIXES "
            "disagree: " + "; ".join(problems)
        )

    ivp_orgs = set(FIRST_PARTY_IVP_ATTESTORS)
    ivp_missing = sorted(org_globs - ivp_orgs)
    ivp_extra = sorted(ivp_orgs - org_globs)
    if ivp_missing or ivp_extra:
        problems = [
            *(f"missing IVP entry for {org_glob!r}" for org_glob in ivp_missing),
            *(f"extra IVP entry for {org_glob!r}" for org_glob in ivp_extra),
        ]
        raise GuardUsageError(
            "FIRST_PARTY_ORG_GLOBS and FIRST_PARTY_IVP_ATTESTORS disagree: "
            + "; ".join(problems)
        )

    attestor_order_orgs = set(FIRST_PARTY_IVP_ATTESTOR_ORDER)
    attestor_order_missing = sorted(ivp_orgs - attestor_order_orgs)
    attestor_order_extra = sorted(attestor_order_orgs - ivp_orgs)
    if attestor_order_missing or attestor_order_extra:
        problems = [
            *(
                f"missing IVP attestor order entry for {org_glob!r}"
                for org_glob in attestor_order_missing
            ),
            *(
                f"extra IVP attestor order entry for {org_glob!r}"
                for org_glob in attestor_order_extra
            ),
        ]
        raise GuardUsageError(
            "FIRST_PARTY_IVP_ATTESTOR_ORDER and FIRST_PARTY_IVP_ATTESTORS "
            "disagree: " + "; ".join(problems)
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan raw YAML for first-party GHCR image refs that are not covered "
            "by Kyverno verifyImages rules with the effective "
            "FIRST_PARTY_ENFORCEMENT_MODE action (Audit; the legacy policy is retired "
            "by PR-C2, not restored; current first-party IVP verification is "
            "the [Audit]/Ignore canary)."
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


def mapping_key_lines(
    fields: dict[str, tuple[Node, int]]
) -> tuple[tuple[str, int], ...]:
    return tuple((key, line) for key, (_node, line) in fields.items())


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


def kustomization_entry_values(
    path: Path,
    fields: Iterable[str],
) -> tuple[str, ...]:
    try:
        with path.open(encoding="utf-8") as handle:
            documents = list(yaml.safe_load_all(handle))
    except (OSError, yaml.YAMLError) as exc:
        raise GuardUsageError(f"failed to parse {path}: {exc}") from exc

    values: list[str] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        if document.get("kind") not in KUSTOMIZATION_KINDS:
            continue
        for field in fields:
            field_entries = document.get(field)
            if not isinstance(field_entries, list):
                continue
            for entry in field_entries:
                if isinstance(entry, str) and entry.strip():
                    values.append(entry.strip())
    return tuple(values)


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
                        "rekor": {
                            "url": REKOR_URL,
                            "ignoreTlog": "false",
                            "pubkey": REKOR_PUBKEY_PEM,
                        },
                        "ctlog": {"ignoreSCT": "false", "pubkey": CTFE_PUBKEY_PEM},
                    }
                }
            ]
        }
    ]


def canonical_ivp_match_expression() -> str:
    terms = " || ".join(
        f"c.image.startsWith('{prefix}')" for prefix in FIRST_PARTY_IVP_MATCH_PREFIXES
    )
    clauses = [
        f"(has(object.spec.{field}) && object.spec.{field}.exists(c, "
        f"{terms}))"
        for field in ("containers", "initContainers", "ephemeralContainers")
    ]
    return "object != null && (\n  " + " ||\n  ".join(clauses) + "\n)"


def canonical_ivp_match_expression_normalized() -> str:
    return normalize_whitespace(canonical_ivp_match_expression())


def canonical_ivp_validation_expression() -> str:
    dispatch_orgs = FIRST_PARTY_IVP_ATTESTOR_ORDER
    dispatch_lines = [
        f"  image.startsWith('{org_glob[:-1]}') ? "
        f"verifyImageSignatures(image, "
        f"[attestors.{FIRST_PARTY_IVP_ATTESTORS[org_glob]}]) > 0 :"
        for org_glob in dispatch_orgs[:-1]
    ]
    dispatch_lines.append(
        "  verifyImageSignatures(image, "
        f"[attestors.{FIRST_PARTY_IVP_ATTESTORS[dispatch_orgs[-1]]}]) > 0)"
    )
    dispatch = "\n".join(dispatch_lines)
    clauses = [
        f"images.{field}.all(image,\n"
        f"{dispatch}"
        for field in ("containers", "initContainers", "ephemeralContainers")
    ]
    return " &&\n".join(clauses)


def canonical_ivp_validation_expression_normalized() -> str:
    return normalize_whitespace(canonical_ivp_validation_expression())


def canonical_ivp_attestor_for(org_glob: str) -> object:
    # node_to_data returns raw scalar strings, so booleans are the strings "false".
    attestor_id = FIRST_PARTY_IVP_ATTESTORS[org_glob]
    identity = CANONICAL_FIRST_PARTY_ATTESTORS[org_glob]
    # In the IVP cosign schema ``ctlog`` is a SIBLING of ``keyless`` under
    # ``cosign`` (unlike the legacy verifyImages shape, where rekor/ctlog nest
    # inside keyless). The rekor pubkey lives at ctlog.rekorPubKey.
    return {
        "name": attestor_id,
        "cosign": {
            "keyless": {
                "identities": [
                    {
                        "issuer": identity["issuer"],
                        "subjectRegExp": identity["subjectRegExp"],
                    }
                ],
                "roots": FULCIO_ROOTS_PEM,
            },
            "ctlog": {
                "url": REKOR_URL,
                "rekorPubKey": REKOR_PUBKEY_PEM,
                "ctLogPubKey": CTFE_PUBKEY_PEM,
                "insecureIgnoreTlog": "false",
                "insecureIgnoreSCT": "false",
            },
        },
    }


def canonical_ivp_attestors() -> object:
    return [
        canonical_ivp_attestor_for(org_glob)
        for org_glob in FIRST_PARTY_IVP_ATTESTOR_ORDER
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


def extract_ivp_from_document(
    document: Node, path: Path
) -> ImageValidatingPolicyDocument | None:
    if not isinstance(document, MappingNode):
        return None

    document_fields = mapping_fields(document)
    api_version = scalar_field(document_fields, "apiVersion")
    kind = scalar_field(document_fields, "kind")
    if kind != IVP_KIND:
        return None

    metadata_pair = mapping_field(document_fields, "metadata")
    metadata_fields = mapping_fields(metadata_pair[0]) if metadata_pair is not None else {}
    metadata_key_lines = mapping_key_lines(metadata_fields)
    name = scalar_field(metadata_fields, "name", "<unnamed>") or "<unnamed>"
    annotations_pair = mapping_field(metadata_fields, "annotations")
    annotation_fields = (
        mapping_fields(annotations_pair[0]) if annotations_pair is not None else {}
    )
    annotation_key_lines = mapping_key_lines(annotation_fields)

    spec_pair = mapping_field(document_fields, "spec")
    spec_fields = mapping_fields(spec_pair[0]) if spec_pair is not None else {}
    spec_key_lines = mapping_key_lines(spec_fields)

    validation_actions_pair = sequence_field(spec_fields, "validationActions")
    validation_actions = (
        string_list(validation_actions_pair[0])
        if validation_actions_pair is not None
        else ()
    )
    failure_policy = scalar_field(spec_fields, "failurePolicy")

    evaluation_pair = mapping_field(spec_fields, "evaluation")
    evaluation = (
        node_to_data(evaluation_pair[0]) if evaluation_pair is not None else None
    )
    evaluation_fields = (
        mapping_fields(evaluation_pair[0]) if evaluation_pair is not None else {}
    )
    evaluation_key_lines = mapping_key_lines(evaluation_fields)
    evaluation_mode_pair = evaluation_fields.get("mode")
    evaluation_mode_present = evaluation_mode_pair is not None
    evaluation_mode = scalar_field(evaluation_fields, "mode")
    admission_pair = mapping_field(evaluation_fields, "admission")
    admission_fields = (
        mapping_fields(admission_pair[0]) if admission_pair is not None else {}
    )
    evaluation_admission_key_lines = mapping_key_lines(admission_fields)
    admission_enabled = scalar_field(admission_fields, "enabled")
    background_pair = mapping_field(evaluation_fields, "background")
    background_fields = (
        mapping_fields(background_pair[0]) if background_pair is not None else {}
    )
    evaluation_background_key_lines = mapping_key_lines(background_fields)
    background_enabled = scalar_field(background_fields, "enabled")

    match_constraints = node_to_data(
        spec_fields["matchConstraints"][0]
    ) if "matchConstraints" in spec_fields else None
    match_conditions_pair = sequence_field(spec_fields, "matchConditions")
    match_condition_entry_count = (
        len(match_conditions_pair[0].value)
        if match_conditions_pair is not None
        else 0
    )
    match_condition_key_lines: list[tuple[str, int]] = []
    if match_conditions_pair is not None:
        for entry in match_conditions_pair[0].value:
            if not isinstance(entry, MappingNode):
                continue
            match_condition_key_lines.extend(
                mapping_key_lines(mapping_fields(entry))
            )
    match_conditions = extract_match_conditions(spec_fields)

    autogen_controllers: tuple[str, ...] = ()
    autogen_pair = mapping_field(spec_fields, "autogen")
    autogen = node_to_data(autogen_pair[0]) if autogen_pair is not None else None
    autogen_key_lines: tuple[tuple[str, int], ...] = ()
    autogen_pod_controllers_key_lines: tuple[tuple[str, int], ...] = ()
    if autogen_pair is not None:
        autogen_fields = mapping_fields(autogen_pair[0])
        autogen_key_lines = mapping_key_lines(autogen_fields)
        pod_controllers_pair = mapping_field(autogen_fields, "podControllers")
        if pod_controllers_pair is not None:
            pod_controllers_fields = mapping_fields(pod_controllers_pair[0])
            autogen_pod_controllers_key_lines = mapping_key_lines(
                pod_controllers_fields
            )
            autogen_controllers = string_list(
                pod_controllers_fields.get("controllers", (None, 0))[0]
            )

    match_image_references: list[str] = []
    match_image_reference_key_lines: list[tuple[str, int]] = []
    match_image_references_pair = sequence_field(spec_fields, "matchImageReferences")
    match_image_reference_entry_count = (
        len(match_image_references_pair[0].value)
        if match_image_references_pair is not None
        else 0
    )
    if match_image_references_pair is not None:
        for entry in match_image_references_pair[0].value:
            if not isinstance(entry, MappingNode):
                continue
            entry_fields = mapping_fields(entry)
            match_image_reference_key_lines.extend(mapping_key_lines(entry_fields))
            glob = scalar_field(entry_fields, "glob")
            if glob:
                match_image_references.append(glob)

    credentials_secrets: tuple[str, ...] = ()
    credentials_pair = mapping_field(spec_fields, "credentials")
    credentials = (
        node_to_data(credentials_pair[0]) if credentials_pair is not None else None
    )
    credentials_key_lines: tuple[tuple[str, int], ...] = ()
    if credentials_pair is not None:
        credentials_fields = mapping_fields(credentials_pair[0])
        credentials_key_lines = mapping_key_lines(credentials_fields)
        credentials_secrets = string_list(
            credentials_fields.get("secrets", (None, 0))[0]
        )

    attestors = node_to_data(
        spec_fields["attestors"][0]
    ) if "attestors" in spec_fields else None

    validation_expressions: list[str] = []
    validation_messages: list[str] = []
    validation_key_lines: list[tuple[str, int]] = []
    validations_pair = sequence_field(spec_fields, "validations")
    validation_entry_count = (
        len(validations_pair[0].value) if validations_pair is not None else 0
    )
    if validations_pair is not None:
        for entry in validations_pair[0].value:
            if not isinstance(entry, MappingNode):
                continue
            validation_fields = mapping_fields(entry)
            validation_key_lines.extend(mapping_key_lines(validation_fields))
            expression = scalar_field(validation_fields, "expression")
            if expression is not None:
                validation_expressions.append(expression)
            message = scalar_field(validation_fields, "message")
            if message is not None:
                validation_messages.append(message)

    return ImageValidatingPolicyDocument(
        name=name,
        path=path,
        line=node_line(document),
        api_version=api_version,
        metadata_key_lines=metadata_key_lines,
        annotation_key_lines=annotation_key_lines,
        spec_key_lines=spec_key_lines,
        validation_actions=validation_actions,
        failure_policy=failure_policy,
        evaluation=evaluation,
        evaluation_key_lines=evaluation_key_lines,
        evaluation_admission_key_lines=evaluation_admission_key_lines,
        evaluation_background_key_lines=evaluation_background_key_lines,
        evaluation_mode_present=evaluation_mode_present,
        evaluation_mode=evaluation_mode,
        admission_enabled=admission_enabled,
        background_enabled=background_enabled,
        autogen=autogen,
        autogen_key_lines=autogen_key_lines,
        autogen_pod_controllers_key_lines=autogen_pod_controllers_key_lines,
        autogen_controllers=autogen_controllers,
        match_constraints=match_constraints,
        match_condition_entry_count=match_condition_entry_count,
        match_condition_key_lines=tuple(match_condition_key_lines),
        match_conditions=match_conditions,
        match_image_reference_entry_count=match_image_reference_entry_count,
        match_image_reference_key_lines=tuple(match_image_reference_key_lines),
        match_image_references=tuple(match_image_references),
        credentials=credentials,
        credentials_key_lines=credentials_key_lines,
        credentials_secrets=credentials_secrets,
        attestors=attestors,
        validation_entry_count=validation_entry_count,
        validation_key_lines=tuple(validation_key_lines),
        validation_expressions=tuple(validation_expressions),
        validation_messages=tuple(validation_messages),
    )


def extract_flux_kustomization_from_document(
    document: Node, path: Path
) -> FluxKustomizationDocument | None:
    if not isinstance(document, MappingNode):
        return None

    document_fields = mapping_fields(document)
    api_version = scalar_field(document_fields, "apiVersion")
    kind = scalar_field(document_fields, "kind")
    if (
        api_version is None
        or not api_version.startswith(FLUX_KUSTOMIZATION_API_VERSION_PREFIX)
        or kind != "Kustomization"
    ):
        return None

    metadata_pair = mapping_field(document_fields, "metadata")
    metadata_fields = mapping_fields(metadata_pair[0]) if metadata_pair is not None else {}
    name = scalar_field(metadata_fields, "name", "<unnamed>") or "<unnamed>"
    namespace = scalar_field(metadata_fields, "namespace")

    spec_pair = mapping_field(document_fields, "spec")
    spec_fields = mapping_fields(spec_pair[0]) if spec_pair is not None else {}
    spec_path_pair = spec_fields.get("path")
    spec_path = scalar_field(spec_fields, "path")
    spec_path_line = spec_path_pair[1] if spec_path_pair is not None else None
    spec_prune_pair = spec_fields.get("prune")
    spec_prune = scalar_field(spec_fields, "prune")
    spec_prune_line = spec_prune_pair[1] if spec_prune_pair is not None else None
    spec_suspend_pair = spec_fields.get("suspend")
    spec_suspend = scalar_field(spec_fields, "suspend")
    spec_suspend_line = spec_suspend_pair[1] if spec_suspend_pair is not None else None

    source_kind = None
    source_name = None
    source_namespace = None
    source_ref_pair = mapping_field(spec_fields, "sourceRef")
    if source_ref_pair is not None:
        source_ref_fields = mapping_fields(source_ref_pair[0])
        source_kind = scalar_field(source_ref_fields, "kind")
        source_name = scalar_field(source_ref_fields, "name")
        source_namespace = scalar_field(source_ref_fields, "namespace")

    forbidden_field_lines = tuple(
        (field, spec_fields[field][1])
        for field in FLUX_KUSTOMIZATION_FORBIDDEN_POLICY_FIELDS
        if field in spec_fields
    )

    image_rewrites: list[FluxImageRewrite] = []
    images_pair = sequence_field(spec_fields, "images")
    if images_pair is not None:
        for entry in images_pair[0].value:
            if not isinstance(entry, MappingNode):
                continue
            image_fields = mapping_fields(entry)
            name_pair = image_fields.get("name")
            image_name = scalar_field(image_fields, "name")
            if name_pair is None or image_name is None:
                continue
            new_name_pair = image_fields.get("newName")
            image_rewrites.append(
                FluxImageRewrite(
                    name=image_name,
                    name_line=name_pair[1],
                    new_name=scalar_field(image_fields, "newName"),
                    new_name_line=(
                        new_name_pair[1] if new_name_pair is not None else None
                    ),
                )
            )

    return FluxKustomizationDocument(
        name=name,
        namespace=namespace,
        path=path,
        line=node_line(document),
        spec_path=spec_path,
        spec_path_line=spec_path_line,
        spec_prune=spec_prune,
        spec_prune_line=spec_prune_line,
        spec_suspend=spec_suspend,
        spec_suspend_line=spec_suspend_line,
        source_kind=source_kind,
        source_name=source_name,
        source_namespace=source_namespace,
        forbidden_field_lines=forbidden_field_lines,
        image_rewrites=tuple(image_rewrites),
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


def parse_yaml_documents(
    documents: Iterable[Node | None],
    path: Path,
) -> tuple[
    list[ImageRef],
    list[PolicyDocument],
    list[ImageValidatingPolicyDocument],
    list[FluxKustomizationDocument],
    list[KyvernoDefaultRegistrySetting],
]:
    refs: list[ImageRef] = []
    policies: list[PolicyDocument] = []
    ivps: list[ImageValidatingPolicyDocument] = []
    flux_kustomizations: list[FluxKustomizationDocument] = []
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
        ivp = extract_ivp_from_document(document, path)
        if ivp is not None:
            ivps.append(ivp)
        flux_kustomization = extract_flux_kustomization_from_document(document, path)
        if flux_kustomization is not None:
            flux_kustomizations.append(flux_kustomization)
        default_registry = extract_kyverno_default_registry(document, path)
        if default_registry is not None:
            kyverno_default_registry_settings.append(default_registry)
    return (
        refs,
        policies,
        ivps,
        flux_kustomizations,
        kyverno_default_registry_settings,
    )


def parse_yaml_file(
    path: Path,
) -> tuple[
    list[ImageRef],
    list[PolicyDocument],
    list[ImageValidatingPolicyDocument],
    list[FluxKustomizationDocument],
    list[KyvernoDefaultRegistrySetting],
]:
    try:
        with path.open(encoding="utf-8") as handle:
            documents = list(yaml.compose_all(handle, Loader=yaml.SafeLoader))
    except (OSError, yaml.YAMLError) as exc:
        raise GuardUsageError(f"failed to parse {path}: {exc}") from exc

    return parse_yaml_documents(documents, path)


def is_first_party(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in FIRST_PARTY_IMAGE_PREFIXES)


def is_first_party_image_reference(image_reference: str) -> bool:
    return any(
        image_reference.startswith(prefix) for prefix in FIRST_PARTY_IMAGE_PREFIXES
    )


def matches_first_party_org_glob(name: str) -> bool:
    normalized = normalize_image_name(name)
    return any(
        fnmatch.fnmatchcase(normalized, org_glob)
        for org_glob in FIRST_PARTY_ORG_GLOBS
    )


def yaml_scalar_true(value: str | None) -> bool:
    return value is not None and value.strip().lower() == "true"


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


def ivp_covers(ivp: ImageValidatingPolicyDocument, image_name: str) -> bool:
    return any(
        fnmatch.fnmatch(image_name, glob)
        for glob in ivp.match_image_references
    )


def current_date() -> date:
    return date.today()


def ivp_is_steady_state() -> bool:
    return (
        IVP_VALIDATION_ACTION == IVP_STEADY_STATE_VALIDATION_ACTION
        and IVP_REQUIRED_FAILURE_POLICY == IVP_STEADY_STATE_FAILURE_POLICY
    )


def ivp_canary_expiry_findings(today: date | None = None) -> list[str]:
    try:
        expires = date.fromisoformat(IVP_CANARY_EXPIRES)
    except ValueError as exc:
        raise GuardUsageError(
            f"IVP_CANARY_EXPIRES must be an ISO date string: {IVP_CANARY_EXPIRES!r}"
        ) from exc

    if ivp_is_steady_state():
        return []

    today = today if today is not None else current_date()
    if today < expires:
        return []

    return [
        "ImageValidatingPolicy canary expired on "
        f"{IVP_CANARY_EXPIRES} while the guard posture is "
        f"[{IVP_VALIDATION_ACTION}]/{IVP_REQUIRED_FAILURE_POLICY}, not the "
        f"steady-state [{IVP_STEADY_STATE_VALIDATION_ACTION}]/"
        f"{IVP_STEADY_STATE_FAILURE_POLICY}. Flip verify-first-party and the "
        "guard constants to [Deny]/Fail, or consciously extend "
        "IVP_CANARY_EXPIRES with a recorded reason."
    ]


def append_unexpected_nested_key_findings(
    findings: list[str],
    ivp: ImageValidatingPolicyDocument,
    key_lines: tuple[tuple[str, int], ...],
    allowed_keys: set[str],
    yaml_path: str,
    why: str,
) -> None:
    for key, line in key_lines:
        if key in allowed_keys:
            continue
        findings.append(
            f"ImageValidatingPolicy {yaml_path} key is not guard-allowlisted "
            "and is rejected fail-closed because "
            f"{why}. Review the field's Kyverno semantics and pin it "
            "explicitly in this guard before allowing it: "
            f"{display_path(ivp.path)}:{line} ({ivp.name}) {yaml_path}.{key}"
        )


def find_ivp_violations(
    first_party_refs: list[ImageRef],
    ivps: list[ImageValidatingPolicyDocument],
    *,
    scope: str = "source policy files",
) -> list[str]:
    findings: list[str] = []

    if len(ivps) != 1:
        found = ", ".join(
            f"{display_path(ivp.path)}:{ivp.line} ({ivp.name})"
            for ivp in sorted(ivps, key=lambda item: (display_path(item.path), item.line))
        ) or "<none>"
        findings.append(
            f"{scope} must contain exactly one ImageValidatingPolicy "
            f"for first-party admission enforcement, named "
            f"{FIRST_PARTY_IVP_POLICY_NAME}: found {len(ivps)}: {found}"
        )

    merged_ivps = [ivp for ivp in ivps if ivp.name == FIRST_PARTY_IVP_POLICY_NAME]
    ivp = merged_ivps[0] if merged_ivps else None
    if ivp is None:
        findings.append(
            f"merged ImageValidatingPolicy {FIRST_PARTY_IVP_POLICY_NAME} not found"
        )

    # Brick-safety (universal): a Fail (or default-Fail) IVP with empty
    # matchConditions is placed in Kyverno's shared cluster-wide fail webhook and
    # would brick all pod creation on a Kyverno/registry outage.
    for ivp in ivps:
        effective_failure_policy = ivp.failure_policy or "Fail"
        if effective_failure_policy != "Ignore" and not ivp.match_conditions:
            findings.append(
                "failurePolicy: Fail ImageValidatingPolicy must declare non-empty "
                "matchConditions to avoid Kyverno's shared cluster-wide fail "
                f"webhook: {display_path(ivp.path)}:{ivp.line} ({ivp.name})"
            )

    if ivp is None:
        return findings

    ivp_ref = f"{display_path(ivp.path)}:{ivp.line} ({ivp.name})"

    if ivp.api_version != IVP_API_VERSION:
        found = ivp.api_version if ivp.api_version is not None else "<unset>"
        findings.append(
            "ImageValidatingPolicy apiVersion must be exactly "
            f"{IVP_API_VERSION}: {ivp_ref} (found {found})"
        )

    allowed_metadata_keys = set(FIRST_PARTY_IVP_ALLOWED_METADATA_KEYS)
    actual_metadata_keys = {key for key, _line in ivp.metadata_key_lines}
    if actual_metadata_keys != allowed_metadata_keys:
        findings.append(
            "ImageValidatingPolicy metadata keys must be exactly "
            f"{list(FIRST_PARTY_IVP_ALLOWED_METADATA_KEYS)} so metadata cannot "
            f"silently alter identity or Kyverno behavior: {ivp_ref} "
            f"(found {sorted(actual_metadata_keys)})"
        )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.metadata_key_lines,
        allowed_metadata_keys,
        "metadata",
        "unpinned metadata fields may silently alter policy identity or "
        "Kyverno behavior",
    )

    allowed_annotation_keys = set(FIRST_PARTY_IVP_ALLOWED_ANNOTATION_KEYS)
    actual_annotation_keys = {key for key, _line in ivp.annotation_key_lines}
    if actual_annotation_keys != allowed_annotation_keys:
        findings.append(
            "ImageValidatingPolicy metadata.annotations keys must be exactly "
            f"{list(FIRST_PARTY_IVP_ALLOWED_ANNOTATION_KEYS)} so annotations "
            f"cannot silently alter Kyverno policy behavior: {ivp_ref} "
            f"(found {sorted(actual_annotation_keys)})"
        )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.annotation_key_lines,
        allowed_annotation_keys,
        "metadata.annotations",
        "unpinned annotations may silently alter Kyverno policy behavior",
    )

    allowed_spec_keys = set(FIRST_PARTY_IVP_ALLOWED_SPEC_KEYS)
    for key, line in ivp.spec_key_lines:
        if key in allowed_spec_keys:
            continue
        findings.append(
            "ImageValidatingPolicy spec key is not guard-allowlisted and is "
            "rejected fail-closed because unpinned IVP spec fields may "
            "silently alter signature-verification semantics. Review the "
            "field's Kyverno semantics and pin it explicitly in this guard "
            "before allowing it: "
            f"{display_path(ivp.path)}:{line} ({ivp.name}) spec.{key}"
        )

    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.evaluation_key_lines,
        {"admission", "background"},
        "spec.evaluation",
        "unpinned evaluation fields may silently change whether signature "
        "verification runs on the admission and background paths",
    )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.evaluation_admission_key_lines,
        {"enabled"},
        "spec.evaluation.admission",
        "unpinned admission evaluation fields may silently weaken or redirect "
        "admission-path signature verification",
    )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.evaluation_background_key_lines,
        {"enabled"},
        "spec.evaluation.background",
        "unpinned background evaluation fields may silently weaken PolicyReport "
        "coverage for the canary and steady-state rollout",
    )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.autogen_key_lines,
        {"podControllers"},
        "spec.autogen",
        "unpinned autogen fields may silently change generated controller "
        "coverage and resurrect Kyverno v1.18.2 autogen-slot hazards",
    )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.autogen_pod_controllers_key_lines,
        {"controllers"},
        "spec.autogen.podControllers",
        "unpinned podControllers fields may silently narrow or broaden which "
        "controller-created Pods receive signature verification",
    )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.match_condition_key_lines,
        {"name", "expression"},
        "spec.matchConditions",
        "unpinned matchConditions fields may silently alter API-server webhook "
        "selection for first-party Pod admissions",
    )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.match_image_reference_key_lines,
        {"glob"},
        "spec.matchImageReferences",
        "unpinned matchImageReferences fields may silently broaden which images "
        "the policy claims to match; expression can bypass the pinned glob set",
    )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.credentials_key_lines,
        {"secrets"},
        "spec.credentials",
        "unpinned credentials fields may silently weaken registry verification "
        "or credential lookup; allowInsecureRegistry permits plaintext or "
        "skip-TLS registry fetches",
    )
    append_unexpected_nested_key_findings(
        findings,
        ivp,
        ivp.validation_key_lines,
        {"expression", "message"},
        "spec.validations",
        "unpinned validation fields may silently alter signature-verification "
        "semantics or operator-facing denial evidence",
    )

    if list(ivp.validation_actions) != [IVP_VALIDATION_ACTION]:
        findings.append(
            "ImageValidatingPolicy spec.validationActions must be "
            f"[{IVP_VALIDATION_ACTION}]: {ivp_ref} "
            f"(found {list(ivp.validation_actions)})"
        )

    if ivp.failure_policy != IVP_REQUIRED_FAILURE_POLICY:
        found = ivp.failure_policy if ivp.failure_policy is not None else "<unset>"
        findings.append(
            "ImageValidatingPolicy must set spec.failurePolicy: "
            f"{IVP_REQUIRED_FAILURE_POLICY}: {ivp_ref} (found {found})"
        )

    if ivp.evaluation != FIRST_PARTY_IVP_EVALUATION:
        findings.append(
            "ImageValidatingPolicy spec.evaluation must exactly equal the "
            "pinned admission/background enabled structure so unpinned "
            f"evaluation fields cannot change execution paths: {ivp_ref} "
            f"(found {ivp.evaluation})"
        )

    if ivp.evaluation_mode_present and ivp.evaluation_mode != "Kubernetes":
        found = ivp.evaluation_mode if ivp.evaluation_mode is not None else "<non-scalar>"
        findings.append(
            "ImageValidatingPolicy spec.evaluation.mode must be absent or "
            f"Kubernetes so the policy remains on the admission path: {ivp_ref} "
            f"(found {found})"
        )

    if ivp.admission_enabled != "true":
        found = (
            ivp.admission_enabled if ivp.admission_enabled is not None else "<unset>"
        )
        findings.append(
            "ImageValidatingPolicy must set "
            "spec.evaluation.admission.enabled: true (admission-path "
            f"verification is the migration's whole point): {ivp_ref} "
            f"(found {found})"
        )

    if ivp.background_enabled != "true":
        found = (
            ivp.background_enabled
            if ivp.background_enabled is not None
            else "<unset>"
        )
        findings.append(
            "ImageValidatingPolicy must set "
            f"spec.evaluation.background.enabled: true: {ivp_ref} "
            f"(found {found})"
        )

    if ivp.autogen != FIRST_PARTY_IVP_AUTOGEN:
        findings.append(
            "ImageValidatingPolicy spec.autogen must exactly equal the pinned "
            "full default podControllers structure so controller coverage cannot "
            f"silently drift: {ivp_ref} (found {ivp.autogen})"
        )

    if tuple(ivp.autogen_controllers) != FIRST_PARTY_IVP_AUTOGEN_CONTROLLERS:
        findings.append(
            "ImageValidatingPolicy spec.autogen.podControllers.controllers must "
            "preserve Kyverno's full default controller set "
            f"{list(FIRST_PARTY_IVP_AUTOGEN_CONTROLLERS)}: {ivp_ref} "
            f"(found {list(ivp.autogen_controllers)})"
        )

    if ivp.match_constraints != IVP_MATCH_CONSTRAINTS:
        findings.append(
            "ImageValidatingPolicy matchConstraints must exactly equal the "
            f"unnarrowed Pod CREATE/UPDATE form: {ivp_ref}"
        )

    if ivp.match_condition_entry_count != 1:
        findings.append(
            "ImageValidatingPolicy spec.matchConditions must contain exactly "
            f"one name/expression entry: {ivp_ref} "
            f"(found {ivp.match_condition_entry_count} entries)"
        )

    if len(ivp.match_conditions) != 1:
        findings.append(
            "ImageValidatingPolicy must declare exactly one matchCondition "
            f"with the canonical merged first-party expression: {ivp_ref} "
            f"(found {len(ivp.match_conditions)})"
        )
    else:
        condition = ivp.match_conditions[0]
        if condition.name != FIRST_PARTY_MATCH_CONDITION_NAME:
            found = condition.name if condition.name is not None else "<unset>"
            findings.append(
                "ImageValidatingPolicy matchCondition has unexpected name: "
                f"{display_path(ivp.path)}:{condition.line} ({ivp.name}) "
                f"(found {found})"
            )
        if normalize_whitespace(
            condition.expression
        ) != canonical_ivp_match_expression_normalized():
            findings.append(
                "ImageValidatingPolicy matchConditions expression does not "
                "exactly match the canonical merged first-party Pod CEL: "
                f"{display_path(ivp.path)}:{condition.line} ({ivp.name})"
            )

    if ivp.match_image_reference_entry_count != len(FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES):
        findings.append(
            "ImageValidatingPolicy matchImageReferences must contain exactly "
            "the pinned glob-only entries: "
            f"{ivp_ref} (found {ivp.match_image_reference_entry_count} entries)"
        )

    if tuple(ivp.match_image_references) != FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES:
        findings.append(
            "ImageValidatingPolicy matchImageReferences must be exactly "
            f"{list(FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES)}: {ivp_ref} "
            f"(found {list(ivp.match_image_references)})"
        )

    if ivp.credentials != FIRST_PARTY_IVP_CREDENTIALS_STRUCTURE:
        findings.append(
            "ImageValidatingPolicy spec.credentials must exactly equal the "
            "pinned ghcr-pull secrets-only structure so registry TLS and "
            f"credential-provider semantics cannot silently drift: {ivp_ref} "
            f"(found {ivp.credentials})"
        )

    if tuple(ivp.credentials_secrets) != FIRST_PARTY_IVP_CREDENTIALS:
        findings.append(
            "ImageValidatingPolicy spec.credentials.secrets must be exactly "
            f"{list(FIRST_PARTY_IVP_CREDENTIALS)}: {ivp_ref} "
            f"(found {list(ivp.credentials_secrets)})"
        )

    if ivp.attestors != canonical_ivp_attestors():
        findings.append(
            "ImageValidatingPolicy attestors must exactly match the guard "
            "canonical offline keyless "
            "identities/roots/ctlog.rekorPubKey/ctlog.ctLogPubKey triples for "
            f"all first-party orgs: {ivp_ref}"
        )

    if ivp.validation_entry_count != 1:
        findings.append(
            "ImageValidatingPolicy spec.validations must contain exactly one "
            f"expression/message entry: {ivp_ref} "
            f"(found {ivp.validation_entry_count} entries)"
        )

    actual_expressions = [
        normalize_whitespace(expression)
        for expression in ivp.validation_expressions
    ]
    if actual_expressions != [canonical_ivp_validation_expression_normalized()]:
        findings.append(
            "ImageValidatingPolicy validations must be exactly one "
            "verifyImageSignatures expression over "
            "containers/initContainers/ephemeralContainers with per-image "
            f"attestor dispatch for all first-party orgs: {ivp_ref}"
        )

    if tuple(ivp.validation_messages) != (FIRST_PARTY_IVP_VALIDATION_MESSAGE,):
        findings.append(
            "ImageValidatingPolicy validations must carry the pinned failure "
            "message so operator-facing denial evidence cannot silently drift: "
            f"{ivp_ref} (found {list(ivp.validation_messages)})"
        )

    for org_glob in FIRST_PARTY_ORG_GLOBS:
        probe = org_probe(org_glob)
        if not ivp_covers(ivp, probe):
            findings.append(
                f"first-party org {org_glob} has no ImageValidatingPolicy "
                "matchImageReferences coverage"
            )

    for ref in sorted(
        first_party_refs, key=lambda item: (display_path(item.path), item.line)
    ):
        if not ivp_covers(ivp, ref.name):
            findings.append(
                "first-party image not covered by an ImageValidatingPolicy: "
                f"{display_path(ref.path)}:{ref.line} ({ref.name})"
            )

    return findings


def kyverno_policy_directories(
    policies: list[PolicyDocument],
    ivps: list[ImageValidatingPolicyDocument],
) -> list[Path]:
    policy_dirs: dict[Path, list[PolicyDocument | ImageValidatingPolicyDocument]] = {}
    for policy in [*policies, *ivps]:
        policy_dirs.setdefault(policy.path.parent, []).append(policy)

    directories: list[Path] = []
    for directory, directory_policies in sorted(
        policy_dirs.items(), key=lambda item: display_path(item[0])
    ):
        has_first_party_policy = any(
            isinstance(policy, PolicyDocument)
            and policy.name in IMAGE_SIGNATURE_POLICY_NAMES
            for policy in directory_policies
        )
        has_source_ivp = any(
            isinstance(policy, ImageValidatingPolicyDocument)
            for policy in directory_policies
        )
        if has_first_party_policy or has_source_ivp:
            directories.append(directory)
    return directories


def kyverno_policy_directories_with_static_hints(
    policies: list[PolicyDocument],
    ivps: list[ImageValidatingPolicyDocument],
) -> list[Path]:
    directories = kyverno_policy_directories(policies, ivps)
    seen = {directory.resolve() for directory in directories}
    for directory in (KYVERNO_POLICIES_REPO_DIRECTORY,):
        resolved = directory.resolve()
        if resolved in seen:
            continue
        directories.append(directory)
        seen.add(resolved)
    return directories


RenderResult = tuple[list[ImageValidatingPolicyDocument], list[str]]
RenderCache = dict[Path, RenderResult]
PolicySurfaceRenderResult = tuple[
    list[ImageValidatingPolicyDocument],
    list[FluxKustomizationDocument],
    list[str],
]
PolicySurfaceRenderCache = dict[Path, PolicySurfaceRenderResult]


def kustomization_entry_is_remote(entry: str) -> bool:
    return (
        "://" in entry
        or entry.startswith("git@")
        or entry.startswith("github.com/")
        or entry.startswith("gitlab.com/")
        or entry.startswith("bitbucket.org/")
    )


def kustomization_remote_resource_entries(
    directory: Path, seen: set[Path] | None = None
) -> tuple[tuple[Path, str], ...]:
    seen = seen or set()
    directory = directory.resolve()
    if directory in seen:
        return ()
    seen.add(directory)

    kustomization_path = kustomization_path_for_directory(directory)
    if kustomization_path is None:
        return ()

    remotes: list[tuple[Path, str]] = []
    for resource in kustomization_entry_values(
        kustomization_path, KUSTOMIZATION_WALKED_ENTRY_FIELDS
    ):
        if kustomization_entry_is_remote(resource):
            remotes.append((kustomization_path, resource))
            continue
        target = (directory / resource).resolve()
        if target.is_dir():
            remotes.extend(
                kustomization_remote_resource_entries(target, seen)
            )

    return tuple(remotes)


def kustomization_remote_resource_findings(directory: Path) -> list[str]:
    findings: list[str] = []
    for kustomization_path, resource in kustomization_remote_resource_entries(directory):
        if resource in KYVERNO_IVP_FREE_REMOTE_BASES:
            continue
        findings.append(
            "rendered Kyverno policy set cannot be verified because "
            "kustomization references remote resource not listed in "
            "KYVERNO_IVP_FREE_REMOTE_BASES: "
            f"{display_path(kustomization_path)} -> {resource}"
        )
    return findings


def kustomization_graph_has_helm_charts(
    directory: Path, seen: set[Path] | None = None
) -> bool:
    seen = seen or set()
    directory = directory.resolve()
    if directory in seen:
        return False
    seen.add(directory)

    kustomization_path = kustomization_path_for_directory(directory)
    if kustomization_path is None:
        return False

    try:
        with kustomization_path.open(encoding="utf-8") as handle:
            documents = list(yaml.safe_load_all(handle))
    except (OSError, yaml.YAMLError):
        return False

    for document in documents:
        if not isinstance(document, dict):
            continue
        if document.get("kind") not in KUSTOMIZATION_KINDS:
            continue
        if "helmCharts" in document or "helmChartInflationGenerator" in document:
            return True

    for entry in kustomization_entry_values(
        kustomization_path, KUSTOMIZATION_WALKED_ENTRY_FIELDS
    ):
        if kustomization_entry_is_remote(entry):
            continue
        target = (directory / entry).resolve()
        if target.is_dir() and kustomization_graph_has_helm_charts(target, seen):
            return True

    return False


def kustomization_render_required_fields(
    directory: Path, seen: set[Path] | None = None
) -> tuple[tuple[Path, str], ...]:
    seen = seen or set()
    directory = directory.resolve()
    if directory in seen:
        return ()
    seen.add(directory)

    kustomization_path = kustomization_path_for_directory(directory)
    if kustomization_path is None:
        return ()

    try:
        with kustomization_path.open(encoding="utf-8") as handle:
            documents = list(yaml.safe_load_all(handle))
    except (OSError, yaml.YAMLError):
        return ()

    found: list[tuple[Path, str]] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        if document.get("kind") not in KUSTOMIZATION_KINDS:
            continue
        for field in KUSTOMIZATION_RENDER_REQUIRED_GRAPH_FIELDS:
            if field in document:
                found.append((kustomization_path, field))

    for entry in kustomization_entry_values(
        kustomization_path, KUSTOMIZATION_WALKED_ENTRY_FIELDS
    ):
        if kustomization_entry_is_remote(entry):
            continue
        target = (directory / entry).resolve()
        if target.is_dir():
            found.extend(kustomization_render_required_fields(target, seen))

    return tuple(found)


def local_enumerable_document_paths(
    directory: Path,
    seen: set[Path] | None = None,
) -> tuple[list[Path], list[str]]:
    seen = seen or set()
    directory = directory.resolve()
    if directory in seen:
        return [], []
    seen.add(directory)

    kustomization_path = kustomization_path_for_directory(directory)
    if kustomization_path is None:
        paths = sorted(
            path.resolve()
            for path in directory.rglob("*")
            if path.is_file() and path.suffix in YAML_SUFFIXES
        )
        return paths, []

    try:
        entries = kustomization_entry_values(
            kustomization_path, KUSTOMIZATION_LOCAL_ENUMERATED_ENTRY_FIELDS
        )
    except GuardUsageError as exc:
        return [], [
            "rendered Kyverno policy set cannot be determined from local "
            f"YAML enumeration because {exc}"
        ]

    findings: list[str] = []
    paths: list[Path] = []
    for entry in entries:
        if kustomization_entry_is_remote(entry):
            continue
        target = (directory / entry).resolve()
        if target.is_dir():
            child_paths, child_findings = local_enumerable_document_paths(
                target, seen
            )
            paths.extend(child_paths)
            findings.extend(child_findings)
            continue
        if not target.exists():
            findings.append(
                "rendered Kyverno policy set cannot be determined from local "
                "YAML enumeration because kustomization entry does not exist: "
                f"{display_path(kustomization_path)} -> {entry}"
            )
            continue
        if not target.is_file():
            findings.append(
                "rendered Kyverno policy set cannot be determined from local "
                "YAML enumeration because kustomization entry is not a file "
                f"or directory: {display_path(kustomization_path)} -> {entry}"
            )
            continue
        paths.append(target)

    return sorted(set(paths), key=display_path), findings


def local_enumerated_policy_surface_from_directory(
    directory: Path,
) -> PolicySurfaceRenderResult:
    paths, findings = local_enumerable_document_paths(directory)
    if findings:
        return [], [], findings

    ivps: list[ImageValidatingPolicyDocument] = []
    flux_kustomizations: list[FluxKustomizationDocument] = []
    for path in paths:
        try:
            _refs, _policies, path_ivps, path_flux_kustomizations, _settings = parse_yaml_file(
                path
            )
        except GuardUsageError as exc:
            findings.append(
                "rendered Kyverno policy set cannot be determined from local "
                f"YAML enumeration because {exc}"
            )
            continue
        ivps.extend(path_ivps)
        flux_kustomizations.extend(path_flux_kustomizations)

    return ivps, flux_kustomizations, findings


def local_enumerated_ivps_from_directory(directory: Path) -> RenderResult:
    ivps, _flux_kustomizations, findings = local_enumerated_policy_surface_from_directory(
        directory
    )
    return ivps, findings


def output_excerpt(value: str, limit: int = 700) -> str:
    normalized = " ".join(value.split())
    if not normalized:
        return "<empty>"
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."


def kubectl_kustomize(
    directory: Path,
    *,
    enable_helm: bool = False,
) -> tuple[subprocess.CompletedProcess[str] | None, list[str]]:
    command = ["kubectl", "kustomize"]
    if enable_helm:
        command.append("--enable-helm")
    command.append(str(directory))
    command_name = "kubectl kustomize --enable-helm" if enable_helm else "kubectl kustomize"

    try:
        completed = subprocess.run(
            tuple(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=KUBECTL_KUSTOMIZE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None, [
            "rendered Kyverno policy set cannot be checked because kubectl "
            f"is not available on PATH: {display_path(directory)}"
        ]
    except subprocess.TimeoutExpired:
        return None, [
            "rendered Kyverno policy set cannot be checked because "
            f"{command_name} timed out after "
            f"{KUBECTL_KUSTOMIZE_TIMEOUT_SECONDS}s for {display_path(directory)}"
        ]
    except OSError as exc:
        return None, [
            "rendered Kyverno policy set cannot be checked because kubectl "
            f"kustomize could not be started for {display_path(directory)}: {exc}"
        ]

    return completed, []


def rewrite_allowlisted_remotes_in_localized_tree(directory: Path) -> list[str]:
    findings: list[str] = []
    stub_counter = 0
    for kustomization_path in sorted(
        (
            path
            for filename in KUSTOMIZATION_FILENAMES
            for path in directory.rglob(filename)
        ),
        key=display_path,
    ):
        try:
            with kustomization_path.open(encoding="utf-8") as handle:
                documents = list(yaml.safe_load_all(handle))
        except (OSError, yaml.YAMLError) as exc:
            findings.append(
                "rendered policy surface cannot be checked because localized "
                f"kustomization parsing failed for {display_path(kustomization_path)}: "
                f"{exc}"
            )
            continue

        changed = False
        for document in documents:
            if not isinstance(document, dict):
                continue
            if document.get("kind") not in KUSTOMIZATION_KINDS:
                continue
            for field in KUSTOMIZATION_WALKED_ENTRY_FIELDS:
                entries = document.get(field)
                if not isinstance(entries, list):
                    continue
                for index, entry in enumerate(entries):
                    if not isinstance(entry, str):
                        continue
                    if not kustomization_entry_is_remote(entry):
                        continue
                    if entry not in KYVERNO_IVP_FREE_REMOTE_BASES:
                        continue
                    stub_counter += 1
                    stub_name = f".guard-allowlisted-remote-{stub_counter}.yaml"
                    stub_path = kustomization_path.parent / stub_name
                    try:
                        stub_path.write_text(
                            "apiVersion: v1\nkind: List\nitems: []\n",
                            encoding="utf-8",
                        )
                    except OSError as exc:
                        findings.append(
                            "rendered policy surface cannot be checked because "
                            "allowlisted remote stub creation failed for "
                            f"{display_path(stub_path)}: {exc}"
                        )
                        continue
                    entries[index] = stub_name
                    changed = True

        if not changed:
            continue
        try:
            with kustomization_path.open("w", encoding="utf-8") as handle:
                yaml.safe_dump_all(
                    documents,
                    handle,
                    explicit_start=False,
                    sort_keys=False,
                )
        except OSError as exc:
            findings.append(
                "rendered policy surface cannot be checked because localized "
                f"kustomization writing failed for {display_path(kustomization_path)}: "
                f"{exc}"
            )

    return findings


def kubectl_kustomize_with_allowlisted_remote_stubs(
    directory: Path,
    *,
    enable_helm: bool = False,
) -> tuple[subprocess.CompletedProcess[str] | None, list[str]]:
    remote_entries = kustomization_remote_resource_entries(directory)
    if not any(resource in KYVERNO_IVP_FREE_REMOTE_BASES for _path, resource in remote_entries):
        return kubectl_kustomize(directory, enable_helm=enable_helm)

    try:
        with tempfile.TemporaryDirectory(prefix="ivp-policy-surface-") as tmpdir:
            localized_directory = Path(tmpdir) / directory.name
            try:
                shutil.copytree(directory, localized_directory)
            except OSError as exc:
                return None, [
                    "rendered policy surface cannot be checked because "
                    "temporary local kustomize tree creation failed for "
                    f"{display_path(directory)}: {exc}"
                ]

            findings = rewrite_allowlisted_remotes_in_localized_tree(
                localized_directory
            )
            if findings:
                return None, findings

            completed, run_findings = kubectl_kustomize(
                localized_directory,
                enable_helm=enable_helm,
            )
            if run_findings:
                return None, [
                    finding.replace(
                        display_path(localized_directory),
                        display_path(directory),
                    )
                    for finding in run_findings
                ]
            return completed, []
    except OSError as exc:
        return None, [
            "rendered policy surface cannot be checked because temporary "
            f"directory setup failed for {display_path(directory)}: {exc}"
        ]


def ivps_from_kustomize_output(
    directory: Path,
    output: str,
    *,
    rendered_path: Path,
) -> RenderResult:
    try:
        documents = list(
            yaml.compose_all(output, Loader=yaml.SafeLoader)
        )
    except yaml.YAMLError as exc:
        return [], [
            "rendered Kyverno policy set cannot be checked because kubectl "
            f"kustomize output is not valid YAML for {display_path(directory)}: "
            f"{exc}"
        ]

    _refs, _policies, rendered_ivps, _flux_kustomizations, _settings = parse_yaml_documents(
        documents, rendered_path
    )
    return rendered_ivps, []


def policy_surface_from_kustomize_output(
    directory: Path,
    output: str,
    *,
    rendered_path: Path,
) -> PolicySurfaceRenderResult:
    try:
        documents = list(
            yaml.compose_all(output, Loader=yaml.SafeLoader)
        )
    except yaml.YAMLError as exc:
        return [], [], [
            "rendered policy surface cannot be checked because kubectl "
            f"kustomize output is not valid YAML for {display_path(directory)}: "
            f"{exc}"
        ]

    (
        _refs,
        _policies,
        rendered_ivps,
        rendered_flux_kustomizations,
        _settings,
    ) = parse_yaml_documents(documents, rendered_path)
    return rendered_ivps, rendered_flux_kustomizations, []


def rendered_ivps_from_kustomization_directory(
    directory: Path,
    render_cache: RenderCache | None = None,
) -> RenderResult:
    directory = directory.resolve()
    if render_cache is not None and directory in render_cache:
        return render_cache[directory]

    result = rendered_ivps_from_kustomization_directory_uncached(directory)
    if render_cache is not None:
        render_cache[directory] = result
    return result


def rendered_ivps_from_kustomization_directory_uncached(directory: Path) -> RenderResult:
    # TIER 3 - content not visible locally. A remote base can only pass as
    # IVP-free through an exact, reviewed KYVERNO_IVP_FREE_REMOTE_BASES entry.
    remote_findings = kustomization_remote_resource_findings(directory)
    if remote_findings:
        return [], remote_findings

    remote_entries = kustomization_remote_resource_entries(directory)
    if remote_entries:
        remote_kustomization_paths = {path for path, _resource in remote_entries}
        render_required_fields = tuple(
            (path, field)
            for path, field in kustomization_render_required_fields(directory)
            if path in remote_kustomization_paths
        )
        if render_required_fields:
            found = ", ".join(
                f"{display_path(path)}:{field}"
                for path, field in render_required_fields
            )
            return [], [
                "rendered Kyverno policy set cannot be verified because "
                "allowlisted remote resource content prevents local rendering "
                "while the kustomization graph also uses render-time fields "
                f"that cannot be reduced to direct YAML enumeration: {found}"
            ]
        return local_enumerated_ivps_from_directory(directory)

    kustomization_path = kustomization_path_for_directory(directory)
    if kustomization_path is None:
        # TIER 2 - Flux synthesizes a kustomization from local YAML documents,
        # so direct enumeration is a positive IVP-free determination when no
        # ImageValidatingPolicy documents are found.
        return local_enumerated_ivps_from_directory(directory)

    # TIER 1 - locally renderable kustomize graph.
    completed, run_findings = kubectl_kustomize(directory)
    if run_findings:
        return [], run_findings

    assert completed is not None
    if completed.returncode == 0:
        return ivps_from_kustomize_output(
            directory,
            completed.stdout,
            rendered_path=directory / "<kubectl kustomize>",
        )

    if kustomization_graph_has_helm_charts(directory):
        helm_completed, helm_findings = kubectl_kustomize(directory, enable_helm=True)
        if helm_findings:
            return [], helm_findings
        assert helm_completed is not None
        if helm_completed.returncode == 0:
            return ivps_from_kustomize_output(
                directory,
                helm_completed.stdout,
                rendered_path=directory / "<kubectl kustomize --enable-helm>",
            )

    # TIER 2 - kustomize did not render, but the remaining content is local and
    # enumerable. If this finds IVPs, callers run the same full shape validation.
    return local_enumerated_ivps_from_directory(directory)


def rendered_policy_surface_from_kustomization_directory(
    directory: Path,
    render_cache: PolicySurfaceRenderCache | None = None,
) -> PolicySurfaceRenderResult:
    directory = directory.resolve()
    if render_cache is not None and directory in render_cache:
        return render_cache[directory]

    result = rendered_policy_surface_from_kustomization_directory_uncached(directory)
    if render_cache is not None:
        render_cache[directory] = result
    return result


def rendered_policy_surface_from_kustomization_directory_uncached(
    directory: Path,
) -> PolicySurfaceRenderResult:
    remote_findings = kustomization_remote_resource_findings(directory)
    if remote_findings:
        return [], [], remote_findings

    kustomization_path = kustomization_path_for_directory(directory)
    if kustomization_path is None:
        return local_enumerated_policy_surface_from_directory(directory)

    completed, run_findings = kubectl_kustomize_with_allowlisted_remote_stubs(directory)
    if run_findings:
        return [], [], run_findings

    assert completed is not None
    if completed.returncode == 0:
        return policy_surface_from_kustomize_output(
            directory,
            completed.stdout,
            rendered_path=directory / "<kubectl kustomize>",
        )

    if kustomization_graph_has_helm_charts(directory):
        helm_completed, helm_findings = kubectl_kustomize_with_allowlisted_remote_stubs(
            directory,
            enable_helm=True,
        )
        if helm_findings:
            return [], [], helm_findings
        assert helm_completed is not None
        if helm_completed.returncode == 0:
            return policy_surface_from_kustomize_output(
                directory,
                helm_completed.stdout,
                rendered_path=directory / "<kubectl kustomize --enable-helm>",
            )

    return local_enumerated_policy_surface_from_directory(directory)


def rendered_ivp_findings(
    first_party_refs: list[ImageRef],
    policies: list[PolicyDocument],
    ivps: list[ImageValidatingPolicyDocument],
    render_cache: RenderCache | None = None,
    skip_directories: set[Path] | None = None,
) -> list[str]:
    findings: list[str] = []
    skip_directories = skip_directories or set()
    for directory in kyverno_policy_directories(policies, ivps):
        if directory.resolve() in skip_directories:
            continue
        rendered_ivps, render_findings = rendered_ivps_from_kustomization_directory(
            directory, render_cache
        )
        findings.extend(render_findings)
        findings.extend(
            find_ivp_violations(
                first_party_refs,
                rendered_ivps,
                scope="rendered Kyverno policy set",
            )
        )

    return findings


def path_candidates_for_flux_spec_path(
    spec_path: str,
    roots: Iterable[Path],
) -> set[Path]:
    raw = spec_path.strip()
    if not raw or "://" in raw:
        return set()

    path = Path(raw)
    if path.is_absolute():
        return {path.resolve()}

    candidates = {(Path.cwd() / path).resolve()}
    for root in roots:
        candidates.add((root.resolve() / path).resolve())
    return candidates


def flux_ref(flux: FluxKustomizationDocument) -> str:
    namespace = flux.namespace if flux.namespace is not None else "<unset>"
    return f"{display_path(flux.path)}:{flux.line} ({namespace}/{flux.name})"


def flux_kustomization_uses_local_repo(
    flux: FluxKustomizationDocument,
) -> bool:
    # Tenant template/proof Flux CRs point at tenant GitRepositories; their
    # spec.path is relative to those external repos, not this Talos repo.
    return (
        flux.source_kind == FLUX_LOCAL_REPO_SOURCE_KIND
        and flux.source_name == FLUX_LOCAL_REPO_SOURCE_NAME
    )


def flux_kustomization_source_ref_names_local_repo(
    flux: FluxKustomizationDocument,
) -> bool:
    return (
        flux.source_kind == FLUX_LOCAL_REPO_SOURCE_KIND
        and flux.source_name == FLUX_LOCAL_REPO_SOURCE_NAME
        and flux.source_namespace in (None, FLUX_LOCAL_REPO_SOURCE_NAMESPACE)
    )


def flux_kustomization_is_root(flux: FluxKustomizationDocument) -> bool:
    return (
        flux.name == ROOT_FLUX_KUSTOMIZATION_NAME
        and flux.namespace == ROOT_FLUX_KUSTOMIZATION_NAMESPACE
        and flux_kustomization_uses_local_repo(flux)
    )


def flux_kustomization_is_kyverno_policies(
    flux: FluxKustomizationDocument,
) -> bool:
    return flux.name == KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME


def kyverno_policies_flux_path_findings(
    flux_kustomizations: list[FluxKustomizationDocument],
) -> list[str]:
    findings: list[str] = []
    matches = [
        flux
        for flux in flux_kustomizations
        if flux.name == KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME
        and flux_kustomization_uses_local_repo(flux)
    ]
    if not matches:
        findings.append(
            "Flux Kustomization "
            f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} using "
            f"{FLUX_LOCAL_REPO_SOURCE_KIND}/{FLUX_LOCAL_REPO_SOURCE_NAME} "
            "not found; guard cannot prove which repo path Flux applies for "
            "Kyverno policies"
        )
        return findings

    if len(matches) != 1:
        found = ", ".join(flux_ref(flux) for flux in matches)
        findings.append(
            "Flux Kustomization "
            f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} using "
            f"{FLUX_LOCAL_REPO_SOURCE_KIND}/{FLUX_LOCAL_REPO_SOURCE_NAME} "
            f"must exist exactly once: found {len(matches)}: {found}"
        )

    for flux in matches:
        if flux.spec_path != KYVERNO_POLICIES_REPO_PATH:
            found = flux.spec_path if flux.spec_path is not None else "<unset>"
            line = flux.spec_path_line or flux.line
            findings.append(
                "Flux Kustomization "
                f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} must set "
                f"spec.path exactly to {KYVERNO_POLICIES_REPO_PATH}: "
                f"{display_path(flux.path)}:{line} (found {found})"
            )
    return findings


def effective_kyverno_policies_flux_findings(
    render_results: list[FluxRenderedImageValidatingPolicies],
) -> list[str]:
    findings: list[str] = []
    effective_matches: list[
        tuple[FluxRenderedImageValidatingPolicies, FluxKustomizationDocument]
    ] = []
    for result in render_results:
        for rendered_flux in result.flux_kustomizations:
            if flux_kustomization_is_kyverno_policies(rendered_flux):
                effective_matches.append((result, rendered_flux))

    if not effective_matches:
        findings.append(
            "rendered root applied graph must contain the effective Flux "
            f"Kustomization {KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAMESPACE}/"
            f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME}; guard cannot prove "
            "Kyverno policies reach the API server"
        )
        return findings

    for result, flux in effective_matches:
        rendered_from = f"{result.flux.namespace or '<unset>'}/{result.flux.name}"
        effective_ref = (
            "effective rendered Flux Kustomization "
            f"{flux.namespace or '<unset>'}/{flux.name} from {rendered_from}: "
            f"{display_path(flux.path)}:{flux.line}"
        )

        if flux.namespace != KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAMESPACE:
            found = flux.namespace if flux.namespace is not None else "<unset>"
            findings.append(
                "effective rendered Flux Kustomization "
                f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} must remain in "
                f"namespace {KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAMESPACE}: "
                f"{effective_ref} (found {found})"
            )

        if flux.spec_path != KYVERNO_POLICIES_REPO_PATH:
            found = flux.spec_path if flux.spec_path is not None else "<unset>"
            line = flux.spec_path_line or flux.line
            findings.append(
                "effective rendered Flux Kustomization "
                f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} must set "
                f"spec.path exactly to {KYVERNO_POLICIES_REPO_PATH}: "
                f"{display_path(flux.path)}:{line} (found {found}; rendered by "
                f"{rendered_from})"
            )

        if yaml_scalar_true(flux.spec_suspend):
            line = flux.spec_suspend_line or flux.line
            findings.append(
                "effective rendered Flux Kustomization "
                f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} must not set "
                "spec.suspend: true because that stops policy reconciliation: "
                f"{display_path(flux.path)}:{line} (rendered by {rendered_from})"
            )

        if flux.spec_prune != KYVERNO_POLICIES_REQUIRED_PRUNE:
            found = flux.spec_prune if flux.spec_prune is not None else "<unset>"
            line = flux.spec_prune_line or flux.line
            findings.append(
                "effective rendered Flux Kustomization "
                f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} must preserve "
                f"spec.prune: {KYVERNO_POLICIES_REQUIRED_PRUNE}: "
                f"{display_path(flux.path)}:{line} (found {found}; rendered by "
                f"{rendered_from})"
            )

        if not flux_kustomization_source_ref_names_local_repo(flux):
            found_namespace = (
                flux.source_namespace if flux.source_namespace is not None else "<unset>"
            )
            findings.append(
                "effective rendered Flux Kustomization "
                f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} must source the "
                f"local {FLUX_LOCAL_REPO_SOURCE_KIND}/"
                f"{FLUX_LOCAL_REPO_SOURCE_NAME} GitRepository: {effective_ref} "
                f"(found kind={flux.source_kind or '<unset>'}, "
                f"name={flux.source_name or '<unset>'}, "
                f"namespace={found_namespace})"
            )

    return findings


def kustomization_applied_file_targets(
    directory: Path,
    seen: set[Path] | None = None,
) -> tuple[set[Path], list[str]]:
    directory = directory.resolve()
    seen = seen or set()
    if directory in seen:
        return set(), []
    seen.add(directory)

    kustomization_path = kustomization_path_for_directory(directory)
    if kustomization_path is None:
        return (
            {
                path.resolve()
                for path in directory.rglob("*")
                if path.is_file() and path.suffix in YAML_SUFFIXES
            },
            [],
        )

    try:
        entries = kustomization_entry_values(
            kustomization_path,
            ("resources", "bases"),
        )
    except GuardUsageError as exc:
        return set(), [str(exc)]

    targets: set[Path] = set()
    findings: list[str] = []
    for entry in entries:
        if kustomization_entry_is_remote(entry):
            continue
        target = (directory / entry).resolve()
        targets.add(target)
        if target.is_dir():
            child_targets, child_findings = kustomization_applied_file_targets(
                target,
                seen,
            )
            targets.update(child_targets)
            findings.extend(child_findings)

    return targets, findings


def kyverno_policies_flux_membership_findings(
    flux_kustomizations: list[FluxKustomizationDocument],
    roots: Iterable[Path],
) -> list[str]:
    findings: list[str] = []
    kyverno_matches = [
        flux
        for flux in flux_kustomizations
        if flux_kustomization_is_kyverno_policies(flux)
    ]
    if not kyverno_matches:
        return findings

    root_matches = [
        flux for flux in flux_kustomizations if flux_kustomization_is_root(flux)
    ]
    if not root_matches:
        findings.append(
            "root Flux Kustomization "
            f"{ROOT_FLUX_KUSTOMIZATION_NAMESPACE}/{ROOT_FLUX_KUSTOMIZATION_NAME} "
            "using the local flux-system GitRepository was not found; guard "
            "cannot prove kyverno-policies is reachable from the applied graph"
        )
        return findings

    for flux in kyverno_matches:
        parent_kustomization = kustomization_path_for_directory(flux.path.parent)
        if parent_kustomization is None:
            findings.append(
                "Flux Kustomization "
                f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} file is in a "
                "directory without a kustomization.yaml resources list: "
                f"{display_path(flux.path)}:{flux.line}"
            )
        else:
            parent_targets = kustomization_resource_targets(
                flux.path.parent,
                kustomization_resource_entries(parent_kustomization),
            )
            if flux.path.resolve() not in parent_targets:
                findings.append(
                    "Flux Kustomization "
                    f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} file is not "
                    "listed in the kustomization that should apply it: "
                    f"{display_path(flux.path)}:{flux.line} "
                    f"(kustomization: {display_path(parent_kustomization)})"
                )

        for root_flux in root_matches:
            root_directory, root_path_findings = flux_spec_path_directory(
                root_flux,
                roots,
            )
            findings.extend(root_path_findings)
            if root_directory is None:
                continue
            applied_targets, graph_findings = kustomization_applied_file_targets(
                root_directory
            )
            for graph_finding in graph_findings:
                findings.append(
                    "root applied graph membership could not be fully checked "
                    f"for {display_path(root_directory)} because {graph_finding}"
                )
            if flux.path.resolve() in applied_targets:
                continue
            findings.append(
                "Flux Kustomization "
                f"{KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} file is not "
                "reachable from the root applied kustomization graph: "
                f"{display_path(flux.path)}:{flux.line} "
                f"(root Flux Kustomization: "
                f"{root_flux.namespace or '<unset>'}/{root_flux.name}, "
                f"spec.path={root_flux.spec_path}; expected a transitive "
                "resources entry to include the file)"
            )

    return findings


def flux_kustomization_first_party_image_rewrite_findings(
    flux_kustomizations: Iterable[FluxKustomizationDocument],
) -> list[str]:
    findings: list[str] = []
    for flux in flux_kustomizations:
        for rewrite in flux.image_rewrites:
            if not matches_first_party_org_glob(rewrite.name):
                continue
            new_name = rewrite.new_name if rewrite.new_name is not None else "<unset>"
            findings.append(
                "Flux Kustomization spec.images must not rewrite first-party "
                "image names because Flux applies the rewrite after kustomize "
                "rendering and can move workloads outside the IVP "
                "matchImageReferences globs: "
                f"{display_path(flux.path)}:{rewrite.name_line} "
                f"({flux.namespace or '<unset>'}/{flux.name}, "
                f"name={rewrite.name}, newName={new_name})"
            )
    return findings


def flux_spec_path_directory(
    flux: FluxKustomizationDocument,
    roots: Iterable[Path],
) -> tuple[Path | None, list[str]]:
    if flux.spec_path is None:
        return None, [
            "Flux Kustomization must declare a local spec.path so the "
            f"guard can render what Flux applies: {flux_ref(flux)} "
            "(found <unset>)"
        ]

    candidates = path_candidates_for_flux_spec_path(flux.spec_path, roots)
    if not candidates:
        return None, [
            "Flux Kustomization spec.path is not a local repo path and "
            f"cannot be rendered by this guard: {flux_ref(flux)} "
            f"(spec.path={flux.spec_path})"
        ]

    existing_directories = sorted(
        (candidate for candidate in candidates if candidate.is_dir()),
        key=display_path,
    )
    if existing_directories:
        return existing_directories[0], []

    existing_files = sorted(
        (candidate for candidate in candidates if candidate.exists()),
        key=display_path,
    )
    if existing_files:
        found = ", ".join(display_path(path) for path in existing_files)
        return None, [
            "Flux Kustomization spec.path must resolve to a directory before "
            f"it can be rendered by this guard: {flux_ref(flux)} "
            f"(spec.path={flux.spec_path}, found file {found})"
        ]

    searched = ", ".join(display_path(candidate) for candidate in sorted(candidates))
    return None, [
        "Flux Kustomization spec.path does not exist in this repo, so the "
        "guard cannot render what Flux applies: "
        f"{flux_ref(flux)} (spec.path={flux.spec_path}, searched {searched})"
    ]


def kustomization_graph_contains_ivp(
    directory: Path,
    seen: set[Path] | None = None,
) -> bool:
    directory = directory.resolve()
    seen = seen or set()
    if directory in seen:
        return False
    seen.add(directory)

    kustomization_path = kustomization_path_for_directory(directory)
    if kustomization_path is None:
        return True

    try:
        with kustomization_path.open(encoding="utf-8") as handle:
            documents = list(yaml.safe_load_all(handle))
    except (OSError, yaml.YAMLError):
        return True

    if not documents:
        return True

    entries: list[str] = []
    for document in documents:
        if not isinstance(document, dict):
            return True
        if document.get("kind") not in KUSTOMIZATION_KINDS:
            return True
        if any(field in document for field in KUSTOMIZATION_UNKNOWN_GRAPH_FIELDS):
            return True
        if any(
            field in document for field in KUSTOMIZATION_DIRECT_UNKNOWN_GRAPH_FIELDS
        ):
            return True
        for field in KUSTOMIZATION_WALKED_ENTRY_FIELDS:
            field_entries = document.get(field)
            if field_entries is None:
                continue
            if not isinstance(field_entries, list):
                return True
            for entry in field_entries:
                if not isinstance(entry, str) or not entry.strip():
                    return True
                entries.append(entry.strip())

    for entry in entries:
        if kustomization_entry_is_remote(entry):
            if entry not in KYVERNO_IVP_FREE_REMOTE_BASES:
                return True
            continue
        target = (directory / entry).resolve()
        if target.is_dir():
            if kustomization_graph_contains_ivp(target, seen):
                return True
            continue
        if not target.exists():
            return True
        if not target.is_file():
            return True
        try:
            _refs, _policies, ivps, _flux_kustomizations, _settings = parse_yaml_file(
                target
            )
        except GuardUsageError:
            return True
        if ivps:
            return True

    return False


def file_contains_policy_surface(path: Path) -> bool:
    try:
        _refs, _policies, ivps, flux_kustomizations, _settings = parse_yaml_file(path)
    except GuardUsageError:
        return True
    if ivps:
        return True
    return any(
        flux.name == KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME
        for flux in flux_kustomizations
    )


def kustomization_graph_contains_policy_surface(
    directory: Path,
    seen: set[Path] | None = None,
) -> bool:
    directory = directory.resolve()
    seen = seen or set()
    if directory in seen:
        return False
    seen.add(directory)

    kustomization_path = kustomization_path_for_directory(directory)
    if kustomization_path is None:
        return True

    try:
        with kustomization_path.open(encoding="utf-8") as handle:
            documents = list(yaml.safe_load_all(handle))
    except (OSError, yaml.YAMLError):
        return True

    if not documents:
        return True

    entries: list[str] = []
    for document in documents:
        if not isinstance(document, dict):
            return True
        if document.get("kind") not in KUSTOMIZATION_KINDS:
            return True
        if any(field in document for field in KUSTOMIZATION_UNKNOWN_GRAPH_FIELDS):
            return True
        if any(
            field in document for field in KUSTOMIZATION_DIRECT_UNKNOWN_GRAPH_FIELDS
        ):
            return True
        for field in KUSTOMIZATION_WALKED_ENTRY_FIELDS:
            field_entries = document.get(field)
            if field_entries is None:
                continue
            if not isinstance(field_entries, list):
                return True
            for entry in field_entries:
                if not isinstance(entry, str) or not entry.strip():
                    return True
                entries.append(entry.strip())

    for entry in entries:
        if kustomization_entry_is_remote(entry):
            if entry not in KYVERNO_IVP_FREE_REMOTE_BASES:
                return True
            continue
        target = (directory / entry).resolve()
        if target.is_dir():
            if kustomization_graph_contains_policy_surface(target, seen):
                return True
            continue
        if not target.exists():
            return True
        if not target.is_file():
            return True
        if file_contains_policy_surface(target):
            return True

    return False


def flux_applied_ivp_findings(
    first_party_refs: list[ImageRef],
    flux_kustomizations: list[FluxKustomizationDocument],
    roots: Iterable[Path],
    render_cache: PolicySurfaceRenderCache | None = None,
) -> tuple[list[str], list[FluxRenderedImageValidatingPolicies]]:
    findings: list[str] = []
    render_results: list[FluxRenderedImageValidatingPolicies] = []
    render_cache = render_cache if render_cache is not None else {}
    roots = tuple(roots)

    for flux in flux_kustomizations:
        if not flux_kustomization_uses_local_repo(flux):
            continue

        directory, path_findings = flux_spec_path_directory(flux, roots)
        findings.extend(path_findings)
        if directory is None:
            continue

        directory = directory.resolve()
        # Follow the local kustomize resource graph, not the whole subtree, so
        # Flux aggregators that only apply child Flux CRs do not force unrelated
        # remote-resource renders.
        if not kustomization_graph_contains_policy_surface(directory):
            continue

        (
            rendered_ivps,
            rendered_flux_kustomizations,
            render_findings,
        ) = rendered_policy_surface_from_kustomization_directory(
            directory, render_cache
        )
        findings.extend(render_findings)
        render_results.append(
            FluxRenderedImageValidatingPolicies(
                flux=flux,
                directory=directory,
                ivps=rendered_ivps,
                flux_kustomizations=rendered_flux_kustomizations,
            )
        )
        if render_findings or not rendered_ivps:
            continue

        findings.extend(
            find_ivp_violations(
                first_party_refs,
                rendered_ivps,
                scope=(
                    "Flux Kustomization rendered output "
                    f"{flux.namespace or '<unset>'}/{flux.name} "
                    f"(spec.path={flux.spec_path})"
                ),
            )
        )

    return findings, render_results


def flux_kustomization_policy_rewrite_findings(
    render_results: list[FluxRenderedImageValidatingPolicies],
) -> list[str]:
    findings: list[str] = []
    for result in render_results:
        contains_kyverno_policies = any(
            flux_kustomization_is_kyverno_policies(rendered_flux)
            for rendered_flux in result.flux_kustomizations
        )
        if not result.ivps and not contains_kyverno_policies:
            continue
        for field, line in result.flux.forbidden_field_lines:
            rendered_subject = (
                f"the {KYVERNO_POLICIES_FLUX_KUSTOMIZATION_NAME} "
                "Flux Kustomization"
                if contains_kyverno_policies and not result.ivps
                else "an ImageValidatingPolicy"
            )
            findings.append(
                "Flux Kustomization whose rendered output contains "
                f"{rendered_subject} must not declare spec.{field} because "
                "Flux can rewrite or stop the policy after source inspection: "
                f"{display_path(result.flux.path)}:{line} "
                f"({result.flux.namespace or '<unset>'}/{result.flux.name}, "
                f"spec.path={result.flux.spec_path})"
            )

    return findings


def policy_resource_membership_findings(
    policies: list[PolicyDocument | ImageValidatingPolicyDocument],
) -> list[str]:
    findings: list[str] = []
    policy_paths_by_directory: dict[
        Path, list[PolicyDocument | ImageValidatingPolicyDocument]
    ] = {}
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


def dedupe_findings(findings: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        if finding in seen:
            continue
        deduped.append(finding)
        seen.add(finding)
    return deduped


def evaluate_roots(roots: Iterable[Path]) -> GuardResult:
    assert_first_party_attestor_constants_consistent()

    roots = tuple(roots)
    render_cache: RenderCache = {}
    policy_surface_render_cache: PolicySurfaceRenderCache = {}
    paths = iter_yaml_paths(roots)
    refs: list[ImageRef] = []
    policies: list[PolicyDocument] = []
    ivps: list[ImageValidatingPolicyDocument] = []
    flux_kustomizations: list[FluxKustomizationDocument] = []
    kyverno_default_registry_settings: list[KyvernoDefaultRegistrySetting] = []
    for path in paths:
        (
            path_refs,
            path_policies,
            path_ivps,
            path_flux_kustomizations,
            path_default_registry_settings,
        ) = parse_yaml_file(path)
        refs.extend(path_refs)
        policies.extend(path_policies)
        ivps.extend(path_ivps)
        flux_kustomizations.extend(path_flux_kustomizations)
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
    findings.extend(ivp_canary_expiry_findings())
    findings.extend(find_ivp_violations(first_party_refs, ivps))
    findings.extend(kyverno_policies_flux_path_findings(flux_kustomizations))
    findings.extend(
        kyverno_policies_flux_membership_findings(flux_kustomizations, roots)
    )
    flux_ivp_findings, flux_render_results = flux_applied_ivp_findings(
        first_party_refs,
        flux_kustomizations,
        roots,
        policy_surface_render_cache,
    )
    findings.extend(flux_ivp_findings)
    findings.extend(effective_kyverno_policies_flux_findings(flux_render_results))
    findings.extend(flux_kustomization_policy_rewrite_findings(flux_render_results))
    rendered_flux_kustomizations = [
        rendered_flux
        for result in flux_render_results
        for rendered_flux in result.flux_kustomizations
    ]
    findings.extend(
        flux_kustomization_first_party_image_rewrite_findings(
            [*flux_kustomizations, *rendered_flux_kustomizations]
        )
    )
    flux_rendered_directories = {result.directory.resolve() for result in flux_render_results}
    findings.extend(
        rendered_ivp_findings(
            first_party_refs,
            policies,
            ivps,
            render_cache,
            skip_directories=flux_rendered_directories,
        )
    )
    findings.extend(policy_resource_membership_findings([*policies, *ivps]))
    findings = dedupe_findings(findings)
    return GuardResult(
        paths=paths,
        refs=refs,
        first_party_refs=first_party_refs,
        policies=policies,
        ivps=ivps,
        flux_kustomizations=flux_kustomizations,
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
    print(
        f"ImageValidatingPolicy admission-path enforcement "
        f"({IVP_VALIDATION_ACTION}/{IVP_REQUIRED_FAILURE_POLICY}), "
        f"{len(result.ivps)} first-party IVP:"
    )
    for ivp in result.ivps:
        print(
            f"  - {ivp.name} -> "
            f"{', '.join(FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES)}"
        )


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
