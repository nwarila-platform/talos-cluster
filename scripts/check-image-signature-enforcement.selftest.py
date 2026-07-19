#!/usr/bin/env python3
"""Offline regression self-test for the image signature enforcement guard."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-image-signature-enforcement.py"
FIRST_PARTY_IMAGE = "ghcr.io/nwarila-platform/foo"
FUTURE_FIRST_PARTY_IMAGE = "ghcr.io/nwarila-platform/not-yet-deployed"
_UNSET = object()


def load_guard():
    spec = importlib.util.spec_from_file_location(
        "check_image_signature_enforcement", GUARD
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {GUARD}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = load_guard()


@dataclass(frozen=True)
class GuardRun:
    rc: int
    findings: list[str]


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected_rc: int
    actual_rc: int
    finding_count: int
    evidence: str
    passed: bool
    findings: list[str]


def write_yaml(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def policy_dir(root: Path) -> Path:
    return root / guard.KYVERNO_POLICIES_REPO_PATH.removeprefix("./")


def flux_policy_kustomization_path(root: Path) -> Path:
    return policy_dir(root).parent / "kustomization-policies.yaml"


def write_flux_policy_kustomization(
    root: Path,
    spec_path: str | None = None,
    extra_spec_lines: tuple[str, ...] = (),
) -> None:
    spec_path = spec_path if spec_path is not None else guard.KYVERNO_POLICIES_REPO_PATH
    lines = [
        "apiVersion: kustomize.toolkit.fluxcd.io/v1",
        "kind: Kustomization",
        "metadata:",
        "  name: kyverno-policies",
        "  namespace: flux-system",
        "spec:",
        "  interval: 10m",
        f"  path: {spec_path}",
        "  prune: true",
        "  sourceRef:",
        "    kind: GitRepository",
        "    name: flux-system",
        *(f"  {line}" for line in extra_spec_lines),
    ]
    write_yaml(
        flux_policy_kustomization_path(root),
        "\n".join(lines),
    )


def cel_expression(
    prefixes: tuple[str, ...] = guard.FIRST_PARTY_IMAGE_PREFIXES,
    fields: tuple[str, ...] = (
        "containers",
        "initContainers",
        "ephemeralContainers",
    ),
) -> str:
    terms = " ||\n      ".join(
        f"c.image.startsWith('{prefix}')" for prefix in prefixes
    )
    clauses = [
        f"(has(object.spec.{field}) && object.spec.{field}.exists(c,\n"
        f"      {terms}))"
        for field in fields
    ]
    return "object != null && (\n  " + " ||\n  ".join(clauses) + "\n)"


def match_conditions_yaml(
    expression: str | None = None,
    name: str = guard.FIRST_PARTY_MATCH_CONDITION_NAME,
) -> str:
    expression = expression if expression is not None else cel_expression()
    return (
        "    matchConditions:\n"
        f"      - name: {name}\n"
        "        expression: >-\n"
        f"{textwrap.indent(expression, '          ')}\n"
    )


def verify_block(
    org_glob: str,
    action: str | None = "Audit",
    skip_refs: tuple[str, ...] = (),
    rule_name: str | None = None,
    required: str | None = "true",
    issuer: str | None = None,
    subject_regexp: str | None = None,
    roots: str | None = None,
    rekor_url: str | None = None,
    rekor_pubkey: str | None = None,
    ctlog_pubkey: str | None = None,
    ignore_tlog: str | None = None,
    ignore_sct: str | None = None,
    rule_extra_lines: tuple[str, ...] = (),
    match_namespaces: tuple[str, ...] = (),
) -> str:
    if rule_name is None:
        rule_name = "verify-" + org_glob.removeprefix("ghcr.io/").removesuffix("/*")
    lines = [
        f"    - name: {rule_name}",
        "      match:",
        "        any:",
        "          - resources:",
        "              kinds:",
        "                - Pod",
    ]
    if match_namespaces:
        lines.append("              namespaces:")
        for namespace in match_namespaces:
            lines.append(f"                - {namespace}")
    lines.extend(rule_extra_lines)
    lines.extend(
        [
            "      verifyImages:",
            "        - imageReferences:",
            f"            - \"{org_glob}\"",
        ]
    )
    if skip_refs:
        lines.append("          skipImageReferences:")
        for skip_ref in skip_refs:
            lines.append(f"            - \"{skip_ref}\"")
    if action is not None:
        lines.append(f"          failureAction: {action}")
    if required is not None:
        lines.append(f"          required: {required}")
    canonical = guard.CANONICAL_FIRST_PARTY_ATTESTORS.get(org_glob)
    if canonical is not None:
        issuer = issuer if issuer is not None else canonical["issuer"]
        subject_regexp = (
            subject_regexp
            if subject_regexp is not None
            else canonical["subjectRegExp"]
        )
        roots = roots if roots is not None else guard.FULCIO_ROOTS_PEM
        rekor_url = rekor_url if rekor_url is not None else guard.REKOR_URL
        rekor_pubkey = (
            rekor_pubkey if rekor_pubkey is not None else guard.REKOR_PUBKEY_PEM
        )
        ctlog_pubkey = (
            ctlog_pubkey if ctlog_pubkey is not None else guard.CTFE_PUBKEY_PEM
        )
        ignore_tlog = ignore_tlog if ignore_tlog is not None else "false"
        ignore_sct = ignore_sct if ignore_sct is not None else "false"
        lines.extend(
            [
                "          attestors:",
                "            - entries:",
                "                - keyless:",
                f"                    issuer: \"{issuer}\"",
                f"                    subjectRegExp: '{subject_regexp}'",
                "                    roots: |-",
                *(f"                      {line}" for line in roots.split("\n")),
                "                    rekor:",
                f"                      url: \"{rekor_url}\"",
                f"                      ignoreTlog: {ignore_tlog}",
                "                      pubkey: |-",
                *(
                    f"                        {line}"
                    for line in rekor_pubkey.split("\n")
                ),
                "                    ctlog:",
                f"                      ignoreSCT: {ignore_sct}",
                "                      pubkey: |-",
                *(
                    f"                        {line}"
                    for line in ctlog_pubkey.split("\n")
                ),
            ]
        )
    return "\n".join(lines)


def policy_yaml(
    actions: dict[str, str | None] | None = None,
    missing: tuple[str, ...] = (),
    skips: dict[str, tuple[str, ...]] | None = None,
    validation_action: str = "Audit",
    failure_policy: str = "Ignore",
    include_match_conditions: bool = True,
    match_expression: str | None = None,
    extra_blocks: tuple[str, ...] = (),
    name: str = "verify-image-signatures-enforced",
    background: str | None = "true",
    autogen_controllers: str | None = "none",
    block_kwargs: dict[str, dict[str, object]] | None = None,
) -> str:
    actions = actions or {}
    skips = skips or {}
    block_kwargs = block_kwargs or {}
    blocks: list[str] = []
    for org_glob in guard.FIRST_PARTY_ORG_GLOBS:
        if org_glob in missing:
            continue
        blocks.append(
            verify_block(
                org_glob,
                action=actions.get(org_glob, "Audit"),
                skip_refs=skips.get(org_glob, ()),
                **block_kwargs.get(org_glob, {}),
            )
        )
    blocks.extend(extra_blocks)
    rule_text = "\n".join(blocks)
    match_conditions = (
        match_conditions_yaml(match_expression) if include_match_conditions else ""
    )
    annotations = ""
    if autogen_controllers is not None:
        annotations = (
            "  annotations:\n"
            "    pod-policies.kyverno.io/autogen-controllers: "
            f"{autogen_controllers}\n"
        )
    background_line = f"  background: {background}\n" if background is not None else ""
    header = f"""\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: {name}
{annotations.rstrip()}
spec:
  validationFailureAction: {validation_action}
{background_line.rstrip()}
  webhookConfiguration:
    failurePolicy: {failure_policy}
{match_conditions.rstrip()}
  rules:
"""
    return header + rule_text + "\n"


def _indent_block(text: str, spaces: int) -> list[str]:
    pad = " " * spaces
    return [f"{pad}{line}" for line in text.split("\n")]


def ivp_filename() -> str:
    return guard.FIRST_PARTY_IVP_FILENAME


def ivp_yaml(
    *,
    api_version: str = "policies.kyverno.io/v1beta1",
    policy_name: str | None = None,
    metadata_extra_lines: tuple[str, ...] = (),
    annotation_extra_lines: tuple[str, ...] = (),
    validation_actions: tuple[str, ...] | None = None,
    failure_policy: str | None | object = _UNSET,
    evaluation_mode: str | None = None,
    admission_enabled: str | None = "true",
    background_enabled: str | None = "true",
    match_constraints_operations: tuple[str, ...] = ("CREATE", "UPDATE"),
    autogen_controllers: tuple[str, ...] | None = guard.FIRST_PARTY_IVP_AUTOGEN_CONTROLLERS,
    autogen_extra_lines: tuple[str, ...] = (),
    autogen_pod_controllers_extra_lines: tuple[str, ...] = (),
    include_match_conditions: bool = True,
    match_expression: str | None = None,
    match_condition_name: str | None = None,
    match_condition_extra_lines: tuple[str, ...] = (),
    match_image_references: tuple[str, ...] | None = None,
    match_image_reference_extra_entries: tuple[str, ...] = (),
    attestor_overrides: dict[str, dict[str, object]] | None = None,
    credentials: tuple[str, ...] | None = None,
    credentials_extra_lines: tuple[str, ...] = (),
    extra_spec_blocks: tuple[str, ...] = (),
    validation_expression: str | None = None,
    validation_message: str | None = None,
    validation_extra_lines: tuple[str, ...] = (),
) -> str:
    policy_name = policy_name if policy_name is not None else guard.FIRST_PARTY_IVP_POLICY_NAME
    validation_actions = (
        validation_actions
        if validation_actions is not None
        else (guard.IVP_VALIDATION_ACTION,)
    )
    failure_policy = (
        failure_policy
        if failure_policy is not _UNSET
        else guard.IVP_REQUIRED_FAILURE_POLICY
    )
    credentials = credentials if credentials is not None else guard.FIRST_PARTY_IVP_CREDENTIALS
    match_image_references = (
        match_image_references
        if match_image_references is not None
        else guard.FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES
    )
    match_condition_name = (
        match_condition_name
        if match_condition_name is not None
        else guard.FIRST_PARTY_MATCH_CONDITION_NAME
    )
    match_expression = (
        match_expression
        if match_expression is not None
        else guard.canonical_ivp_match_expression()
    )
    validation_expression = (
        validation_expression
        if validation_expression is not None
        else guard.canonical_ivp_validation_expression()
    )
    validation_message = (
        validation_message
        if validation_message is not None
        else guard.FIRST_PARTY_IVP_VALIDATION_MESSAGE
    )
    attestor_overrides = attestor_overrides or {}

    operations = ", ".join(f'"{op}"' for op in match_constraints_operations)
    actions = ", ".join(validation_actions)
    lines = [
        f"apiVersion: {api_version}",
        "kind: ImageValidatingPolicy",
        "metadata:",
        f"  name: {policy_name}",
        "  annotations:",
        "    policies.kyverno.io/title: Verify First-Party Image Signatures",
        "    policies.kyverno.io/category: Supply Chain Security",
        "    policies.kyverno.io/severity: high",
        *[f"    {line}" for line in annotation_extra_lines],
        *[f"  {line}" for line in metadata_extra_lines],
        "spec:",
        f"  validationActions: [{actions}]",
    ]
    if failure_policy is not None:
        lines.append(f"  failurePolicy: {failure_policy}")
    lines.append("  evaluation:")
    if evaluation_mode is not None:
        lines.append(f"    mode: {evaluation_mode}")
    lines.append("    admission:")
    if admission_enabled is not None:
        lines.append(f"      enabled: {admission_enabled}")
    lines.append("    background:")
    if background_enabled is not None:
        lines.append(f"      enabled: {background_enabled}")
    lines.extend(
        [
            "  matchConstraints:",
            "    resourceRules:",
            '      - apiGroups: [""]',
            '        apiVersions: ["v1"]',
            f"        operations: [{operations}]",
            '        resources: ["pods"]',
        ]
    )
    if autogen_controllers is not None:
        lines.extend(
            [
                "  autogen:",
                "    podControllers:",
                "      controllers:",
            ]
        )
        for controller in autogen_controllers:
            lines.append(f"        - {controller}")
        for line in autogen_pod_controllers_extra_lines:
            lines.append(f"      {line}")
        for line in autogen_extra_lines:
            lines.append(f"    {line}")
    if include_match_conditions:
        lines.extend(
            [
                "  matchConditions:",
                f"    - name: {match_condition_name}",
                "      expression: |-",
                *_indent_block(match_expression, 8),
            ]
        )
        for line in match_condition_extra_lines:
            lines.append(f"      {line}")
    lines.append("  matchImageReferences:")
    for glob in match_image_references:
        lines.append(f'    - glob: "{glob}"')
    for entry in match_image_reference_extra_entries:
        lines.extend(_indent_block(textwrap.dedent(entry).strip(), 4))
    if credentials:
        lines.append("  credentials:")
        lines.append("    secrets:")
        for secret in credentials:
            lines.append(f"      - {secret}")
        for line in credentials_extra_lines:
            lines.append(f"    {line}")
    for block in extra_spec_blocks:
        lines.extend(_indent_block(textwrap.dedent(block).strip(), 2))
    lines.append("  attestors:")
    for org_glob in guard.FIRST_PARTY_IVP_ATTESTOR_ORDER:
        identity = guard.CANONICAL_FIRST_PARTY_ATTESTORS[org_glob]
        overrides = attestor_overrides.get(org_glob, {})
        attestor_name = guard.FIRST_PARTY_IVP_ATTESTORS[org_glob]
        issuer = str(overrides.get("issuer", identity["issuer"]))
        subject_regexp = str(
            overrides.get("subject_regexp", identity["subjectRegExp"])
        )
        roots = str(overrides.get("roots", guard.FULCIO_ROOTS_PEM))
        rekor_url = str(overrides.get("rekor_url", guard.REKOR_URL))
        rekor_pubkey = str(overrides.get("rekor_pubkey", guard.REKOR_PUBKEY_PEM))
        ctlog_pubkey = str(overrides.get("ctlog_pubkey", guard.CTFE_PUBKEY_PEM))
        ignore_tlog = str(overrides.get("ignore_tlog", "false"))
        ignore_sct = str(overrides.get("ignore_sct", "false"))
        lines.extend(
            [
                f"    - name: {attestor_name}",
                "      cosign:",
                "        keyless:",
                "          identities:",
                f'            - issuer: "{issuer}"',
                f"              subjectRegExp: '{subject_regexp}'",
                "          roots: |-",
                *_indent_block(roots, 12),
                "        ctlog:",
                f'          url: "{rekor_url}"',
                "          rekorPubKey: |-",
                *_indent_block(rekor_pubkey, 12),
                "          ctLogPubKey: |-",
                *_indent_block(ctlog_pubkey, 12),
                f"          insecureIgnoreTlog: {ignore_tlog}",
                f"          insecureIgnoreSCT: {ignore_sct}",
            ]
        )
    lines.extend(
        [
            "  validations:",
            "    - expression: |-",
            *_indent_block(validation_expression, 8),
            f'      message: "{validation_message}"',
        ]
    )
    for line in validation_extra_lines:
        lines.append(f"      {line}")
    return "\n".join(lines)


def write_ivps(
    root: Path,
    omit: bool = False,
    overrides: dict[str, object] | None = None,
) -> tuple[str, ...]:
    if omit:
        return ()
    filename = ivp_filename()
    write_yaml(
        policy_dir(root) / filename,
        ivp_yaml(**(overrides or {})),
    )
    return (filename,)


def audit_policy_yaml() -> str:
    return """
    apiVersion: kyverno.io/v1
    kind: ClusterPolicy
    metadata:
      name: verify-image-signatures
      annotations:
        pod-policies.kyverno.io/autogen-controllers: none
    spec:
      validationFailureAction: Audit
      background: true
      webhookConfiguration:
        failurePolicy: Ignore
      rules:
        - name: verify-flux-images
          verifyImages:
            - imageReferences:
                - "ghcr.io/fluxcd/*"
              failureAction: Audit
    """


def audit_policy_with_cilium_skips_yaml() -> str:
    return """
    apiVersion: kyverno.io/v1
    kind: ClusterPolicy
    metadata:
      name: verify-image-signatures
      annotations:
        pod-policies.kyverno.io/autogen-controllers: none
    spec:
      validationFailureAction: Audit
      background: true
      webhookConfiguration:
        failurePolicy: Ignore
      rules:
        - name: verify-cilium-images
          verifyImages:
            - imageReferences:
                - "quay.io/cilium/*"
              skipImageReferences:
                - "quay.io/cilium/startup-script"
                - "quay.io/cilium/cilium-envoy"
              failureAction: Audit
    """


def deployment_yaml(image: str = FIRST_PARTY_IMAGE, namespace: str | None = None) -> str:
    namespace_line = f"\n      namespace: {namespace}" if namespace else ""
    return f"""
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: app{namespace_line}
    spec:
      template:
        spec:
          containers:
            - name: app
              image: {image}
    """


def kustomization_yaml(
    image: str = FIRST_PARTY_IMAGE, namespace: str | None = None
) -> str:
    namespace_line = f"namespace: {namespace}\n" if namespace else ""
    return f"""
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization
    {namespace_line.rstrip()}
    images:
      - name: {image}:v1.2.3
    """


def write_policy_kustomization(
    root: Path,
    resources: tuple[str, ...] = (
        "verify-image-signatures.yaml",
        "verify-image-signatures-enforced.yaml",
    ),
    extra_lines: tuple[str, ...] = (),
) -> None:
    resource_lines = "\n".join(f"  - {resource}" for resource in resources)
    suffix = "\n" + "\n".join(extra_lines) if extra_lines else ""
    write_yaml(
        policy_dir(root) / "kustomization.yaml",
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n"
        f"{resource_lines}"
        f"{suffix}",
    )
    write_flux_policy_kustomization(root)


def write_base_fixture(
    root: Path,
    policy: str | None,
    image: str = FIRST_PARTY_IMAGE,
    namespace: str | None = None,
    kustomize_namespace: str | None = None,
) -> None:
    if policy is not None:
        write_yaml(policy_dir(root) / "verify-image-signatures-enforced.yaml", policy)
    write_yaml(root / "apps/app/deployment.yaml", deployment_yaml(image, namespace))
    write_yaml(
        root / "apps/app/kustomization.yaml",
        kustomization_yaml(image, kustomize_namespace),
    )


def write_real_shape_fixture(
    root: Path,
    enforced_policy: str | None = None,
    image: str = FIRST_PARTY_IMAGE,
    namespace: str | None = None,
    kustomize_namespace: str | None = None,
    ivp_omit: bool = False,
    ivp_overrides: dict[str, object] | None = None,
    ivp_kustomization_omit: bool = False,
) -> None:
    write_yaml(policy_dir(root) / "verify-image-signatures.yaml", audit_policy_yaml())
    write_ivps(root, omit=ivp_omit, overrides=ivp_overrides)
    listed_ivps = () if ivp_omit or ivp_kustomization_omit else (ivp_filename(),)
    write_policy_kustomization(
        root,
        (
            "verify-image-signatures.yaml",
            "verify-image-signatures-enforced.yaml",
        )
        + listed_ivps,
    )
    write_base_fixture(
        root,
        enforced_policy if enforced_policy is not None else policy_yaml(),
        image=image,
        namespace=namespace,
        kustomize_namespace=kustomize_namespace,
    )


def good_fixture(root: Path) -> None:
    write_real_shape_fixture(root)


def org_not_audit_fixture(root: Path) -> None:
    # Every first-party org must carry an Audit rule on this LEGACY policy (it stays
    # Audit until PR-C2 retires it). Re-arming a single org to Enforce (a partial
    # brick re-arm of the #335 defect)
    # drops it out of the Audit-covered set and must bite.
    write_real_shape_fixture(
        root,
        policy_yaml(actions={"ghcr.io/nwarila/*": "Enforce"}),
    )


def removed_org_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(missing=("ghcr.io/the-hero-wars-guys/*",)),
    )


def skipped_image_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            skips={"ghcr.io/nwarila-platform/*": (FIRST_PARTY_IMAGE,)},
        ),
    )


def enforce_skip_not_yet_deployed_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            skips={"ghcr.io/nwarila-platform/*": (FUTURE_FIRST_PARTY_IMAGE,)},
        ),
    )


def audit_skip_image_references_fixture(root: Path) -> None:
    write_yaml(
        policy_dir(root) / "verify-image-signatures.yaml",
        audit_policy_with_cilium_skips_yaml(),
    )
    ivp_filenames = write_ivps(root)
    write_policy_kustomization(
        root,
        (
            "verify-image-signatures.yaml",
            "verify-image-signatures-enforced.yaml",
        )
        + ivp_filenames,
    )
    write_base_fixture(root, policy_yaml())


def inheritance_enforce_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            actions={
                "ghcr.io/nwarila-platform/*": None,
                "ghcr.io/nwarila/*": None,
                "ghcr.io/the-hero-wars-guys/*": None,
            },
            validation_action="Enforce",
        ),
    )


def inheritance_audit_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            actions={
                "ghcr.io/nwarila-platform/*": None,
                "ghcr.io/nwarila/*": None,
                "ghcr.io/the-hero-wars-guys/*": None,
            },
            validation_action="Audit",
        ),
    )


def fail_closed_fixture(root: Path) -> None:
    write_base_fixture(root, policy=None)


def failure_policy_fail_fixture(root: Path) -> None:
    # This LEGACY policy requires failurePolicy: Ignore (fail-open) — it is Audit
    # until PR-C2 retires it, and re-arming it to Fail re-arms the #335 brick.
    # (Current first-party IVP admission is the non-blocking [Audit]/Ignore
    # canary; the follow-up restores [Deny]/Fail there, not here.)
    write_real_shape_fixture(root, policy_yaml(failure_policy="Fail"))


def no_match_conditions_fixture(root: Path) -> None:
    write_real_shape_fixture(root, policy_yaml(include_match_conditions=False))


def cel_missing_org_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(match_expression=cel_expression(guard.FIRST_PARTY_IMAGE_PREFIXES[:-1])),
    )


def cel_missing_initcontainers_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            match_expression=cel_expression(
                fields=("containers", "ephemeralContainers")
            )
        ),
    )


def cel_missing_ephemeralcontainers_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            match_expression=cel_expression(fields=("containers", "initContainers"))
        ),
    )


def cel_extra_restrictive_conjunction_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            match_expression=(
                cel_expression() + " && object.metadata.namespace != 'deploy-vault'"
            )
        ),
    )


def non_first_party_enforce_ref_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            extra_blocks=(
                verify_block(
                    "ghcr.io/not-first-party/*",
                    rule_name="verify-not-first-party-images",
                ),
            )
        ),
    )


def fail_mutate_no_matchconditions_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_yaml(
        policy_dir(root) / "fail-mutate-no-matchconditions.yaml",
        """
        apiVersion: kyverno.io/v1
        kind: ClusterPolicy
        metadata:
          name: fail-mutate-no-matchconditions
        spec:
          webhookConfiguration:
            failurePolicy: Fail
          rules:
            - name: mutate-label
              mutate:
                patchStrategicMerge:
                  metadata:
                    labels:
                      example.com/mutated: "true"
        """,
    )
    write_policy_kustomization(
        root,
        (
            "verify-image-signatures.yaml",
            "verify-image-signatures-enforced.yaml",
            "fail-mutate-no-matchconditions.yaml",
        )
        + (ivp_filename(),),
    )


def fail_mutate_no_webhook_configuration_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_yaml(
        policy_dir(root) / "fail-mutate-no-webhook-configuration.yaml",
        """
        apiVersion: kyverno.io/v1
        kind: ClusterPolicy
        metadata:
          name: fail-mutate-no-webhook-configuration
        spec:
          rules:
            - name: mutate-label
              mutate:
                patchStrategicMerge:
                  metadata:
                    labels:
                      example.com/mutated: "true"
        """,
    )
    write_policy_kustomization(
        root,
        (
            "verify-image-signatures.yaml",
            "verify-image-signatures-enforced.yaml",
            "fail-mutate-no-webhook-configuration.yaml",
        )
        + (ivp_filename(),),
    )


def first_party_in_excluded_namespace_fixture(root: Path) -> None:
    write_real_shape_fixture(root, namespace="kube-system")


def first_party_in_kube_public_fixture(root: Path) -> None:
    write_real_shape_fixture(root, namespace="kube-public")


def first_party_in_kube_node_lease_fixture(root: Path) -> None:
    write_real_shape_fixture(root, namespace="kube-node-lease")


def first_party_in_kustomize_namespace_fixture(root: Path) -> None:
    write_real_shape_fixture(root, kustomize_namespace="kube-system")


def missing_policy_kustomization_resource_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_policy_kustomization(
        root,
        ("verify-image-signatures.yaml",)
        + (ivp_filename(),),
    )


def kyverno_default_registry_ghcr_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_yaml(
        root / "apps/kyverno/release/helmrelease.yaml",
        """
        apiVersion: helm.toolkit.fluxcd.io/v2
        kind: HelmRelease
        metadata:
          name: kyverno
          namespace: kyverno
        spec:
          values:
            config:
              defaultRegistry: ghcr.io
        """,
    )


def attestor_subject_wildcard_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            block_kwargs={
                "ghcr.io/nwarila-platform/*": {"subject_regexp": ".*"},
            },
        ),
    )


def attestor_required_false_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            block_kwargs={
                "ghcr.io/nwarila-platform/*": {"required": "false"},
            },
        ),
    )


def attestor_rekor_repointed_fixture(root: Path) -> None:
    # Repoint the Rekor verification key to a valid-but-wrong key (the CTFE key):
    # the guard's exact-match against the pinned REKOR_PUBKEY_PEM must bite.
    write_real_shape_fixture(
        root,
        policy_yaml(
            block_kwargs={
                "ghcr.io/nwarila-platform/*": {
                    "rekor_pubkey": guard.CTFE_PUBKEY_PEM,
                },
            },
        ),
    )


def attestor_ignore_tlog_true_fixture(root: Path) -> None:
    # ignoreTlog: true is the DANGEROUS keyless mode (drops the signing-time anchor
    # for the ephemeral Fulcio cert). The guard's exact-match (pins "false") must bite.
    write_real_shape_fixture(
        root,
        policy_yaml(
            block_kwargs={
                "ghcr.io/nwarila-platform/*": {"ignore_tlog": "true"},
            },
        ),
    )


def attestor_rekor_url_repointed_fixture(root: Path) -> None:
    # rekor.url is a runtime dead fallback, but repointing it to a rogue log is a
    # weakening (it would be used for a bundle-less signature); the pinned REKOR_URL
    # exact-match must bite.
    write_real_shape_fixture(
        root,
        policy_yaml(
            block_kwargs={
                "ghcr.io/nwarila-platform/*": {
                    "rekor_url": "https://rekor.attacker.example",
                },
            },
        ),
    )


def attestor_issuer_changed_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            block_kwargs={
                "ghcr.io/nwarila-platform/*": {
                    "issuer": "https://issuer.attacker.example",
                },
            },
        ),
    )


def rule_exclude_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            block_kwargs={
                "ghcr.io/nwarila-platform/*": {
                    "rule_extra_lines": (
                        "      exclude:",
                        "        any:",
                        "          - resources:",
                        "              namespaces:",
                        "                - deploy-vault",
                    ),
                },
            },
        ),
    )


def rule_match_namespaces_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            block_kwargs={
                "ghcr.io/nwarila-platform/*": {
                    "match_namespaces": ("unused-ns",),
                },
            },
        ),
    )


def rule_preconditions_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(
            block_kwargs={
                "ghcr.io/nwarila-platform/*": {
                    "rule_extra_lines": (
                        "      preconditions:",
                        "        all:",
                        "          - key: \"{{ request.namespace }}\"",
                        "            operator: Equals",
                        "            value: never-fire",
                    ),
                },
            },
        ),
    )


def background_false_fixture(root: Path) -> None:
    write_real_shape_fixture(root, policy_yaml(background="false"))


def autogen_removed_fixture(root: Path) -> None:
    write_real_shape_fixture(root, policy_yaml(autogen_controllers=None))


# ---- ImageValidatingPolicy (IVP) weakening fixtures --------------------------
# Independent constructions (NOT the guard's own parser) so a parser bug cannot
# hide a real weakening. The clean baseline (one merged IVP) is written by
# write_real_shape_fixture; each case mutates that IVP via ivp_overrides.
HWG_ORG = "ghcr.io/the-hero-wars-guys/*"
NWARILA_ORG = "ghcr.io/nwarila/*"


def ivp_weak_cel(
    prefix: str,
    fields: tuple[str, ...] = ("containers", "initContainers", "ephemeralContainers"),
) -> str:
    clauses = [
        f"(has(object.spec.{field}) && object.spec.{field}.exists(c, "
        f"c.image.startsWith('{prefix}')))"
        for field in fields
    ]
    return "object != null && (\n  " + " ||\n  ".join(clauses) + "\n)"


def ivp_weak_validation(
    fields: tuple[str, ...] = ("containers", "initContainers", "ephemeralContainers"),
) -> str:
    clauses = [
        f"images.{field}.all(image,\n"
        "  image.startsWith('ghcr.io/the-hero-wars-guys/') ? "
        "verifyImageSignatures(image, [attestors.hwg]) > 0 :\n"
        "  image.startsWith('ghcr.io/nwarila-platform/') ? "
        "verifyImageSignatures(image, [attestors.nwarila_platform]) > 0 :\n"
        "  verifyImageSignatures(image, [attestors.nwarila]) > 0)"
        for field in fields
    ]
    return " &&\n".join(clauses)


def ivp_over(org_glob: str, **kwargs: object) -> dict[str, object]:
    attestor_keys = {
        "issuer",
        "subject_regexp",
        "roots",
        "rekor_url",
        "rekor_pubkey",
        "ctlog_pubkey",
        "ignore_tlog",
        "ignore_sct",
    }
    attestor_overrides = {
        key: value for key, value in kwargs.items() if key in attestor_keys
    }
    merged_overrides = {
        key: value for key, value in kwargs.items() if key not in attestor_keys
    }
    if attestor_overrides:
        merged_overrides["attestor_overrides"] = {org_glob: attestor_overrides}
    return merged_overrides


def different_ivp_validation_action(suffix: str) -> str:
    return f"{guard.IVP_VALIDATION_ACTION}-{suffix}"


def different_ivp_failure_policy() -> str:
    return f"{guard.IVP_REQUIRED_FAILURE_POLICY}-different"


def ivp_missing_org_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides={
            "match_image_references": tuple(
                glob
                for glob in guard.FIRST_PARTY_IVP_MATCH_IMAGE_REFERENCES
                if glob != HWG_ORG
            )
        },
    )


def ivp_api_version_alpha_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides={"api_version": "policies.kyverno.io/v1alpha1"},
    )


def ivp_metadata_autogen_annotation_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides={
            "annotation_extra_lines": (
                "pod-policies.kyverno.io/autogen-controllers: none",
            )
        },
    )


def ivp_validation_action_audit_fixture(root: Path) -> None:
    # Name kept for continuity; the assertion is posture-agnostic.
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG,
            validation_actions=(different_ivp_validation_action("different"),),
        ),
    )


def ivp_validation_action_warn_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG,
            validation_actions=(different_ivp_validation_action("Warn"),),
        ),
    )


def ivp_failure_policy_ignore_fixture(root: Path) -> None:
    # Name kept for continuity; the assertion is posture-agnostic.
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG,
            failure_policy=different_ivp_failure_policy(),
        ),
    )


def ivp_admission_disabled_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, admission_enabled="false")
    )


def ivp_background_disabled_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, background_enabled="false")
    )


def ivp_images_extractors_shadow_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG,
            extra_spec_blocks=(
                """
                images:
                  - name: containers
                    expression: "[]"
                  - name: initContainers
                    expression: "[]"
                  - name: ephemeralContainers
                    expression: "[]"
                """,
            ),
        ),
    )


def ivp_evaluation_mode_json_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, evaluation_mode="JSON")
    )


def ivp_validationconfigurations_required_false_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG,
            extra_spec_blocks=(
                """
                validationConfigurations:
                  required: false
                """,
            ),
        ),
    )


def ivp_unknown_spec_key_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG,
            extra_spec_blocks=(
                """
                webhookConfiguration:
                  failurePolicy: Ignore
                """,
            ),
        ),
    )


def ivp_matchconstraints_narrowed_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG, match_constraints_operations=("CREATE",)
        ),
    )


def ivp_autogen_narrowed_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG, autogen_controllers=("deployments", "jobs")
        ),
    )


def ivp_no_matchconditions_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, include_match_conditions=False)
    )


def ivp_matchconditions_missing_field_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG,
            match_expression=ivp_weak_cel(
                "ghcr.io/nwarila/", fields=("containers", "ephemeralContainers")
            ),
        ),
    )


def ivp_matchconditions_wrong_org_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG, match_expression=ivp_weak_cel("ghcr.io/the-hero-wars-guys/")
        ),
    )


def ivp_matchimagereferences_broadened_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(NWARILA_ORG, match_image_references=("ghcr.io/*",)),
    )


def ivp_attestor_roots_repointed_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, roots=guard.CTFE_PUBKEY_PEM)
    )


def ivp_attestor_rekor_repointed_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, rekor_pubkey=guard.CTFE_PUBKEY_PEM)
    )


def ivp_attestor_ctlog_repointed_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, ctlog_pubkey=guard.REKOR_PUBKEY_PEM)
    )


def ivp_attestor_ignore_tlog_true_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, ignore_tlog="true")
    )


def ivp_attestor_ignore_sct_true_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, ignore_sct="true")
    )


def ivp_attestor_rekor_url_repointed_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG, rekor_url="https://rekor.attacker.example"
        ),
    )


def ivp_attestor_issuer_changed_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(NWARILA_ORG, issuer="https://issuer.attacker.example"),
    )


def ivp_attestor_subject_wildcard_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root, ivp_overrides=ivp_over(NWARILA_ORG, subject_regexp=".*")
    )


def ivp_validations_weakened_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            NWARILA_ORG,
            validation_expression=ivp_weak_validation(
                fields=("containers", "ephemeralContainers")
            ),
        ),
    )


def ivp_hwg_credentials_dropped_fixture(root: Path) -> None:
    write_real_shape_fixture(root, ivp_overrides=ivp_over(HWG_ORG, credentials=()))


def ivp_credentials_allow_insecure_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            HWG_ORG,
            credentials_extra_lines=("allowInsecureRegistry: true",),
        ),
    )


def ivp_credentials_providers_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            HWG_ORG,
            credentials_extra_lines=("providers: [github]",),
        ),
    )


def ivp_matchimagereferences_expression_entry_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            HWG_ORG,
            match_image_reference_extra_entries=('- expression: "true"',),
        ),
    )


def ivp_autogen_extra_key_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            HWG_ORG,
            autogen_pod_controllers_extra_lines=("mode: all",),
        ),
    )


def ivp_matchconditions_extra_field_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            HWG_ORG,
            match_condition_extra_lines=("message: widened match condition",),
        ),
    )


def ivp_validations_extra_field_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        ivp_overrides=ivp_over(
            HWG_ORG,
            validation_extra_lines=("reason: Forbidden",),
        ),
    )


def ivp_kustomization_patches_weaken_render_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_policy_kustomization(
        root,
        (
            "verify-image-signatures.yaml",
            "verify-image-signatures-enforced.yaml",
            ivp_filename(),
        ),
        extra_lines=(
            "patches:",
            "  - target:",
            "      kind: ImageValidatingPolicy",
            f"      name: {guard.FIRST_PARTY_IVP_POLICY_NAME}",
            "    patch: |-",
            "      - op: replace",
            "        path: /spec/validations/0/expression",
            '        value: "true"',
            "      - op: replace",
            "        path: /spec/attestors/0/cosign/keyless/identities/0/subjectRegExp",
            '        value: ".*"',
        ),
    )


def ivp_kustomization_components_weaken_render_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_yaml(
        policy_dir(root) / "weaken-ivp-component/kustomization.yaml",
        f"""
        apiVersion: kustomize.config.k8s.io/v1alpha1
        kind: Component
        patches:
          - target:
              kind: ImageValidatingPolicy
              name: {guard.FIRST_PARTY_IVP_POLICY_NAME}
            patch: |-
              - op: replace
                path: /spec/validations/0/expression
                value: "true"
        """,
    )
    write_policy_kustomization(
        root,
        (
            "verify-image-signatures.yaml",
            "verify-image-signatures-enforced.yaml",
            ivp_filename(),
        ),
        extra_lines=(
            "components:",
            "  - weaken-ivp-component",
        ),
    )


def flux_kustomization_spec_patches_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_flux_policy_kustomization(
        root,
        extra_spec_lines=(
            "patches:",
            "  - target:",
            "      kind: ImageValidatingPolicy",
            f"      name: {guard.FIRST_PARTY_IVP_POLICY_NAME}",
            "    patch: |-",
            "      - op: replace",
            "        path: /spec/validations/0/expression",
            '        value: "true"',
        ),
    )


def flux_wrapper_patches_redirect_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    applied_dir = policy_dir(root).parent / "policies-applied"
    write_yaml(
        applied_dir / "kustomization.yaml",
        f"""
        apiVersion: kustomize.config.k8s.io/v1beta1
        kind: Kustomization
        resources:
          - ../policies
        patches:
          - target:
              kind: ImageValidatingPolicy
              name: {guard.FIRST_PARTY_IVP_POLICY_NAME}
            patch: |-
              - op: replace
                path: /spec/validations/0/expression
                value: "true"
              - op: replace
                path: /spec/attestors/0/cosign/keyless/identities/0/subjectRegExp
                value: ".*"
        """,
    )
    write_flux_policy_kustomization(
        root,
        "./clusters/talos-cluster/apps/kyverno/policies-applied",
    )


def flux_wrapper_components_redirect_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    applied_dir = policy_dir(root).parent / "policies-applied"
    write_yaml(
        applied_dir / "weaken-ivp-component/kustomization.yaml",
        f"""
        apiVersion: kustomize.config.k8s.io/v1alpha1
        kind: Component
        patches:
          - target:
              kind: ImageValidatingPolicy
              name: {guard.FIRST_PARTY_IVP_POLICY_NAME}
            patch: |-
              - op: replace
                path: /spec/validations/0/expression
                value: "true"
              - op: replace
                path: /spec/attestors/0/cosign/keyless/identities/0/subjectRegExp
                value: ".*"
        """,
    )
    write_yaml(
        applied_dir / "kustomization.yaml",
        """
        apiVersion: kustomize.config.k8s.io/v1beta1
        kind: Kustomization
        resources:
          - ../policies
        components:
          - weaken-ivp-component
        """,
    )
    write_flux_policy_kustomization(
        root,
        "./clusters/talos-cluster/apps/kyverno/policies-applied",
    )


def flux_kyverno_policies_path_drift_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    drift_dir = policy_dir(root).parent / "policies-drift"
    write_yaml(
        drift_dir / "kustomization.yaml",
        """
        apiVersion: kustomize.config.k8s.io/v1beta1
        kind: Kustomization
        resources: []
        """,
    )
    write_flux_policy_kustomization(
        root,
        "./clusters/talos-cluster/apps/kyverno/policies-drift",
    )


def flux_dangling_spec_path_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_yaml(
        root / "clusters/talos-cluster/apps/dangling-kustomization.yaml",
        """
        apiVersion: kustomize.toolkit.fluxcd.io/v1
        kind: Kustomization
        metadata:
          name: dangling-local-path
          namespace: flux-system
        spec:
          interval: 10m
          path: ./clusters/talos-cluster/apps/does-not-exist
          prune: true
          sourceRef:
            kind: GitRepository
            name: flux-system
        """,
    )


def ivp_file_not_in_kustomization_fixture(root: Path) -> None:
    write_real_shape_fixture(root, ivp_kustomization_omit=True)


def ivp_second_policy_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_yaml(
        policy_dir(root) / "second-ivp.yaml",
        f"""
        apiVersion: policies.kyverno.io/v1beta1
        kind: ImageValidatingPolicy
        metadata:
          name: second-ivp
        spec:
          validationActions: [{guard.IVP_VALIDATION_ACTION}]
          failurePolicy: {guard.IVP_REQUIRED_FAILURE_POLICY}
          matchConstraints:
            resourceRules:
              - apiGroups: [""]
                apiVersions: ["v1"]
                operations: ["CREATE"]
                resources: ["pods"]
          matchConditions:
            - name: scoped
              expression: "object != null"
          matchImageReferences:
            - glob: "example.com/*"
          attestors: []
          validations:
            - expression: "true"
        """,
    )
    write_policy_kustomization(
        root,
        (
            "verify-image-signatures.yaml",
            "verify-image-signatures-enforced.yaml",
            ivp_filename(),
            "second-ivp.yaml",
        ),
    )


def ivp_remote_kustomization_resource_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_policy_kustomization(
        root,
        (
            "verify-image-signatures.yaml",
            "verify-image-signatures-enforced.yaml",
            ivp_filename(),
            "https://example.invalid/kyverno/remote-ivp.yaml",
        ),
    )


def ivp_fail_no_matchconditions_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_yaml(
        policy_dir(root) / "extra-fail-ivp.yaml",
        f"""
        apiVersion: policies.kyverno.io/v1beta1
        kind: ImageValidatingPolicy
        metadata:
          name: extra-fail-ivp
        spec:
          validationActions: [{guard.IVP_VALIDATION_ACTION}]
          failurePolicy: Fail
          matchConstraints:
            resourceRules:
              - apiGroups: [""]
                apiVersions: ["v1"]
                operations: ["CREATE"]
                resources: ["pods"]
          matchImageReferences:
            - glob: "example.com/*"
          attestors: []
          validations:
            - expression: "true"
        """,
    )
    write_policy_kustomization(
        root,
        (
            "verify-image-signatures.yaml",
            "verify-image-signatures-enforced.yaml",
            "extra-fail-ivp.yaml",
        )
        + (ivp_filename(),),
    )


def run_guard_for_roots(roots: tuple[Path, ...]) -> GuardRun:
    try:
        result = guard.evaluate_roots(roots)
    except guard.GuardUsageError as exc:
        return GuardRun(rc=2, findings=[f"usage error: {exc}"])
    return GuardRun(
        rc=guard.exit_code_for_findings(result.findings),
        findings=result.findings,
    )


def run_guard(root: Path) -> GuardRun:
    return run_guard_for_roots((root,))


def run_case(
    name: str,
    expected_rc: int,
    evidence: str,
    fixture: Callable[[Path], None],
    expected_fragments: tuple[str, ...] = (),
) -> CaseResult:
    with tempfile.TemporaryDirectory(prefix="image-signature-guard-") as tmpdir:
        root = Path(tmpdir)
        fixture(root)
        run = run_guard(root)

    findings_text = "\n".join(run.findings)
    fragments_present = all(fragment in findings_text for fragment in expected_fragments)
    empty_matches_rc = (not run.findings and run.rc == 0) or (
        bool(run.findings) and run.rc in (1, 2)
    )
    passed = (
        run.rc == expected_rc
        and fragments_present
        and empty_matches_rc
    )
    return CaseResult(
        name=name,
        expected_rc=expected_rc,
        actual_rc=run.rc,
        finding_count=len(run.findings),
        evidence=evidence,
        passed=passed,
        findings=run.findings,
    )


def run_repository_case(
    name: str,
    expected_rc: int,
    evidence: str,
    expected_fragments: tuple[str, ...] = (),
) -> CaseResult:
    run = run_guard_for_roots(tuple(ROOT / root for root in guard.DEFAULT_ROOTS))
    findings_text = "\n".join(run.findings)
    fragments_present = all(fragment in findings_text for fragment in expected_fragments)
    empty_matches_rc = (not run.findings and run.rc == 0) or (
        bool(run.findings) and run.rc in (1, 2)
    )
    passed = (
        run.rc == expected_rc
        and fragments_present
        and empty_matches_rc
    )
    return CaseResult(
        name=name,
        expected_rc=expected_rc,
        actual_rc=run.rc,
        finding_count=len(run.findings),
        evidence=evidence,
        passed=passed,
        findings=run.findings,
    )


def ivp_canary_expiry_case(
    name: str,
    expected_rc: int,
    evidence: str,
    *,
    today: str,
    validation_action: str,
    failure_policy: str,
    expected_fragments: tuple[str, ...] = (),
) -> CaseResult:
    original_today = guard.current_date
    original_action = guard.IVP_VALIDATION_ACTION
    original_failure_policy = guard.IVP_REQUIRED_FAILURE_POLICY
    original_expires = guard.IVP_CANARY_EXPIRES
    try:
        guard.current_date = lambda: date.fromisoformat(today)
        guard.IVP_VALIDATION_ACTION = validation_action
        guard.IVP_REQUIRED_FAILURE_POLICY = failure_policy
        guard.IVP_CANARY_EXPIRES = "2026-08-01"
        with tempfile.TemporaryDirectory(prefix="image-signature-guard-") as tmpdir:
            root = Path(tmpdir)
            write_real_shape_fixture(root)
            run = run_guard(root)
    finally:
        guard.current_date = original_today
        guard.IVP_VALIDATION_ACTION = original_action
        guard.IVP_REQUIRED_FAILURE_POLICY = original_failure_policy
        guard.IVP_CANARY_EXPIRES = original_expires

    findings_text = "\n".join(run.findings)
    fragments_present = all(fragment in findings_text for fragment in expected_fragments)
    empty_matches_rc = (not run.findings and run.rc == 0) or (
        bool(run.findings) and run.rc in (1, 2)
    )
    passed = (
        run.rc == expected_rc
        and fragments_present
        and empty_matches_rc
    )
    return CaseResult(
        name=name,
        expected_rc=expected_rc,
        actual_rc=run.rc,
        finding_count=len(run.findings),
        evidence=evidence,
        passed=passed,
        findings=run.findings,
    )


def missing_canonical_attestor_case() -> CaseResult:
    missing_org = "ghcr.io/example-missing/*"
    original_org_globs = guard.FIRST_PARTY_ORG_GLOBS
    original_prefixes = guard.FIRST_PARTY_IMAGE_PREFIXES
    try:
        guard.FIRST_PARTY_ORG_GLOBS = original_org_globs + (missing_org,)
        guard.FIRST_PARTY_IMAGE_PREFIXES = tuple(
            org_glob[:-1] for org_glob in guard.FIRST_PARTY_ORG_GLOBS
        )
        return run_case(
            "constants-missing-canonical-attestor",
            2,
            "startup consistency assert exits 2",
            good_fixture,
            (
                "FIRST_PARTY_ORG_GLOBS and CANONICAL_FIRST_PARTY_ATTESTORS "
                "disagree",
                f"missing canonical entry for {missing_org!r}",
            ),
        )
    finally:
        guard.FIRST_PARTY_ORG_GLOBS = original_org_globs
        guard.FIRST_PARTY_IMAGE_PREFIXES = original_prefixes


def dropped_ivp_match_prefix_case() -> CaseResult:
    dropped_prefix = "ghcr.io/nwarila/"
    original_match_prefixes = guard.FIRST_PARTY_IVP_MATCH_PREFIXES
    try:
        guard.FIRST_PARTY_IVP_MATCH_PREFIXES = tuple(
            prefix
            for prefix in original_match_prefixes
            if prefix != dropped_prefix
        )
        return run_case(
            "constants-dropped-ivp-match-prefix",
            2,
            "startup match-prefix consistency assert exits 2",
            good_fixture,
            (
                "FIRST_PARTY_ORG_GLOBS and FIRST_PARTY_IVP_MATCH_PREFIXES "
                "disagree",
                f"missing merged IVP match prefix for {dropped_prefix!r}",
            ),
        )
    finally:
        guard.FIRST_PARTY_IVP_MATCH_PREFIXES = original_match_prefixes


def extra_ivp_match_prefix_case() -> CaseResult:
    extra_prefix = "ghcr.io/example-extra/"
    original_match_prefixes = guard.FIRST_PARTY_IVP_MATCH_PREFIXES
    try:
        guard.FIRST_PARTY_IVP_MATCH_PREFIXES = (
            original_match_prefixes + (extra_prefix,)
        )
        return run_case(
            "constants-extra-ivp-match-prefix",
            2,
            "startup match-prefix consistency assert exits 2",
            good_fixture,
            (
                "FIRST_PARTY_ORG_GLOBS and FIRST_PARTY_IVP_MATCH_PREFIXES "
                "disagree",
                f"extra merged IVP match prefix for {extra_prefix!r}",
            ),
        )
    finally:
        guard.FIRST_PARTY_IVP_MATCH_PREFIXES = original_match_prefixes


def attestor_order_missing_case() -> CaseResult:
    missing_org = "ghcr.io/the-hero-wars-guys/*"
    original_attestor_order = guard.FIRST_PARTY_IVP_ATTESTOR_ORDER
    try:
        guard.FIRST_PARTY_IVP_ATTESTOR_ORDER = tuple(
            org_glob
            for org_glob in original_attestor_order
            if org_glob != missing_org
        )
        return run_case(
            "constants-attestor-order-missing",
            2,
            "startup attestor-order consistency assert exits 2",
            good_fixture,
            (
                "FIRST_PARTY_IVP_ATTESTOR_ORDER and FIRST_PARTY_IVP_ATTESTORS "
                "disagree",
                f"missing IVP attestor order entry for {missing_org!r}",
            ),
        )
    finally:
        guard.FIRST_PARTY_IVP_ATTESTOR_ORDER = original_attestor_order


def exit_code_invariant_case(results: list[CaseResult]) -> CaseResult:
    invariant_holds = all(
        (result.finding_count == 0 and result.actual_rc == 0)
        or (result.finding_count > 0 and result.actual_rc == 1)
        or (
            result.finding_count > 0
            and result.actual_rc == 2
            and any(finding.startswith("usage error:") for finding in result.findings)
        )
        for result in results
    )
    return CaseResult(
        name="exit-code-invariant",
        expected_rc=0,
        actual_rc=0 if invariant_holds else 1,
        finding_count=0,
        evidence="empty findings -> 0; policy findings -> 1; usage errors -> 2",
        passed=invariant_holds,
        findings=[],
    )


def output_tail(text: str, line_count: int = 16) -> str:
    lines = text.splitlines()
    if len(lines) > line_count:
        lines = ["..."] + lines[-line_count:]
    return "\n".join(lines)


def print_table(results: list[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    evidence_width = max(len("evidence"), *(len(result.evidence) for result in results))
    print(
        f"{'case':<{name_width}}  expected  actual  findings  "
        f"{'evidence':<{evidence_width}}  result"
    )
    print(
        f"{'-' * name_width}  --------  ------  --------  "
        f"{'-' * evidence_width}  ------"
    )
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.name:<{name_width}}  "
            f"{result.expected_rc:^8}  {result.actual_rc:^6}  "
            f"{result.finding_count:^8}  {result.evidence:<{evidence_width}}  "
            f"{status}"
        )


def main() -> int:
    results = [
        run_repository_case(
            "real-repository-tree",
            0,
            "actual clusters/addons tree passes",
        ),
        run_case("real-two-policy-shape", 0, "clean split policy shape", good_fixture),
        run_case(
            "audit-cilium-skipimage-references",
            0,
            "Audit cilium skipImageReferences allowed",
            audit_skip_image_references_fixture,
        ),
        ivp_canary_expiry_case(
            "ivp-canary-expired-canary-posture",
            1,
            "expired Audit/Ignore canary turns CI red",
            today="2026-08-01",
            validation_action="Audit",
            failure_policy="Ignore",
            expected_fragments=(
                "canary expired on 2026-08-01",
                "Flip verify-first-party",
                "extend IVP_CANARY_EXPIRES with a recorded reason",
            ),
        ),
        ivp_canary_expiry_case(
            "ivp-canary-expired-steady-state",
            0,
            "expired date is inert after [Deny]/Fail",
            today="2026-08-02",
            validation_action="Deny",
            failure_policy="Fail",
        ),
        ivp_canary_expiry_case(
            "ivp-canary-before-expiry",
            0,
            "Audit/Ignore canary remains green before expiry",
            today="2026-07-31",
            validation_action="Audit",
            failure_policy="Ignore",
        ),
        missing_canonical_attestor_case(),
        dropped_ivp_match_prefix_case(),
        extra_ivp_match_prefix_case(),
        attestor_order_missing_case(),
        run_case(
            "attestor-subject-wildcard",
            1,
            "I7 subjectRegExp wildcard bites",
            attestor_subject_wildcard_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "attestor-required-false",
            1,
            "I7 required:false bites",
            attestor_required_false_fixture,
            ("must set required: true",),
        ),
        run_case(
            "attestor-rekor-repointed",
            1,
            "I7 Rekor pubkey repoint bites",
            attestor_rekor_repointed_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "attestor-ignore-tlog-true",
            1,
            "I7 ignoreTlog:true (insecure keyless) bites",
            attestor_ignore_tlog_true_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "attestor-rekor-url-repointed",
            1,
            "I7 rekor.url repoint bites",
            attestor_rekor_url_repointed_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "attestor-issuer-changed",
            1,
            "I7 issuer swap bites",
            attestor_issuer_changed_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "rule-exclude",
            1,
            "I8 rule exclude bites",
            rule_exclude_fixture,
            ("must not declare rule-level exclude",),
        ),
        run_case(
            "rule-match-namespaces",
            1,
            "I8 match namespace narrowing bites",
            rule_match_namespaces_fixture,
            ("match must exactly equal",),
        ),
        run_case(
            "rule-preconditions",
            1,
            "I8 preconditions bite",
            rule_preconditions_fixture,
            ("must not declare preconditions",),
        ),
        run_case(
            "policy-background-false",
            1,
            "I9 background:false bites",
            background_false_fixture,
            ("spec.background: true",),
        ),
        run_case(
            "policy-autogen-removed",
            1,
            "I9 autogen removal bites",
            autogen_removed_fixture,
            ("autogen-controllers]: none",),
        ),
        run_case(
            "posture-org-not-audit",
            1,
            "single org re-armed to Enforce bites (legacy policy stays Audit)",
            org_not_audit_fixture,
            ("first-party org ghcr.io/nwarila/* has no Audit signature rule",),
        ),
        run_case(
            "posture-removed-org",
            1,
            "posture removal bites",
            removed_org_fixture,
            (
                "first-party org ghcr.io/the-hero-wars-guys/* "
                "has no Audit signature rule",
            ),
        ),
        run_case(
            "coverage-skipped-image",
            1,
            "coverage skip bites",
            skipped_image_fixture,
            ("first-party image not signature-covered (Audit):",),
        ),
        run_case(
            "enforce-skip-not-yet-deployed-image",
            1,
            "I10 Enforce skipImageReferences bites",
            enforce_skip_not_yet_deployed_fixture,
            (
                "Enforce verifyImages block must not declare "
                "skipImageReferences",
                FUTURE_FIRST_PARTY_IMAGE,
            ),
        ),
        run_case(
            "inheritance-audit",
            0,
            "policy-level Audit inheritance counts",
            inheritance_audit_fixture,
        ),
        run_case(
            "inheritance-enforce",
            1,
            "policy-level Enforce does not count",
            inheritance_enforce_fixture,
            (
                "no first-party image-signature policy with failureAction: "
                "Audit found",
            ),
        ),
        run_case(
            "fail-closed-no-policy",
            1,
            "zero Audit blocks bite",
            fail_closed_fixture,
            (
                "no first-party image-signature policy with failureAction: "
                "Audit found",
            ),
        ),
        run_case(
            "interim-failure-policy-fail",
            1,
            "failurePolicy: Fail re-arms the brick",
            failure_policy_fail_fixture,
            ("webhookConfiguration.failurePolicy: Ignore",),
        ),
        run_case(
            "enforce-no-matchconditions",
            1,
            "I2/I4 empty matchConditions bite",
            no_match_conditions_fixture,
            ("must declare exactly one matchCondition",),
        ),
        run_case(
            "cel-missing-org-prefix",
            1,
            "I2 missing org prefix bites",
            cel_missing_org_fixture,
            ("does not exactly match the canonical",),
        ),
        run_case(
            "cel-missing-initcontainers",
            1,
            "I2 missing initContainers bites",
            cel_missing_initcontainers_fixture,
            ("does not exactly match the canonical",),
        ),
        run_case(
            "cel-missing-ephemeralcontainers",
            1,
            "I2 missing ephemeralContainers bites",
            cel_missing_ephemeralcontainers_fixture,
            ("does not exactly match the canonical",),
        ),
        run_case(
            "cel-extra-restrictive-conjunction",
            1,
            "I2 exact match defeats appended carve-out",
            cel_extra_restrictive_conjunction_fixture,
            ("does not exactly match the canonical",),
        ),
        run_case(
            "interim-non-first-party-ref",
            1,
            "I3 non-first-party ref in interim policy bites",
            non_first_party_enforce_ref_fixture,
            ("outside FIRST_PARTY_ORG_GLOBS",),
        ),
        run_case(
            "fail-mutate-no-matchconditions",
            1,
            "I4 mutate-only brick guard bites",
            fail_mutate_no_matchconditions_fixture,
            ("mutate or verifyImages rules must declare non-empty matchConditions",),
        ),
        run_case(
            "fail-mutate-no-webhook-configuration",
            1,
            "D2 absent webhookConfiguration defaults to Fail",
            fail_mutate_no_webhook_configuration_fixture,
            ("mutate or verifyImages rules must declare non-empty matchConditions",),
        ),
        run_case(
            "first-party-kube-system",
            1,
            "I5 excluded namespace bypass bites",
            first_party_in_excluded_namespace_fixture,
            ("Kyverno-exempt namespace (kube-system)",),
        ),
        run_case(
            "first-party-kube-public",
            1,
            "D1 resourceFilters kube-public bypass bites",
            first_party_in_kube_public_fixture,
            ("Kyverno-exempt namespace (kube-public)",),
        ),
        run_case(
            "first-party-kube-node-lease",
            1,
            "D1 resourceFilters kube-node-lease bypass bites",
            first_party_in_kube_node_lease_fixture,
            ("Kyverno-exempt namespace (kube-node-lease)",),
        ),
        run_case(
            "first-party-kustomize-namespace",
            1,
            "D3 kustomize namespace bypass bites",
            first_party_in_kustomize_namespace_fixture,
            ("Kyverno-exempt namespace (kube-system)",),
        ),
        run_case(
            "missing-policy-kustomization-resource",
            1,
            "N1 unlisted policy resource bites",
            missing_policy_kustomization_resource_fixture,
            ("not listed in its directory kustomization.yaml resources",),
        ),
        run_case(
            "kyverno-defaultregistry-ghcr",
            1,
            "I6 defaultRegistry coupling bites",
            kyverno_default_registry_ghcr_fixture,
            ("config.defaultRegistry must remain docker.io",),
        ),
        run_case(
            "ivp-missing-org",
            1,
            "IVP1 missing merged matchImageReferences org bites",
            ivp_missing_org_fixture,
            (
                "first-party org ghcr.io/the-hero-wars-guys/* has no "
                "ImageValidatingPolicy matchImageReferences coverage",
            ),
        ),
        run_case(
            "ivp-api-version-alpha",
            1,
            "IVP1 exact apiVersion pin bites",
            ivp_api_version_alpha_fixture,
            ("apiVersion must be exactly policies.kyverno.io/v1beta1",),
        ),
        run_case(
            "ivp-metadata-autogen-annotation",
            1,
            "IVP1 metadata annotation allowlist bites",
            ivp_metadata_autogen_annotation_fixture,
            (
                "metadata.annotations key is not guard-allowlisted",
                "pod-policies.kyverno.io/autogen-controllers",
            ),
        ),
        run_case(
            "ivp-second-policy",
            1,
            "IVP1 a second IVP resurrects Kyverno IVP defects",
            ivp_second_policy_fixture,
            ("source policy files must contain exactly one ImageValidatingPolicy",),
        ),
        run_case(
            "ivp-remote-kustomization-resource",
            1,
            "IVP1 remote kustomization resource is unverifiable and bites",
            ivp_remote_kustomization_resource_fixture,
            (
                "kustomization references remote resource",
                "policies/kustomization.yaml -> "
                "https://example.invalid/kyverno/remote-ivp.yaml",
            ),
        ),
        run_case(
            "ivp-kustomization-patches-weaken-render",
            1,
            "rendered kustomize patches weakening bites",
            ivp_kustomization_patches_weaken_render_fixture,
            (
                "<kubectl kustomize>",
                "validations must be exactly one verifyImageSignatures expression",
                "attestors must exactly match",
            ),
        ),
        run_case(
            "ivp-kustomization-components-weaken-render",
            1,
            "rendered kustomize components weakening bites",
            ivp_kustomization_components_weaken_render_fixture,
            (
                "<kubectl kustomize>",
                "validations must be exactly one verifyImageSignatures expression",
            ),
        ),
        run_case(
            "flux-kustomization-spec-patches",
            1,
            "Flux post-render policy patch bites",
            flux_kustomization_spec_patches_fixture,
            (
                "Flux Kustomization whose rendered output contains an "
                "ImageValidatingPolicy",
                "must not declare spec.patches",
            ),
        ),
        run_case(
            "flux-wrapper-patches-redirect",
            1,
            "Flux wrapper path with patches weakening bites",
            flux_wrapper_patches_redirect_fixture,
            (
                "spec.path exactly to "
                f"{guard.KYVERNO_POLICIES_REPO_PATH}",
                "<kubectl kustomize>",
                "validations must be exactly one verifyImageSignatures expression",
                "attestors must exactly match",
            ),
        ),
        run_case(
            "flux-wrapper-components-redirect",
            1,
            "Flux wrapper path with component weakening bites",
            flux_wrapper_components_redirect_fixture,
            (
                "spec.path exactly to "
                f"{guard.KYVERNO_POLICIES_REPO_PATH}",
                "<kubectl kustomize>",
                "validations must be exactly one verifyImageSignatures expression",
                "attestors must exactly match",
            ),
        ),
        run_case(
            "flux-kyverno-policies-path-drift",
            1,
            "kyverno-policies spec.path drift bites",
            flux_kyverno_policies_path_drift_fixture,
            (
                "Flux Kustomization kyverno-policies must set spec.path exactly",
                "policies-drift",
            ),
        ),
        run_case(
            "flux-dangling-spec-path",
            1,
            "dangling local Flux spec.path bites",
            flux_dangling_spec_path_fixture,
            (
                "Flux Kustomization spec.path does not exist in this repo",
                "dangling-local-path",
            ),
        ),
        run_case(
            "ivp-validation-action-audit",
            1,
            "IVP2 non-configured validationActions value bites",
            ivp_validation_action_audit_fixture,
            (f"validationActions must be [{guard.IVP_VALIDATION_ACTION}]",),
        ),
        run_case(
            "ivp-validation-action-warn",
            1,
            "IVP2 non-configured validationActions value bites",
            ivp_validation_action_warn_fixture,
            (f"validationActions must be [{guard.IVP_VALIDATION_ACTION}]",),
        ),
        run_case(
            "ivp-failure-policy-ignore",
            1,
            "IVP2 non-configured failurePolicy value bites",
            ivp_failure_policy_ignore_fixture,
            (
                "must set spec.failurePolicy: "
                f"{guard.IVP_REQUIRED_FAILURE_POLICY}",
            ),
        ),
        run_case(
            "ivp-admission-disabled",
            1,
            "IVP3 disabling the admission path bites (the migration's point)",
            ivp_admission_disabled_fixture,
            ("spec.evaluation.admission.enabled: true",),
        ),
        run_case(
            "ivp-background-disabled",
            1,
            "IVP3 disabling background (PolicyReports) bites",
            ivp_background_disabled_fixture,
            ("spec.evaluation.background.enabled: true",),
        ),
        run_case(
            "ivp-images-extractors-shadow",
            1,
            "IVP3 spec.images extractor shadowing bites",
            ivp_images_extractors_shadow_fixture,
            (
                "not guard-allowlisted",
                "silently alter signature-verification semantics",
                "pin it explicitly in this guard",
                "spec.images",
            ),
        ),
        run_case(
            "ivp-evaluation-mode-json",
            1,
            "IVP3 evaluation.mode JSON leaves admission path",
            ivp_evaluation_mode_json_fixture,
            ("spec.evaluation.mode must be absent or Kubernetes", "found JSON"),
        ),
        run_case(
            "ivp-validationconfigurations-required-false",
            1,
            "IVP3 validationConfigurations.required:false bites",
            ivp_validationconfigurations_required_false_fixture,
            (
                "not guard-allowlisted",
                "silently alter signature-verification semantics",
                "spec.validationConfigurations",
            ),
        ),
        run_case(
            "ivp-unknown-spec-key-webhookconfiguration",
            1,
            "IVP3 arbitrary unknown spec key bites",
            ivp_unknown_spec_key_fixture,
            (
                "not guard-allowlisted",
                "pin it explicitly in this guard",
                "spec.webhookConfiguration",
            ),
        ),
        run_case(
            "ivp-matchconstraints-narrowed",
            1,
            "IVP4 narrowing matchConstraints operations bites",
            ivp_matchconstraints_narrowed_fixture,
            ("matchConstraints must exactly equal",),
        ),
        run_case(
            "ivp-autogen-narrowed",
            1,
            "IVP4 narrowed spec.autogen controller set bites",
            ivp_autogen_narrowed_fixture,
            ("spec.autogen.podControllers.controllers must preserve",),
        ),
        run_case(
            "ivp-autogen-extra-key",
            1,
            "IVP4 unpinned spec.autogen nested field bites",
            ivp_autogen_extra_key_fixture,
            (
                "spec.autogen.podControllers key is not guard-allowlisted",
                "controller-created Pods receive signature verification",
                "spec.autogen.podControllers.mode",
            ),
        ),
        run_case(
            "ivp-no-matchconditions",
            1,
            "IVP5 empty matchConditions bite",
            ivp_no_matchconditions_fixture,
            ("must declare exactly one matchCondition",),
        ),
        run_case(
            "ivp-matchconditions-missing-field",
            1,
            "IVP5 dropping initContainers from the CEL bites",
            ivp_matchconditions_missing_field_fixture,
            ("matchConditions expression does not exactly match the canonical",),
        ),
        run_case(
            "ivp-matchconditions-wrong-org",
            1,
            "IVP5 wrong-org CEL prefix bites",
            ivp_matchconditions_wrong_org_fixture,
            ("matchConditions expression does not exactly match the canonical",),
        ),
        run_case(
            "ivp-matchconditions-extra-field",
            1,
            "IVP5 unpinned spec.matchConditions nested field bites",
            ivp_matchconditions_extra_field_fixture,
            (
                "spec.matchConditions key is not guard-allowlisted",
                "API-server webhook selection",
                "spec.matchConditions.message",
            ),
        ),
        run_case(
            "ivp-matchimagereferences-broadened",
            1,
            "IVP6 broadening matchImageReferences bites",
            ivp_matchimagereferences_broadened_fixture,
            ("matchImageReferences must be exactly",),
        ),
        run_case(
            "ivp-matchimagereferences-expression-entry",
            1,
            "IVP6 expression-only matchImageReferences entry bites",
            ivp_matchimagereferences_expression_entry_fixture,
            (
                "spec.matchImageReferences key is not guard-allowlisted",
                "expression can bypass the pinned glob set",
                "spec.matchImageReferences.expression",
            ),
        ),
        run_case(
            "ivp-attestor-roots-repointed",
            1,
            "IVP7 Fulcio roots repoint bites",
            ivp_attestor_roots_repointed_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "ivp-attestor-rekor-repointed",
            1,
            "IVP7 Rekor pubkey repoint bites",
            ivp_attestor_rekor_repointed_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "ivp-attestor-ctlog-repointed",
            1,
            "IVP7 CT-log pubkey repoint bites",
            ivp_attestor_ctlog_repointed_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "ivp-attestor-ignore-tlog-true",
            1,
            "IVP7 insecureIgnoreTlog:true (insecure keyless) bites",
            ivp_attestor_ignore_tlog_true_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "ivp-attestor-ignore-sct-true",
            1,
            "IVP7 insecureIgnoreSCT:true bites",
            ivp_attestor_ignore_sct_true_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "ivp-attestor-rekor-url-repointed",
            1,
            "IVP7 ctlog.url repoint bites",
            ivp_attestor_rekor_url_repointed_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "ivp-attestor-issuer-changed",
            1,
            "IVP7 issuer swap bites",
            ivp_attestor_issuer_changed_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "ivp-attestor-subject-wildcard",
            1,
            "IVP7 subjectRegExp wildcard bites",
            ivp_attestor_subject_wildcard_fixture,
            ("attestors must exactly match",),
        ),
        run_case(
            "ivp-validations-weakened",
            1,
            "IVP8 dropping a container type from validations bites",
            ivp_validations_weakened_fixture,
            ("validations must be exactly one verifyImageSignatures expression",),
        ),
        run_case(
            "ivp-validations-extra-field",
            1,
            "IVP8 unpinned spec.validations nested field bites",
            ivp_validations_extra_field_fixture,
            (
                "spec.validations key is not guard-allowlisted",
                "signature-verification semantics",
                "spec.validations.reason",
            ),
        ),
        run_case(
            "ivp-hwg-credentials-dropped",
            1,
            "IVP9 dropping the shared ghcr-pull image-pull secret bites",
            ivp_hwg_credentials_dropped_fixture,
            ("spec.credentials.secrets must be exactly ['ghcr-pull']",),
        ),
        run_case(
            "ivp-credentials-allow-insecure",
            1,
            "IVP9 credentials.allowInsecureRegistry:true bites",
            ivp_credentials_allow_insecure_fixture,
            (
                "spec.credentials key is not guard-allowlisted",
                "allowInsecureRegistry permits plaintext or skip-TLS registry fetches",
                "spec.credentials.allowInsecureRegistry",
            ),
        ),
        run_case(
            "ivp-credentials-providers",
            1,
            "IVP9 credentials.providers bites",
            ivp_credentials_providers_fixture,
            (
                "spec.credentials key is not guard-allowlisted",
                "credential lookup",
                "spec.credentials.providers",
            ),
        ),
        run_case(
            "ivp-file-not-in-kustomization",
            1,
            "IVP10 an unlisted IVP file bites",
            ivp_file_not_in_kustomization_fixture,
            ("not listed in its directory kustomization.yaml resources",),
        ),
        run_case(
            "ivp-fail-no-matchconditions",
            1,
            "IVP11 Fail IVP without matchConditions (shared fail webhook) bites",
            ivp_fail_no_matchconditions_fixture,
            (
                "failurePolicy: Fail ImageValidatingPolicy must declare non-empty "
                "matchConditions",
            ),
        ),
    ]
    results.append(exit_code_invariant_case(results))

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for result in failures:
            print(
                f"\n[{result.name}] expected rc {result.expected_rc}, "
                f"got rc {result.actual_rc}",
                file=sys.stderr,
            )
            if result.findings:
                print("findings tail:", file=sys.stderr)
                print(output_tail("\n".join(result.findings)), file=sys.stderr)
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
