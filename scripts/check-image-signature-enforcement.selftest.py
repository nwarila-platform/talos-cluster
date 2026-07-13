#!/usr/bin/env python3
"""Offline regression self-test for the image signature enforcement guard."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-image-signature-enforcement.py"
FIRST_PARTY_IMAGE = "ghcr.io/nwarila-platform/foo"


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
    action: str | None = "Enforce",
    skip_refs: tuple[str, ...] = (),
    rule_name: str | None = None,
) -> str:
    if rule_name is None:
        rule_name = "verify-" + org_glob.removeprefix("ghcr.io/").removesuffix("/*")
    lines = [
        f"    - name: {rule_name}",
        "      verifyImages:",
        "        - imageReferences:",
        f"            - \"{org_glob}\"",
    ]
    if skip_refs:
        lines.append("          skipImageReferences:")
        for skip_ref in skip_refs:
            lines.append(f"            - \"{skip_ref}\"")
    if action is not None:
        lines.append(f"          failureAction: {action}")
    return "\n".join(lines)


def policy_yaml(
    actions: dict[str, str | None] | None = None,
    missing: tuple[str, ...] = (),
    skips: dict[str, tuple[str, ...]] | None = None,
    validation_action: str = "Enforce",
    failure_policy: str = "Fail",
    include_match_conditions: bool = True,
    match_expression: str | None = None,
    extra_blocks: tuple[str, ...] = (),
    name: str = "verify-image-signatures-enforced",
) -> str:
    actions = actions or {}
    skips = skips or {}
    blocks: list[str] = []
    for org_glob in guard.FIRST_PARTY_ORG_GLOBS:
        if org_glob in missing:
            continue
        blocks.append(
            verify_block(
                org_glob,
                action=actions.get(org_glob, "Enforce"),
                skip_refs=skips.get(org_glob, ()),
            )
        )
    blocks.extend(extra_blocks)
    rule_text = "\n".join(blocks)
    match_conditions = (
        match_conditions_yaml(match_expression) if include_match_conditions else ""
    )
    header = f"""\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: {name}
spec:
  validationFailureAction: {validation_action}
  webhookConfiguration:
    failurePolicy: {failure_policy}
{match_conditions.rstrip()}
  rules:
"""
    return header + rule_text + "\n"


def audit_policy_yaml() -> str:
    return """
    apiVersion: kyverno.io/v1
    kind: ClusterPolicy
    metadata:
      name: verify-image-signatures
    spec:
      validationFailureAction: Audit
      webhookConfiguration:
        failurePolicy: Ignore
      rules:
        - name: verify-flux-images
          verifyImages:
            - imageReferences:
                - "ghcr.io/fluxcd/*"
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
) -> None:
    resource_lines = "\n".join(f"  - {resource}" for resource in resources)
    write_yaml(
        root / "policies/kustomization.yaml",
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n"
        f"{resource_lines}",
    )


def write_base_fixture(
    root: Path,
    policy: str | None,
    image: str = FIRST_PARTY_IMAGE,
    namespace: str | None = None,
    kustomize_namespace: str | None = None,
) -> None:
    if policy is not None:
        write_yaml(root / "policies/verify-image-signatures-enforced.yaml", policy)
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
) -> None:
    write_yaml(root / "policies/verify-image-signatures.yaml", audit_policy_yaml())
    write_policy_kustomization(root)
    write_base_fixture(
        root,
        enforced_policy if enforced_policy is not None else policy_yaml(),
        image=image,
        namespace=namespace,
        kustomize_namespace=kustomize_namespace,
    )


def good_fixture(root: Path) -> None:
    write_real_shape_fixture(root)


def downgraded_org_fixture(root: Path) -> None:
    write_real_shape_fixture(
        root,
        policy_yaml(actions={"ghcr.io/nwarila/*": "Audit"}),
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


def failure_policy_ignore_fixture(root: Path) -> None:
    write_real_shape_fixture(root, policy_yaml(failure_policy="Ignore"))


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
        root / "policies/fail-mutate-no-matchconditions.yaml",
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
        ),
    )


def fail_mutate_no_webhook_configuration_fixture(root: Path) -> None:
    write_real_shape_fixture(root)
    write_yaml(
        root / "policies/fail-mutate-no-webhook-configuration.yaml",
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
        ),
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
    write_policy_kustomization(root, ("verify-image-signatures.yaml",))


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


def run_guard(root: Path) -> GuardRun:
    try:
        result = guard.evaluate_roots((root,))
    except guard.GuardUsageError as exc:
        return GuardRun(rc=2, findings=[f"usage error: {exc}"])
    return GuardRun(
        rc=guard.exit_code_for_findings(result.findings),
        findings=result.findings,
    )


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
        bool(run.findings) and run.rc == 1
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


def exit_code_invariant_case(results: list[CaseResult]) -> CaseResult:
    invariant_holds = all(
        (result.finding_count == 0 and result.actual_rc == 0)
        or (result.finding_count > 0 and result.actual_rc == 1)
        for result in results
    )
    return CaseResult(
        name="exit-code-invariant",
        expected_rc=0,
        actual_rc=0 if invariant_holds else 1,
        finding_count=0,
        evidence="empty findings -> 0; non-empty findings -> 1",
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
        run_case("real-two-policy-shape", 0, "clean split policy shape", good_fixture),
        run_case(
            "posture-downgraded-audit",
            1,
            "posture downgrade bites",
            downgraded_org_fixture,
            ("first-party org ghcr.io/nwarila/* has no Enforce signature rule",),
        ),
        run_case(
            "posture-removed-org",
            1,
            "posture removal bites",
            removed_org_fixture,
            (
                "first-party org ghcr.io/the-hero-wars-guys/* "
                "has no Enforce signature rule",
            ),
        ),
        run_case(
            "coverage-skipped-image",
            1,
            "coverage skip bites",
            skipped_image_fixture,
            ("first-party image not signature-Enforced:",),
        ),
        run_case(
            "inheritance-enforce",
            0,
            "policy-level Enforce counts",
            inheritance_enforce_fixture,
        ),
        run_case(
            "inheritance-audit",
            1,
            "policy-level Audit does not count",
            inheritance_audit_fixture,
            ("no Enforce image-signature policy found",),
        ),
        run_case(
            "fail-closed-no-policy",
            1,
            "zero Enforce blocks bite",
            fail_closed_fixture,
            ("no Enforce image-signature policy found",),
        ),
        run_case(
            "enforce-failure-policy-ignore",
            1,
            "I1 fail-open policy bites",
            failure_policy_ignore_fixture,
            ("webhookConfiguration.failurePolicy: Fail",),
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
            "enforce-non-first-party-ref",
            1,
            "I3 non-first-party Enforce ref bites",
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
