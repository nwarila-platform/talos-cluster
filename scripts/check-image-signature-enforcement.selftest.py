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


def verify_block(
    org_glob: str,
    action: str | None = "Enforce",
    skip_refs: tuple[str, ...] = (),
) -> str:
    lines = [
        "    - name: verify-" + org_glob.removeprefix("ghcr.io/").removesuffix("/*"),
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
    validation_action: str = "Audit",
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
    rule_text = "\n".join(blocks)
    header = f"""\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: {validation_action}
  rules:
"""
    return header + rule_text + "\n"


def deployment_yaml(image: str = FIRST_PARTY_IMAGE) -> str:
    return f"""
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: app
    spec:
      template:
        spec:
          containers:
            - name: app
              image: {image}
    """


def kustomization_yaml(image: str = FIRST_PARTY_IMAGE) -> str:
    return f"""
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization
    images:
      - name: {image}:v1.2.3
    """


def write_base_fixture(root: Path, policy: str | None) -> None:
    if policy is not None:
        write_yaml(root / "policies/verify-image-signatures.yaml", policy)
    write_yaml(root / "apps/app/deployment.yaml", deployment_yaml())
    write_yaml(root / "apps/app/kustomization.yaml", kustomization_yaml())


def good_fixture(root: Path) -> None:
    write_base_fixture(root, policy_yaml())


def downgraded_org_fixture(root: Path) -> None:
    write_base_fixture(
        root,
        policy_yaml(actions={"ghcr.io/nwarila/*": "Audit"}),
    )


def removed_org_fixture(root: Path) -> None:
    write_base_fixture(
        root,
        policy_yaml(missing=("ghcr.io/the-hero-wars-guys/*",)),
    )


def skipped_image_fixture(root: Path) -> None:
    write_base_fixture(
        root,
        policy_yaml(
            skips={"ghcr.io/nwarila-platform/*": (FIRST_PARTY_IMAGE,)},
        ),
    )


def inheritance_enforce_fixture(root: Path) -> None:
    write_base_fixture(
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
    write_base_fixture(
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
        run_case("good", 0, "clean posture and coverage", good_fixture),
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
