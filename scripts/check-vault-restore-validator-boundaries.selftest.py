#!/usr/bin/env python3
"""Regression self-test for the vault restore-validator boundary guard."""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROOT_KUSTOMIZATION = ROOT / "clusters/talos-cluster/kustomization.yaml"
APPS_DIR = ROOT / "clusters/talos-cluster/apps"
CRONJOB = APPS_DIR / "vault-restore-validator/cronjob.yaml"
GUARD = ROOT / "scripts/check-vault-restore-validator-boundaries.sh"

FORCE_OFFLINE_APPEND = """

# guard-selftest: force the guard's GUARD_OFFLINE root-render fallback.
resources:
  - __guard_selftest_force_offline_missing_resource__
"""


@dataclass(frozen=True)
class GuardRun:
    rc: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Case:
    key: str
    description: str
    expect_pass: bool
    mutate: Callable[[], contextlib.AbstractContextManager[None]]


@dataclass(frozen=True)
class CaseResult:
    key: str
    description: str
    expected: str
    rc: int
    passed: bool
    stdout: str
    stderr: str


def dedent_yaml(text: str) -> bytes:
    return (textwrap.dedent(text).strip() + "\n").encode("utf-8")


def run_guard() -> GuardRun:
    env = os.environ.copy()
    env["GUARD_OFFLINE"] = "1"
    result = subprocess.run(
        ["bash", str(GUARD.relative_to(ROOT))],
        cwd=ROOT,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return GuardRun(result.returncode, result.stdout, result.stderr)


@contextlib.contextmanager
def temporary_bytes(path: Path, content: bytes) -> Iterator[None]:
    existed = path.exists()
    original = path.read_bytes() if existed else None
    path.write_bytes(content)
    try:
        yield
    finally:
        if existed:
            assert original is not None
            path.write_bytes(original)
        else:
            path.unlink(missing_ok=True)


def probe_path(key: str) -> Path:
    return APPS_DIR / f"zz-guard-selftest-{key.lower()}.yaml"


def probe_file(key: str, content: str) -> contextlib.AbstractContextManager[None]:
    return temporary_bytes(probe_path(key), dedent_yaml(content))


def load_cronjob() -> dict:
    document = yaml.safe_load(CRONJOB.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError(f"{CRONJOB.relative_to(ROOT)} did not parse as a mapping")
    return document


def cronjob_container(document: dict) -> dict:
    containers = (
        document["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"]
    )
    if len(containers) != 1 or not isinstance(containers[0], dict):
        raise RuntimeError("CronJob/dr-restore-driver does not have exactly one container")
    return containers[0]


def edit_cronjob(mutator: Callable[[dict], None]) -> contextlib.AbstractContextManager[None]:
    document = load_cronjob()
    mutator(document)
    content = yaml.safe_dump(document, sort_keys=False).encode("utf-8")
    return temporary_bytes(CRONJOB, content)


def cronjob_with_lifecycle() -> contextlib.AbstractContextManager[None]:
    def mutate(document: dict) -> None:
        cronjob_container(document)["lifecycle"] = {
            "preStop": {
                "exec": {
                    "command": ["/bin/sh", "-c", "true"],
                },
            },
        }

    return edit_cronjob(mutate)


def cronjob_with_ssa_ignore() -> contextlib.AbstractContextManager[None]:
    def mutate(document: dict) -> None:
        metadata = document.setdefault("metadata", {})
        annotations = metadata.setdefault("annotations", {})
        annotations["kustomize.toolkit.fluxcd.io/ssa"] = "Ignore"

    return edit_cronjob(mutate)


def cases() -> list[Case]:
    return [
        Case(
            "A",
            "ClusterRoleBinding grants cluster-admin to system:serviceaccounts:dr-validate",
            False,
            lambda: probe_file(
                "A",
                """
                apiVersion: rbac.authorization.k8s.io/v1
                kind: ClusterRoleBinding
                metadata:
                  name: guard-selftest-a-group-cluster-admin
                subjects:
                  - kind: Group
                    apiGroup: rbac.authorization.k8s.io
                    name: system:serviceaccounts:dr-validate
                roleRef:
                  apiGroup: rbac.authorization.k8s.io
                  kind: ClusterRole
                  name: cluster-admin
                """,
            ),
        ),
        Case(
            "C",
            "Deployment in dr-validate runs as dr-orchestrator",
            False,
            lambda: probe_file(
                "C",
                """
                apiVersion: apps/v1
                kind: Deployment
                metadata:
                  name: guard-selftest-c-dr-orchestrator
                  namespace: dr-validate
                spec:
                  selector:
                    matchLabels:
                      app: guard-selftest-c
                  template:
                    metadata:
                      labels:
                        app: guard-selftest-c
                    spec:
                      serviceAccountName: dr-orchestrator
                      containers:
                        - name: pause
                          image: registry.k8s.io/pause:3.10
                """,
            ),
        ),
        Case(
            "D",
            "Role in longhorn-system grants delete on longhorn.io volumes",
            False,
            lambda: probe_file(
                "D",
                """
                apiVersion: rbac.authorization.k8s.io/v1
                kind: Role
                metadata:
                  name: guard-selftest-d-delete-volume
                  namespace: longhorn-system
                rules:
                  - apiGroups:
                      - longhorn.io
                    resources:
                      - volumes
                    verbs:
                      - delete
                """,
            ),
        ),
        Case(
            "F",
            "CiliumClusterwideNetworkPolicy selects validator pods and allows world egress",
            False,
            lambda: probe_file(
                "F",
                """
                apiVersion: cilium.io/v2
                kind: CiliumClusterwideNetworkPolicy
                metadata:
                  name: guard-selftest-f-world-egress
                spec:
                  endpointSelector:
                    matchLabels:
                      app.kubernetes.io/name: vault-restore-validator
                  egress:
                    - toEntities:
                        - world
                """,
            ),
        ),
        Case(
            "H",
            "MutatingWebhookConfiguration targets pods",
            False,
            lambda: probe_file(
                "H",
                """
                apiVersion: admissionregistration.k8s.io/v1
                kind: MutatingWebhookConfiguration
                metadata:
                  name: guard-selftest-h-pods
                webhooks:
                  - name: pods.guard-selftest.example.com
                    clientConfig:
                      service:
                        namespace: kube-system
                        name: guard-selftest
                        path: /mutate
                    admissionReviewVersions:
                      - v1
                    sideEffects: None
                    rules:
                      - apiGroups:
                          - ""
                        apiVersions:
                          - v1
                        operations:
                          - CREATE
                        resources:
                          - pods
                """,
            ),
        ),
        Case(
            "I",
            "Role copycat carries the Longhorn volume create identity scope",
            False,
            lambda: probe_file(
                "I",
                """
                apiVersion: rbac.authorization.k8s.io/v1
                kind: Role
                metadata:
                  name: copycat
                  namespace: longhorn-system
                rules:
                  - apiGroups:
                      - longhorn.io
                    resources:
                      - volumes
                    verbs:
                      - create
                      - get
                      - list
                      - watch
                """,
            ),
        ),
        Case(
            "K",
            "ClusterRoleBinding grants cluster-admin to default in dr-validate",
            False,
            lambda: probe_file(
                "K",
                """
                apiVersion: rbac.authorization.k8s.io/v1
                kind: ClusterRoleBinding
                metadata:
                  name: guard-selftest-k-default-cluster-admin
                subjects:
                  - kind: ServiceAccount
                    name: default
                    namespace: dr-validate
                roleRef:
                  apiGroup: rbac.authorization.k8s.io
                  kind: ClusterRole
                  name: cluster-admin
                """,
            ),
        ),
        Case(
            "M",
            "Secret creates a dr-orchestrator service-account token in dr-validate",
            False,
            lambda: probe_file(
                "M",
                """
                apiVersion: v1
                kind: Secret
                metadata:
                  name: guard-selftest-m-dr-orchestrator-token
                  namespace: dr-validate
                  annotations:
                    kubernetes.io/service-account.name: dr-orchestrator
                type: kubernetes.io/service-account-token
                """,
            ),
        ),
        Case(
            "N",
            "RoleBinding points attacker at dr-orchestrator-longhorn-restore",
            False,
            lambda: probe_file(
                "N",
                """
                apiVersion: rbac.authorization.k8s.io/v1
                kind: RoleBinding
                metadata:
                  name: guard-selftest-n-attacker
                  namespace: longhorn-system
                subjects:
                  - kind: User
                    apiGroup: rbac.authorization.k8s.io
                    name: attacker
                roleRef:
                  apiGroup: rbac.authorization.k8s.io
                  kind: Role
                  name: dr-orchestrator-longhorn-restore
                """,
            ),
        ),
        Case(
            "O",
            "ClusterRole grants impersonate on serviceaccounts",
            False,
            lambda: probe_file(
                "O",
                """
                apiVersion: rbac.authorization.k8s.io/v1
                kind: ClusterRole
                metadata:
                  name: guard-selftest-o-impersonate-serviceaccounts
                rules:
                  - apiGroups:
                      - ""
                    resources:
                      - serviceaccounts
                    verbs:
                      - impersonate
                """,
            ),
        ),
        Case(
            "S",
            "Longhorn Volume restore references data-vault backup material",
            False,
            lambda: probe_file(
                "S",
                """
                apiVersion: longhorn.io/v1beta2
                kind: Volume
                metadata:
                  name: guard-selftest-s-data-vault
                  namespace: longhorn-system
                spec:
                  fromBackup: s3://guard-selftest/data-vault
                """,
            ),
        ),
        Case(
            "Q1",
            "Flux Kustomization targets dr-validate",
            False,
            lambda: probe_file(
                "Q1",
                """
                apiVersion: kustomize.toolkit.fluxcd.io/v1
                kind: Kustomization
                metadata:
                  name: guard-selftest-q1-target-namespace
                  namespace: flux-system
                spec:
                  interval: 10m
                  path: ./clusters/talos-cluster/apps/vault-restore-validator
                  prune: true
                  sourceRef:
                    kind: GitRepository
                    name: flux-system
                  targetNamespace: dr-validate
                """,
            ),
        ),
        Case(
            "Q2",
            "Flux Kustomization uses postBuild substitution",
            False,
            lambda: probe_file(
                "Q2",
                """
                apiVersion: kustomize.toolkit.fluxcd.io/v1
                kind: Kustomization
                metadata:
                  name: guard-selftest-q2-postbuild
                  namespace: flux-system
                spec:
                  interval: 10m
                  path: ./clusters/talos-cluster/apps/vault-restore-validator
                  prune: true
                  sourceRef:
                    kind: GitRepository
                    name: flux-system
                  postBuild:
                    substitute:
                      X: y
                """,
            ),
        ),
        Case(
            "E",
            "CronJob container defines lifecycle",
            False,
            cronjob_with_lifecycle,
        ),
        Case(
            "L",
            "CronJob opts out of Flux SSA",
            False,
            cronjob_with_ssa_ignore,
        ),
        Case(
            "benign-configmap",
            "ConfigMap in kube-system remains outside the validator footprint",
            True,
            lambda: probe_file(
                "benign-configmap",
                """
                apiVersion: v1
                kind: ConfigMap
                metadata:
                  name: guard-selftest-benign-outside-footprint
                  namespace: kube-system
                data:
                  ok: "true"
                """,
            ),
        ),
        Case(
            "benign-longhorn-readonly",
            "Role in longhorn-system grants read-only Longhorn volume access",
            True,
            lambda: probe_file(
                "benign-longhorn-readonly",
                """
                apiVersion: rbac.authorization.k8s.io/v1
                kind: Role
                metadata:
                  name: guard-selftest-benign-longhorn-readonly
                  namespace: longhorn-system
                rules:
                  - apiGroups:
                      - longhorn.io
                    resources:
                      - volumes
                    verbs:
                      - get
                      - list
                      - watch
                """,
            ),
        ),
    ]


def result_for(key: str, description: str, expect_pass: bool, run: GuardRun) -> CaseResult:
    passed = run.rc == 0 if expect_pass else run.rc != 0
    return CaseResult(
        key=key,
        description=description,
        expected="rc 0" if expect_pass else "rc != 0",
        rc=run.rc,
        passed=passed,
        stdout=run.stdout,
        stderr=run.stderr,
    )


def output_tail(text: str, line_count: int = 24) -> str:
    lines = text.splitlines()
    if len(lines) > line_count:
        lines = ["..."] + lines[-line_count:]
    return "\n".join(lines)


def print_table(results: list[CaseResult]) -> None:
    key_width = max(len("case"), *(len(result.key) for result in results))
    expected_width = max(len("expected"), *(len(result.expected) for result in results))
    rc_width = max(len("rc"), *(len(str(result.rc)) for result in results))
    print(
        f"{'case':<{key_width}}  {'expected':<{expected_width}}  "
        f"{'rc':>{rc_width}}  result  description"
    )
    print(
        f"{'-' * key_width}  {'-' * expected_width}  "
        f"{'-' * rc_width}  ------  -----------"
    )
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.key:<{key_width}}  {result.expected:<{expected_width}}  "
            f"{result.rc:>{rc_width}}  {status:<6}  {result.description}"
        )


def residue_errors(original_root: bytes, original_cronjob: bytes, probe_paths: list[Path]) -> list[str]:
    errors: list[str] = []
    if ROOT_KUSTOMIZATION.read_bytes() != original_root:
        errors.append(f"{ROOT_KUSTOMIZATION.relative_to(ROOT)} was not restored")
    if CRONJOB.read_bytes() != original_cronjob:
        errors.append(f"{CRONJOB.relative_to(ROOT)} was not restored")
    for path in probe_paths:
        if path.exists():
            errors.append(f"{path.relative_to(ROOT)} still exists")
    return errors


def main() -> int:
    os.chdir(ROOT)
    all_cases = cases()
    probe_paths = [probe_path(case.key) for case in all_cases if case.key not in {"E", "L"}]
    existing_probe_paths = [path for path in probe_paths if path.exists()]
    if existing_probe_paths:
        print("refusing to overwrite existing guard selftest probe path(s):", file=sys.stderr)
        for path in existing_probe_paths:
            print(f"  - {path.relative_to(ROOT)}", file=sys.stderr)
        return 2

    original_root = ROOT_KUSTOMIZATION.read_bytes()
    original_cronjob = CRONJOB.read_bytes()
    results: list[CaseResult] = []
    cleanup_errors: list[str] = []

    try:
        ROOT_KUSTOMIZATION.write_bytes(
            original_root + FORCE_OFFLINE_APPEND.encode("utf-8")
        )
        baseline = run_guard()
        results.append(
            result_for(
                "baseline",
                "clean tree with forced GUARD_OFFLINE fallback",
                True,
                baseline,
            )
        )
        if baseline.rc == 0:
            for case in all_cases:
                with case.mutate():
                    run = run_guard()
                results.append(
                    result_for(case.key, case.description, case.expect_pass, run)
                )
    finally:
        ROOT_KUSTOMIZATION.write_bytes(original_root)
        CRONJOB.write_bytes(original_cronjob)
        for path in probe_paths:
            path.unlink(missing_ok=True)
        cleanup_errors = residue_errors(original_root, original_cronjob, probe_paths)

    print_table(results)

    failures = [result for result in results if not result.passed]
    if cleanup_errors:
        print("\ncleanup regression(s):", file=sys.stderr)
        for error in cleanup_errors:
            print(f"  - {error}", file=sys.stderr)

    if failures:
        print("\ncase regression detail:", file=sys.stderr)
        for result in failures:
            print(
                f"\n[{result.key}] expected {result.expected}, got rc {result.rc}: "
                f"{result.description}",
                file=sys.stderr,
            )
            stderr_tail = output_tail(result.stderr)
            stdout_tail = output_tail(result.stdout)
            if stderr_tail:
                print("stderr tail:", file=sys.stderr)
                print(stderr_tail, file=sys.stderr)
            if stdout_tail:
                print("stdout tail:", file=sys.stderr)
                print(stdout_tail, file=sys.stderr)

    if cleanup_errors or failures:
        return 1

    print("\nPASS: guard boundary selftest completed with no residue")
    return 0


if __name__ == "__main__":
    sys.exit(main())
