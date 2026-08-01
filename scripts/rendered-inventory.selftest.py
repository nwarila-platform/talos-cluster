#!/usr/bin/env python3
"""Branch-complete self-test for rendered-inventory.py."""

from __future__ import annotations

import copy
import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts/rendered-inventory.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("_rendered_inventory", HELPER_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {HELPER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


helper = load_helper()


@dataclass
class Result:
    returncode: int = 0
    stdout: object = ""
    stderr: object = ""


class FakeRunner:
    def __init__(self, *responses: object):
        self.responses = list(responses)
        self.commands: list[list[str]] = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if not self.responses:
            raise AssertionError("unexpected renderer invocation")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def write_yaml(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def config_doc() -> dict:
    return {
        "apiVersion": helper.REDHATCOP_API_VERSION,
        "kind": "JWTOIDCAuthEngineConfig",
        "metadata": {"name": "jwt-github"},
        "spec": {"path": "jwt-github"},
    }


def health(kind: str) -> dict:
    return {
        "apiVersion": helper.REDHATCOP_API_VERSION,
        "kind": kind,
        "current": helper.HEALTH_CURRENT,
    }


def flux_doc(path: object = "./managed") -> dict:
    return {
        "apiVersion": helper.FLUX_API_VERSION,
        "kind": helper.FLUX_KIND,
        "metadata": {
            "name": helper.FLUX_NAME,
            "namespace": helper.FLUX_NAMESPACE,
        },
        "spec": {
            "interval": "10m",
            "path": path,
            "prune": True,
            "wait": True,
            "dependsOn": [
                {"name": "vault-config-operator"},
                {"name": "vault"},
            ],
            "sourceRef": {"kind": "GitRepository", "name": "flux-system"},
            "healthCheckExprs": [
                health("JWTOIDCAuthEngineConfig"),
                health("JWTOIDCAuthEngineRole"),
            ],
        },
    }


def setup_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    write_yaml(repo / "managed/config.yaml", config_doc())
    write_yaml(
        repo / "managed/kustomization.yaml",
        {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": ["config.yaml"],
        },
    )


def yaml_stream(*docs: object) -> str:
    return yaml.safe_dump_all(docs, sort_keys=False)


def fake_load(
    repo: Path,
    *,
    flux: dict | None = None,
    root_stdout: object | None = None,
    target_stdout: object | None = None,
    responses: list[object] | None = None,
    which=lambda _: "/test/kubectl",
    directory_entries=Path.iterdir,
):
    selected = flux_doc() if flux is None else flux
    if responses is None:
        responses = [
            Result(stdout=yaml_stream(selected) if root_stdout is None else root_stdout),
            Result(
                stdout=yaml_stream(config_doc())
                if target_stdout is None
                else target_stdout
            ),
        ]
    runner = FakeRunner(*responses)
    inventory = helper.load_rendered_inventory(
        repo,
        which=which,
        runner=runner,
        timeout_seconds=7,
        directory_entries=directory_entries,
    )
    return inventory, runner


def desired_owner(
    name: str,
    path: object,
    *,
    namespace: object = helper.FLUX_NAMESPACE,
    source_kind: object = "GitRepository",
    source_name: object = "flux-system",
    source_namespace: object = helper.FLUX_NAMESPACE,
    spec_updates: dict | None = None,
) -> dict:
    source_ref = {"kind": source_kind, "name": source_name}
    if source_namespace is not _ABSENT:
        source_ref["namespace"] = source_namespace
    spec = {
        "interval": "10m",
        "path": path,
        "prune": True,
        "wait": True,
        "sourceRef": source_ref,
    }
    if spec_updates:
        spec.update(spec_updates)
    return {
        "apiVersion": helper.FLUX_API_VERSION,
        "kind": helper.FLUX_KIND,
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def desired_load(
    repo: Path,
    *responses: object,
    runner: FakeRunner | None = None,
    which=lambda _: "/test/kubectl",
    max_discovered_owners: int = helper.MAX_DISCOVERED_OWNERS,
):
    selected_runner = runner if runner is not None else FakeRunner(*responses)
    inventory = helper.load_desired_build_inventory(
        repo,
        which=which,
        runner=selected_runner,
        timeout_seconds=7,
        directory_entries=Path.iterdir,
        max_discovered_owners=max_discovered_owners,
    )
    return inventory, selected_runner


def make_render_path(repo: Path, name: str) -> Path:
    path = repo / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def ordinary_doc(kind: str, name: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": kind,
        "metadata": {"name": name},
    }


_ABSENT = object()


CASES: list[tuple[str, object]] = []


def case(name: str):
    def register(function):
        CASES.append((name, function))
        return function

    return register


def expect_error(callback, fragment: str) -> None:
    try:
        callback()
    except helper.InventoryError as exc:
        if fragment not in str(exc):
            raise AssertionError(
                f"expected error fragment {fragment!r}, got {str(exc)!r}"
            ) from exc
    else:
        raise AssertionError(f"expected InventoryError containing {fragment!r}")


def expect_main_error(root: Path, loader, fragment: str) -> None:
    original_loader = helper.load_rendered_inventory
    original_argv = sys.argv
    stdout, stderr = io.StringIO(), io.StringIO()

    def injected_loader(requested: Path):
        helper.load_rendered_inventory = original_loader
        try:
            return loader(requested)
        finally:
            helper.load_rendered_inventory = injected_loader

    helper.load_rendered_inventory = injected_loader
    sys.argv = ["rendered-inventory", "--root", str(root)]
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = helper.main()
    finally:
        helper.load_rendered_inventory = original_loader
        sys.argv = original_argv
    output = (stdout.getvalue() + stderr.getvalue()).strip()
    if rc != 2:
        raise AssertionError(f"expected exit 2, got {rc}: {output!r}")
    if fragment not in output:
        raise AssertionError(
            f"expected error fragment {fragment!r}, got {output!r}"
        )


def expect_all_paths_main_error(root: Path, loader, fragment: str) -> None:
    original_loader = helper.load_desired_build_inventory
    original_argv = sys.argv
    stdout, stderr = io.StringIO(), io.StringIO()

    def injected_loader(requested: Path):
        helper.load_desired_build_inventory = original_loader
        try:
            return loader(requested)
        finally:
            helper.load_desired_build_inventory = injected_loader

    helper.load_desired_build_inventory = injected_loader
    sys.argv = ["rendered-inventory", "--root", str(root), "--all-paths"]
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = helper.main()
    finally:
        helper.load_desired_build_inventory = original_loader
        sys.argv = original_argv
    output = (stdout.getvalue() + stderr.getvalue()).strip()
    if rc != 2:
        raise AssertionError(f"expected exit 2, got {rc}: {output!r}")
    if fragment not in output:
        raise AssertionError(
            f"expected error fragment {fragment!r}, got {output!r}"
        )


@case("success-uses-flux-load-restrictor-on-both-renders")
def success_flags(repo: Path) -> None:
    inventory, runner = fake_load(repo)
    if len(inventory.documents) != 1:
        raise AssertionError("expected one managed document")
    if len(runner.commands) != 2:
        raise AssertionError(f"expected two renders, found {len(runner.commands)}")
    for command in runner.commands:
        expected = ["kustomize", "--load-restrictor", "LoadRestrictionsNone"]
        if command[1:4] != expected:
            raise AssertionError(f"Flux load restrictor missing: {command!r}")


@case("diagnostic-label-ignores-object-annotations")
def diagnostic_label_ignores_annotations(repo: Path) -> None:
    doc = config_doc()
    doc["metadata"]["annotations"] = {
        "trust-root.nwarila.dev/source-path": "attacker-selected-label"
    }
    label = helper.rendered_document_label(doc)
    expected = "managed render 'JWTOIDCAuthEngineConfig'/'jwt-github'"
    if label != expected:
        raise AssertionError(f"expected {expected!r}, got {label!r}")


@case("success-with-real-kubectl")
def success_real_kubectl(repo: Path) -> None:
    cluster = repo / helper.ROOT_KUSTOMIZATION
    write_yaml(
        cluster / "kustomization.yaml",
        {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": ["../../managed-flux.yaml"],
        },
    )
    real_flux = flux_doc("./managed")
    write_yaml(repo / "managed-flux.yaml", real_flux)
    inventory = helper.load_rendered_inventory(repo)
    if len(inventory.documents) != 1:
        raise AssertionError("real kubectl did not render the managed config")


@case("kubectl-absent")
def kubectl_absent(repo: Path) -> None:
    expect_error(
        lambda: fake_load(repo, which=lambda _: None),
        "kubectl was not found",
    )


def register_render_error_cases() -> None:
    stages = ("ROOT", "managed target")
    failures = (
        (
            "spawn-failure",
            lambda stage: OSError(f"{stage} spawn denied"),
            "could not spawn",
        ),
        (
            "non-zero-exit",
            lambda stage: Result(returncode=9, stderr=f"{stage} failed"),
            "failed with exit 9",
        ),
        (
            "timeout",
            lambda stage: subprocess.TimeoutExpired([stage], 7),
            "timed out after 7s",
        ),
        (
            "unparseable-yaml",
            lambda stage: Result(stdout="key: [unterminated"),
            "not parseable YAML",
        ),
        (
            "non-mapping-document",
            lambda stage: Result(stdout="- not-a-mapping\n"),
            "is not a mapping",
        ),
    )
    for stage_index, stage in enumerate(stages):
        for suffix, failure, fragment in failures:
            name = f"{stage.lower().replace(' ', '-')}-{suffix}"

            def run(
                repo: Path,
                stage_index=stage_index,
                stage=stage,
                failure=failure,
                fragment=fragment,
            ) -> None:
                responses: list[object] = []
                if stage_index:
                    responses.append(Result(stdout=yaml_stream(flux_doc())))
                responses.append(failure(stage))
                expect_error(
                    lambda: fake_load(repo, responses=responses),
                    fragment,
                )

            CASES.append((name, run))


register_render_error_cases()


@case("ROOT-stdout-not-text")
def root_stdout_not_text(repo: Path) -> None:
    expect_error(
        lambda: fake_load(repo, responses=[Result(stdout=b"bytes")]),
        "stdout was not text",
    )


@case("anchor-zero-matches")
def anchor_zero(repo: Path) -> None:
    other = flux_doc()
    other["metadata"]["name"] = "other"
    expect_error(lambda: fake_load(repo, flux=other), "found 0")


@case("anchor-multiple-matches")
def anchor_multiple(repo: Path) -> None:
    duplicate = flux_doc()
    duplicate["apiVersion"] = "example.invalid/v1"
    expect_error(
        lambda: fake_load(
            repo,
            root_stdout=yaml_stream(flux_doc(), duplicate),
        ),
        "found 2",
    )


def register_flux_mutation(name: str, fragment: str, mutate) -> None:
    def run(repo: Path) -> None:
        flux = flux_doc()
        mutate(flux)
        expect_error(lambda: fake_load(repo, flux=flux), fragment)

    CASES.append((name, run))


def register_flux_finding(name: str, fragment: str, mutate) -> None:
    def run(repo: Path) -> None:
        flux = flux_doc()
        mutate(flux)
        inventory, _ = fake_load(repo, flux=flux)
        if not any(fragment in finding for finding in inventory.flux_findings):
            raise AssertionError(
                f"expected finding fragment {fragment!r}, got "
                f"{inventory.flux_findings!r}"
            )

    CASES.append((name, run))


register_flux_mutation(
    "anchor-wrong-api-version",
    "must be kustomize.toolkit.fluxcd.io/v1 Kustomization",
    lambda doc: doc.__setitem__("apiVersion", "v1"),
)
register_flux_mutation(
    "anchor-wrong-kind",
    "must be kustomize.toolkit.fluxcd.io/v1 Kustomization",
    lambda doc: doc.__setitem__("kind", "ConfigMap"),
)
register_flux_mutation(
    "anchor-spec-not-mapping",
    "spec must be a mapping",
    lambda doc: doc.__setitem__("spec", []),
)
for key, fragment in (
    ("postBuild", "build-content altering"),
    ("kubeConfig", "apply-target altering"),
    ("ignore", "drift-semantics altering"),
    ("futureField", "unsupported spec key"),
):
    register_flux_mutation(
        f"anchor-rejects-{key}",
        fragment,
        lambda doc, key=key: doc["spec"].__setitem__(key, {}),
    )
register_flux_finding(
    "anchor-prune-not-true",
    "spec.prune must be true",
    lambda doc: doc["spec"].__setitem__("prune", False),
)
register_flux_finding(
    "anchor-wait-not-true",
    "spec.wait must be true",
    lambda doc: doc["spec"].__setitem__("wait", False),
)
register_flux_finding(
    "anchor-suspend-not-false",
    "spec.suspend must be absent or false",
    lambda doc: doc["spec"].__setitem__("suspend", True),
)
register_flux_finding(
    "anchor-force-not-false",
    "spec.force must be absent or false",
    lambda doc: doc["spec"].__setitem__("force", True),
)
register_flux_finding(
    "anchor-dependsOn-not-list",
    "spec.dependsOn must be a list",
    lambda doc: doc["spec"].__setitem__("dependsOn", {}),
)
register_flux_finding(
    "anchor-operator-dependency-missing",
    "dependency 'vault-config-operator'",
    lambda doc: doc["spec"].__setitem__("dependsOn", [{"name": "vault"}]),
)
register_flux_finding(
    "anchor-vault-dependency-missing",
    "dependency 'vault'",
    lambda doc: doc["spec"].__setitem__(
        "dependsOn", [{"name": "vault-config-operator"}]
    ),
)
register_flux_finding(
    "anchor-operator-dependency-namespace",
    "dependency 'vault-config-operator' namespace",
    lambda doc: doc["spec"]["dependsOn"][0].__setitem__("namespace", "tenant"),
)
register_flux_finding(
    "anchor-vault-dependency-namespace",
    "dependency 'vault' namespace",
    lambda doc: doc["spec"]["dependsOn"][1].__setitem__("namespace", "tenant"),
)
register_flux_finding(
    "anchor-operator-dependency-readyExpr",
    "dependency 'vault-config-operator' must not set readyExpr",
    lambda doc: doc["spec"]["dependsOn"][0].__setitem__("readyExpr", "true"),
)
register_flux_finding(
    "anchor-vault-dependency-readyExpr",
    "dependency 'vault' must not set readyExpr",
    lambda doc: doc["spec"]["dependsOn"][1].__setitem__("readyExpr", "true"),
)
register_flux_mutation(
    "anchor-sourceRef-not-mapping",
    "spec.sourceRef must be a mapping",
    lambda doc: doc["spec"].__setitem__("sourceRef", []),
)
for field, value, fragment in (
    ("kind", "Bucket", "sourceRef.kind"),
    ("name", "other", "sourceRef.name"),
    ("namespace", "tenant", "sourceRef.namespace"),
):
    register_flux_mutation(
        f"anchor-sourceRef-{field}-mismatch",
        fragment,
        lambda doc, field=field, value=value: doc["spec"]["sourceRef"].__setitem__(
            field, value
        ),
    )
register_flux_finding(
    "anchor-healthCheckExprs-not-list",
    "healthCheckExprs must be a list",
    lambda doc: doc["spec"].__setitem__("healthCheckExprs", {}),
)
register_flux_finding(
    "anchor-health-config-missing",
    "JWTOIDCAuthEngineConfig entry",
    lambda doc: doc["spec"].__setitem__(
        "healthCheckExprs",
        [health("JWTOIDCAuthEngineRole")],
    ),
)
register_flux_finding(
    "anchor-health-role-missing",
    "JWTOIDCAuthEngineRole entry",
    lambda doc: doc["spec"].__setitem__(
        "healthCheckExprs",
        [health("JWTOIDCAuthEngineConfig")],
    ),
)
register_flux_finding(
    "anchor-health-config-duplicate",
    "JWTOIDCAuthEngineConfig entry",
    lambda doc: doc["spec"]["healthCheckExprs"].append(
        health("JWTOIDCAuthEngineConfig")
    ),
)
register_flux_finding(
    "anchor-health-expression-wrong",
    "JWTOIDCAuthEngineConfig entry",
    lambda doc: doc["spec"]["healthCheckExprs"][0].__setitem__("current", "true"),
)
register_flux_mutation(
    "anchor-path-not-string",
    "spec.path must be a non-empty string",
    lambda doc: doc["spec"].__setitem__("path", []),
)
register_flux_mutation(
    "anchor-path-empty",
    "spec.path must be a non-empty string",
    lambda doc: doc["spec"].__setitem__("path", ""),
)


@case("path-resolution-error")
def path_resolution_error(repo: Path) -> None:
    (repo / "loop").symlink_to("loop")
    expect_error(
        lambda: fake_load(repo, flux=flux_doc("./loop")),
        "could not resolve Flux spec.path",
    )


@case("path-symlink-escape")
def path_symlink_escape(repo: Path) -> None:
    outside = repo.parent / "outside"
    outside.mkdir()
    (repo / "escape").symlink_to(outside, target_is_directory=True)
    expect_error(
        lambda: fake_load(repo, flux=flux_doc("./escape")),
        "escapes the repository",
    )


@case("path-target-nonexistent")
def path_nonexistent(repo: Path) -> None:
    expect_error(
        lambda: fake_load(repo, flux=flux_doc("./absent")),
        "target does not exist",
    )


@case("path-target-not-directory")
def path_not_directory(repo: Path) -> None:
    file_path = repo / "not-directory"
    file_path.write_text("data\n", encoding="utf-8")
    expect_error(
        lambda: fake_load(repo, flux=flux_doc("./not-directory")),
        "target is not a directory",
    )


@case("containment-directory-unreadable")
def containment_unreadable(repo: Path) -> None:
    def unreadable(_):
        raise PermissionError("fixture denied")

    expect_error(
        lambda: fake_load(repo, directory_entries=unreadable),
        "managed directory is unreadable",
    )


@case("containment-kustomization-missing")
def containment_missing_kustomization(repo: Path) -> None:
    (repo / "managed/kustomization.yaml").unlink()
    expect_error(lambda: fake_load(repo), "managed kustomization is missing")


@case("containment-kustomization-unparseable")
def containment_unparseable_kustomization(repo: Path) -> None:
    (repo / "managed/kustomization.yaml").write_text(
        "resources: [unterminated", encoding="utf-8"
    )
    expect_error(lambda: fake_load(repo), "failed to parse managed kustomization")


@case("containment-kustomization-multiple-documents-exits-2")
def containment_multiple_kustomization_documents(repo: Path) -> None:
    kustomization = {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "resources": ["config.yaml"],
    }
    (repo / "managed/kustomization.yaml").write_text(
        yaml_stream(kustomization, copy.deepcopy(kustomization)),
        encoding="utf-8",
    )
    expect_main_error(
        repo,
        lambda root: fake_load(root)[0],
        "must contain exactly one mapping document",
    )


@case("containment-resource-resolution-error-exits-2")
def containment_resource_resolution_error(repo: Path) -> None:
    (repo / "managed/loop").symlink_to("loop")
    write_yaml(
        repo / "managed/kustomization.yaml",
        {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": ["loop"],
        },
    )
    expect_main_error(
        repo,
        lambda root: fake_load(root)[0],
        "could not resolve managed build input 'loop'",
    )


@case("containment-managed-file-resolution-error-exits-2")
def containment_managed_file_resolution_error(repo: Path) -> None:
    (repo / "managed/dangling.yaml").symlink_to("absent.yaml")
    expect_main_error(
        repo,
        lambda root: fake_load(root)[0],
        "could not resolve managed file",
    )


@case("repository-root-resolution-error-exits-2")
def repository_root_resolution_error(repo: Path) -> None:
    root = repo / "root-loop"
    root.symlink_to("root-loop")
    expect_main_error(
        root,
        lambda requested: fake_load(requested)[0],
        "could not resolve repository root",
    )


@case("repository-root-not-directory-exits-2")
def repository_root_not_directory(repo: Path) -> None:
    root = repo / "root-file"
    root.write_text("not a directory\n", encoding="utf-8")
    expect_main_error(
        root,
        lambda requested: fake_load(requested)[0],
        "repository root is not a directory",
    )


@case("containment-resources-not-list")
def containment_resources_not_list(repo: Path) -> None:
    write_yaml(
        repo / "managed/kustomization.yaml",
        {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": "config.yaml",
        },
    )
    expect_error(lambda: fake_load(repo), "resources must be a list")


@case("empty-render-is-determined-not-tooling-error")
def empty_render(repo: Path) -> None:
    inventory, _ = fake_load(repo, target_stdout="")
    if inventory.documents:
        raise AssertionError("empty target render was not preserved")
    findings = helper.applied_inventory_findings(inventory)
    if not any("at least one" in finding for finding in findings):
        raise AssertionError(f"empty render invariant missing: {findings!r}")


@case("containment-unlisted-file-is-finding")
def containment_unlisted(repo: Path) -> None:
    write_yaml(repo / "managed/unlisted.json", config_doc())
    inventory, _ = fake_load(repo)
    if not any("authored in the prune-armed directory but not applied" in finding
               for finding in inventory.containment_findings):
        raise AssertionError(inventory.containment_findings)


@case("containment-subdirectory-is-finding")
def containment_subdirectory(repo: Path) -> None:
    (repo / "managed/nested").mkdir()
    inventory, _ = fake_load(repo)
    if not any("subdirectories are forbidden" in finding
               for finding in inventory.containment_findings):
        raise AssertionError(inventory.containment_findings)


@case("containment-external-patch-file-is-finding")
def containment_patch_file(repo: Path) -> None:
    patch = repo / "managed/config.patch.yaml"
    patch.write_text("- op: add\n  path: /metadata/labels/x\n  value: y\n", encoding="utf-8")
    kustomization = yaml.safe_load(
        (repo / "managed/kustomization.yaml").read_text(encoding="utf-8")
    )
    kustomization["patches"] = [
        {"target": {"kind": "JWTOIDCAuthEngineConfig"}, "path": patch.name}
    ]
    write_yaml(repo / "managed/kustomization.yaml", kustomization)
    inventory, _ = fake_load(repo)
    if not any("non-resource build inputs are forbidden" in finding
               for finding in inventory.containment_findings):
        raise AssertionError(inventory.containment_findings)


@case("containment-duplicate-resource-entry-is-finding")
def containment_duplicate_resource(repo: Path) -> None:
    kustomization = yaml.safe_load(
        (repo / "managed/kustomization.yaml").read_text(encoding="utf-8")
    )
    kustomization["resources"].append("./config.yaml")
    write_yaml(repo / "managed/kustomization.yaml", kustomization)
    inventory, _ = fake_load(repo)
    if not any("listed exactly once" in finding
               for finding in inventory.containment_findings):
        raise AssertionError(inventory.containment_findings)


@case("all-paths-discovers-owner-from-non-root-render-with-attribution")
def all_paths_nested_discovery(repo: Path) -> None:
    make_render_path(repo, "owner-a")
    make_render_path(repo, "owner-b")
    owner_a = desired_owner("owner-a", "./owner-a")
    owner_b = desired_owner("owner-b", "./owner-b")
    config_a = ordinary_doc("ConfigMap", "config-a")
    secret_b = ordinary_doc("Secret", "secret-b")
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(owner_a)),
        Result(stdout=yaml_stream(config_a, owner_b)),
        Result(stdout=yaml_stream(secret_b)),
    )
    expected = [
        ((helper.FLUX_NAMESPACE, "owner-a"), config_a),
        ((helper.FLUX_NAMESPACE, "owner-a"), owner_b),
        ((helper.FLUX_NAMESPACE, "owner-b"), secret_b),
    ]
    actual = [
        (document.owner_identity, document.document)
        for document in inventory.documents
    ]
    if actual != expected:
        raise AssertionError(f"unexpected attributed documents: {actual!r}")
    if len(runner.commands) != 3:
        raise AssertionError(f"expected ROOT plus two owner renders: {runner.commands!r}")


@case("all-paths-repository-root-resolution-error")
def all_paths_repository_root_resolution_error(repo: Path) -> None:
    root = repo / "root-loop"
    root.symlink_to("root-loop")
    runner = FakeRunner(Result(stdout=yaml_stream(desired_owner("valid", "./managed"))))
    expect_error(
        lambda: desired_load(root, runner=runner),
        "could not resolve repository root",
    )
    if runner.commands:
        raise AssertionError(f"invalid repository root was rendered: {runner.commands!r}")


@case("all-paths-repository-root-not-directory")
def all_paths_repository_root_not_directory(repo: Path) -> None:
    root = repo / "root-file"
    root.write_text("not a directory\n", encoding="utf-8")
    runner = FakeRunner(Result(stdout=yaml_stream(desired_owner("valid", "./managed"))))
    expect_error(
        lambda: desired_load(root, runner=runner),
        "repository root is not a directory",
    )
    if runner.commands:
        raise AssertionError(f"non-directory repository root was rendered: {runner.commands!r}")


@case("all-paths-kubectl-absent")
def all_paths_kubectl_absent(repo: Path) -> None:
    runner = FakeRunner(Result(stdout=yaml_stream(desired_owner("valid", "./managed"))))
    expect_error(
        lambda: desired_load(repo, runner=runner, which=lambda _: None),
        "kubectl was not found on PATH",
    )
    if runner.commands:
        raise AssertionError(f"missing kubectl reached render: {runner.commands!r}")


@case("all-paths-invalid-maximum-discovered-owners")
def all_paths_invalid_maximum_discovered_owners(repo: Path) -> None:
    runner = FakeRunner(Result(stdout=yaml_stream(desired_owner("valid", "./managed"))))
    expect_error(
        lambda: desired_load(repo, runner=runner, max_discovered_owners=0),
        "maximum unique discovered owners must be a positive integer",
    )
    if runner.commands:
        raise AssertionError(f"invalid discovery limit reached render: {runner.commands!r}")


@case("all-paths-root-self-reference-converges")
def all_paths_root_self_reference(repo: Path) -> None:
    make_render_path(repo, str(helper.ROOT_KUSTOMIZATION))
    owner = desired_owner("root-self", f"./{helper.ROOT_KUSTOMIZATION}")
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(owner)),
    )
    if [item.identity for item in inventory.owners] != [owner_identity(owner)]:
        raise AssertionError(inventory.owners)
    if len(runner.commands) != 1:
        raise AssertionError(f"ROOT self-reference rendered twice: {runner.commands!r}")
    if [item.owner_identity for item in inventory.documents] != [owner_identity(owner)]:
        raise AssertionError(inventory.documents)


@case("all-paths-non-root-self-reference-converges")
def all_paths_non_root_self_reference(repo: Path) -> None:
    make_render_path(repo, "self-owner")
    owner = desired_owner("self-owner", "./self-owner")
    config = ordinary_doc("ConfigMap", "self-output")
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(owner)),
        Result(stdout=yaml_stream(owner, config)),
    )
    if len(inventory.owners) != 1 or len(runner.commands) != 2:
        raise AssertionError((inventory.owners, runner.commands))
    if [item.document for item in inventory.documents] != [owner, config]:
        raise AssertionError(inventory.documents)


@case("all-paths-two-node-cycle-converges")
def all_paths_two_node_cycle(repo: Path) -> None:
    make_render_path(repo, "cycle-a")
    make_render_path(repo, "cycle-b")
    owner_a = desired_owner("cycle-a", "./cycle-a")
    owner_b = desired_owner("cycle-b", "./cycle-b")
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(owner_a)),
        Result(stdout=yaml_stream(owner_b)),
        Result(stdout=yaml_stream(owner_a)),
    )
    if [owner.identity for owner in inventory.owners] != sorted(
        [owner_identity(owner_a), owner_identity(owner_b)]
    ):
        raise AssertionError(inventory.owners)
    if len(runner.commands) != 3:
        raise AssertionError(f"cycle did not converge: {runner.commands!r}")


@case("all-paths-discovery-limit-reports-limit-and-count")
def all_paths_discovery_limit(repo: Path) -> None:
    limit = 3
    owners = []
    for index in range(limit + 1):
        make_render_path(repo, f"chain-{index}")
        owners.append(desired_owner(f"chain-{index}", f"./chain-{index}"))
    runner = FakeRunner(
        Result(stdout=yaml_stream(owners[0])),
        *[
            Result(stdout=yaml_stream(owners[index + 1]))
            for index in range(limit)
        ],
    )
    try:
        desired_load(
            repo,
            runner=runner,
            max_discovered_owners=limit,
        )
    except helper.InventoryError as exc:
        error = str(exc)
        for fragment in (
            "discovery limit exceeded",
            f"is {limit}",
            f"count reached {limit + 1}",
        ):
            if fragment not in error:
                raise AssertionError(f"missing {fragment!r} in {error!r}") from exc
    else:
        raise AssertionError("expected discovery limit exceeded")
    if len(runner.commands) != limit + 1:
        raise AssertionError(f"wrong render count at discovery limit: {runner.commands!r}")


@case("all-paths-duplicate-owner-differing-specs-before-owner-render")
def all_paths_duplicate_differing_specs(repo: Path) -> None:
    make_render_path(repo, "duplicate-a")
    make_render_path(repo, "duplicate-b")
    first = desired_owner("duplicate", "./duplicate-a")
    second = desired_owner("duplicate", "./duplicate-b")
    runner = FakeRunner(Result(stdout=yaml_stream(first, second)))
    expect_error(
        lambda: desired_load(repo, runner=runner),
        "duplicate owner flux-system/duplicate has differing specs",
    )
    if len(runner.commands) != 1:
        raise AssertionError(f"differing owner path was rendered: {runner.commands!r}")


@case("all-paths-duplicate-owner-type-distinct-specs-before-owner-render")
def all_paths_duplicate_type_distinct_specs(repo: Path) -> None:
    make_render_path(repo, "duplicate-typed")
    first = desired_owner(
        "duplicate-typed",
        "./duplicate-typed",
        spec_updates={"interval": True},
    )
    second = desired_owner(
        "duplicate-typed",
        "./duplicate-typed",
        spec_updates={"interval": 1},
    )
    runner = FakeRunner(Result(stdout=yaml_stream(first, second)))
    expect_error(
        lambda: desired_load(repo, runner=runner),
        "duplicate owner flux-system/duplicate-typed has differing specs",
    )
    if len(runner.commands) != 1:
        raise AssertionError(f"type-distinct owner was rendered: {runner.commands!r}")


@case("all-paths-modified-root-owner-reuses-bootstrap-with-partial-reach")
def all_paths_modified_root_owner(repo: Path) -> None:
    make_render_path(repo, str(helper.ROOT_KUSTOMIZATION))
    owner = desired_owner(
        "flux-system",
        f"./{helper.ROOT_KUSTOMIZATION}",
        spec_updates={"decryption": {"provider": "sops"}},
    )
    inventory, runner = desired_load(repo, Result(stdout=yaml_stream(owner)))
    if len(runner.commands) != 1:
        raise AssertionError(f"modified ROOT owner rendered again: {runner.commands!r}")
    selected = {item.identity: item for item in inventory.owners}[owner_identity(owner)]
    if selected.classification != "modified":
        raise AssertionError(selected)
    if any(item.owner_identity == owner_identity(owner) for item in inventory.documents):
        raise AssertionError("modified ROOT owner contributed desired-build documents")
    if len(inventory.reach_limits) != 1:
        raise AssertionError(inventory.reach_limits)
    if inventory.reach_limits[0].reason != helper.ROOT_PARTIALLY_SEARCHED_REASON:
        raise AssertionError(inventory.reach_limits[0])


@case("all-paths-modified-and-external-reach-limits-wholly-unsearched")
def all_paths_wholly_unsearched_reach_limits(repo: Path) -> None:
    make_render_path(repo, "modified-owner")
    modified = desired_owner(
        "modified-owner",
        "./modified-owner",
        spec_updates={"targetNamespace": "target"},
    )
    external = desired_owner(
        "external-owner",
        "./does-not-exist",
        source_kind="OCIRepository",
        source_name="artifact",
    )
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(modified, external)),
    )
    if len(runner.commands) != 1:
        raise AssertionError(f"class-excluded owner was rendered: {runner.commands!r}")
    reasons = {limit.owner_identity: limit.reason for limit in inventory.reach_limits}
    expected = {
        owner_identity(modified): helper.MODIFIED_WHOLELY_UNSEARCHED_REASON,
        owner_identity(external): helper.EXTERNAL_WHOLELY_UNSEARCHED_REASON,
    }
    if reasons != expected:
        raise AssertionError(reasons)


@case("all-paths-modified-shared-rendered-path-is-partially-searched")
def all_paths_modified_shared_rendered_path(repo: Path) -> None:
    make_render_path(repo, "shared-rendered-path")
    unmodified = desired_owner("shared-builder", "./shared-rendered-path")
    modified = desired_owner(
        "shared-modified",
        "./shared-rendered-path",
        spec_updates={"targetNamespace": "target"},
    )
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(unmodified, modified)),
        Result(stdout=yaml_stream(ordinary_doc("ConfigMap", "shared-output"))),
    )
    if len(runner.commands) != 2:
        raise AssertionError(f"shared path render count was wrong: {runner.commands!r}")
    limits = {limit.owner_identity: limit for limit in inventory.reach_limits}
    limit = limits[owner_identity(modified)]
    if limit.reason != helper.MODIFIED_PARTIALLY_SEARCHED_REASON:
        raise AssertionError(limit)
    if limit.reason == helper.ROOT_PARTIALLY_SEARCHED_REASON:
        raise AssertionError("non-ROOT modified owner received the ROOT reason")


@case("all-paths-rejects-unsupported-flux-api-version")
def all_paths_unsupported_flux_version(repo: Path) -> None:
    make_render_path(repo, "future-owner")
    owner = desired_owner("future-owner", "./future-owner")
    owner["apiVersion"] = "kustomize.toolkit.fluxcd.io/v1beta2"
    expect_error(
        lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
        "flux-system/future-owner uses unsupported Flux apiVersion "
        "'kustomize.toolkit.fluxcd.io/v1beta2'",
    )


def register_indeterminable_api_version_cases() -> None:
    mutations = {
        "absent": lambda doc: doc.pop("apiVersion"),
        "null": lambda doc: doc.__setitem__("apiVersion", None),
        "non-string": lambda doc: doc.__setitem__("apiVersion", 1),
    }
    for suffix, mutate in mutations.items():
        def run(repo: Path, suffix=suffix, mutate=mutate) -> None:
            make_render_path(repo, "api-version-valid-path")
            owner = desired_owner(
                f"api-version-{suffix}",
                "./api-version-valid-path",
            )
            mutate(owner)
            runner = FakeRunner(Result(stdout=yaml_stream(owner)))
            expect_error(
                lambda: desired_load(repo, runner=runner),
                "ROOT bootstrap render document 1 "
                f"flux-system/api-version-{suffix} apiVersion must be a string",
            )
            if len(runner.commands) != 1:
                raise AssertionError(
                    f"indeterminable apiVersion owner was rendered: {runner.commands!r}"
                )

        CASES.append((f"all-paths-api-version-{suffix}-is-indeterminable", run))


register_indeterminable_api_version_cases()


def register_indeterminable_api_group_cases() -> None:
    api_versions = {
        "empty": "",
        "whitespace-only": "   ",
        "leading-slash": "/v1",
    }
    for suffix, api_version in api_versions.items():
        def run(repo: Path, suffix=suffix, api_version=api_version) -> None:
            make_render_path(repo, "api-group-valid-path")
            owner = desired_owner(
                f"api-group-{suffix}",
                "./api-group-valid-path",
            )
            owner["apiVersion"] = api_version
            runner = FakeRunner(Result(stdout=yaml_stream(owner)))
            expect_error(
                lambda: desired_load(repo, runner=runner),
                "ROOT bootstrap render document 1 "
                f"flux-system/api-group-{suffix} apiVersion {api_version!r} "
                "has indeterminable API group",
            )
            if len(runner.commands) != 1:
                raise AssertionError(
                    f"indeterminable API group owner was rendered: {runner.commands!r}"
                )

        CASES.append((f"all-paths-api-group-{suffix}-is-indeterminable", run))


register_indeterminable_api_group_cases()


def register_determinable_non_flux_group_cases() -> None:
    api_versions = {
        "core-v1": "v1",
        "apps-v1": "apps/v1",
    }
    for suffix, api_version in api_versions.items():
        def run(repo: Path, suffix=suffix, api_version=api_version) -> None:
            make_render_path(repo, "foreign-group-valid-path")
            document = desired_owner(
                f"foreign-group-{suffix}",
                "./foreign-group-valid-path",
            )
            document["apiVersion"] = api_version
            inventory, runner = desired_load(
                repo,
                Result(stdout=yaml_stream(document)),
            )
            if inventory.root_documents != (document,):
                raise AssertionError(inventory.root_documents)
            if inventory.owners or inventory.documents or inventory.reach_limits:
                raise AssertionError(inventory)
            if len(runner.commands) != 1:
                raise AssertionError(runner.commands)

        CASES.append((f"all-paths-{suffix}-document-is-not-owner", run))


register_determinable_non_flux_group_cases()


@case("all-paths-kustomize-config-document-is-not-owner")
def all_paths_kustomize_config_not_owner(repo: Path) -> None:
    kustomization = {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "metadata": {"name": "ordinary-build-file"},
        "resources": [],
    }
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(kustomization)),
    )
    if inventory.owners or inventory.documents or inventory.reach_limits:
        raise AssertionError(inventory)
    if len(runner.commands) != 1:
        raise AssertionError(runner.commands)


def owner_identity(doc: dict) -> tuple[str, str]:
    return doc["metadata"]["namespace"], doc["metadata"]["name"]


def register_build_affecting_owner_cases() -> None:
    values = {
        "patches": [],
        "images": [],
        "components": [],
        "ignoreMissingComponents": False,
        "targetNamespace": "target",
        "namePrefix": "prefix-",
        "nameSuffix": "-suffix",
        "commonMetadata": {},
        "postBuild": {},
        "decryption": {},
        "buildMetadata": [],
    }
    for key, value in values.items():
        def run(repo: Path, key=key, value=value) -> None:
            make_render_path(repo, "modified")
            owner = desired_owner(
                f"modified-{key}",
                "./modified",
                spec_updates={key: value},
            )
            inventory, runner = desired_load(
                repo,
                Result(stdout=yaml_stream(owner)),
            )
            selected = inventory.owners[0]
            if selected.classification != "modified":
                raise AssertionError(selected)
            if selected.build_affecting_keys != (key,):
                raise AssertionError(selected.build_affecting_keys)
            if len(runner.commands) != 1:
                raise AssertionError(f"modified owner was rendered: {runner.commands!r}")

        CASES.append((f"all-paths-build-affecting-{key}-is-modified", run))


register_build_affecting_owner_cases()


@case("all-paths-multiple-build-affecting-keys-are-sorted")
def all_paths_multiple_build_affecting_keys(repo: Path) -> None:
    make_render_path(repo, "multi-modified")
    owner = desired_owner(
        "multi-modified",
        "./multi-modified",
        spec_updates={"targetNamespace": "target", "patches": []},
    )
    inventory, runner = desired_load(repo, Result(stdout=yaml_stream(owner)))
    if inventory.owners[0].build_affecting_keys != ("patches", "targetNamespace"):
        raise AssertionError(inventory.owners[0].build_affecting_keys)
    if len(runner.commands) != 1:
        raise AssertionError(runner.commands)


@case("all-paths-kubeConfig-is-distinctly-unsupported")
def all_paths_kubeconfig_unsupported(repo: Path) -> None:
    owner = desired_owner(
        "kubeconfig-owner",
        "./managed",
        spec_updates={"kubeConfig": {"secretRef": {"name": "remote"}}},
    )
    expect_error(
        lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
        "unsupported spec key 'kubeConfig'",
    )


@case("all-paths-unrecognised-spec-key-is-distinct")
def all_paths_unrecognised_spec_key(repo: Path) -> None:
    owner = desired_owner(
        "future-field-owner",
        "./managed",
        spec_updates={"futureField": True},
    )
    expect_error(
        lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
        "unrecognised spec key(s): ['futureField']",
    )


@case("all-paths-all-build-neutral-owner-is-rendered")
def all_paths_all_neutral(repo: Path) -> None:
    make_render_path(repo, "all-neutral")
    neutral_values = {
        "interval": "10m",
        "retryInterval": "2m",
        "timeout": "5m",
        "prune": True,
        "wait": True,
        "force": False,
        "dependsOn": [],
        "healthChecks": [],
        "healthCheckExprs": [],
        "serviceAccountName": "builder",
        "deletionPolicy": "MirrorPrune",
        "suspend": False,
    }
    owner = desired_owner(
        "all-neutral",
        "./all-neutral",
        spec_updates=neutral_values,
    )
    output = ordinary_doc("ConfigMap", "neutral-output")
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(owner)),
        Result(stdout=yaml_stream(output)),
    )
    if inventory.owners[0].classification != "unmodified":
        raise AssertionError(inventory.owners[0])
    if len(runner.commands) != 2 or inventory.documents[0].document != output:
        raise AssertionError((runner.commands, inventory.documents))


@case("all-paths-apply-semantics-are-verbatim-and-rendered")
def all_paths_apply_semantics(repo: Path) -> None:
    make_render_path(repo, "apply-semantics")
    expected = {
        "prune": False,
        "force": True,
        "deletionPolicy": "Delete",
        "suspend": True,
        "serviceAccountName": "reconciler",
    }
    owner = desired_owner(
        "apply-semantics",
        "./apply-semantics",
        spec_updates=expected,
    )
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(owner)),
        Result(stdout=yaml_stream(ordinary_doc("ConfigMap", "applied"))),
    )
    selected = inventory.owners[0]
    if selected.classification != "unmodified" or selected.apply_semantics != expected:
        raise AssertionError(selected)
    if len(runner.commands) != 2:
        raise AssertionError(runner.commands)


@case("all-paths-tenant-owner-defaults-source-namespace-to-owner")
def all_paths_tenant_source_default(repo: Path) -> None:
    owner = desired_owner(
        "tenant-owner",
        "./managed",
        namespace="tenant",
        source_namespace=_ABSENT,
    )
    inventory, runner = desired_load(repo, Result(stdout=yaml_stream(owner)))
    selected = inventory.owners[0]
    if selected.classification != "external" or selected.source_namespace != "tenant":
        raise AssertionError(selected)
    if len(runner.commands) != 1:
        raise AssertionError(runner.commands)


def register_invalid_source_namespace_cases() -> None:
    values = {
        "empty": "",
        "null": None,
        "false": False,
        "zero": 0,
    }
    for suffix, value in values.items():
        def run(repo: Path, suffix=suffix, value=value) -> None:
            owner = desired_owner(
                f"source-namespace-{suffix}",
                "./managed",
                source_namespace=value,
            )
            expect_error(
                lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
                "spec.sourceRef.namespace must be a non-empty string",
            )

        CASES.append((f"all-paths-source-namespace-{suffix}-is-not-absence", run))


register_invalid_source_namespace_cases()


@case("all-paths-oci-source-is-external-without-render")
def all_paths_oci_source(repo: Path) -> None:
    owner = desired_owner(
        "oci-owner",
        "./remote-path",
        source_kind="OCIRepository",
        source_name="artifact",
    )
    inventory, runner = desired_load(repo, Result(stdout=yaml_stream(owner)))
    if inventory.owners[0].classification != "external":
        raise AssertionError(inventory.owners[0])
    if len(runner.commands) != 1:
        raise AssertionError(runner.commands)


@case("all-paths-external-classified-before-path-resolution")
def all_paths_external_before_path(repo: Path) -> None:
    owner = desired_owner(
        "external-missing-path",
        "./path-that-does-not-exist",
        source_name="different-repository",
    )
    inventory, runner = desired_load(repo, Result(stdout=yaml_stream(owner)))
    if inventory.owners[0].classification != "external":
        raise AssertionError(inventory.owners[0])
    if len(runner.commands) != 1:
        raise AssertionError(runner.commands)


@case("all-paths-path-dotdot-escape-is-rejected")
def all_paths_dotdot_escape(repo: Path) -> None:
    owner = desired_owner("dotdot-owner", "../outside")
    expect_error(
        lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
        "Flux spec.path escapes the repository",
    )


@case("all-paths-path-symlink-escape-is-rejected")
def all_paths_symlink_escape(repo: Path) -> None:
    outside = repo.parent / "desired-outside"
    outside.mkdir()
    (repo / "desired-escape").symlink_to(outside, target_is_directory=True)
    owner = desired_owner("symlink-owner", "./desired-escape")
    expect_error(
        lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
        "Flux spec.path escapes the repository",
    )


@case("all-paths-path-nonexistent-is-rejected")
def all_paths_path_nonexistent(repo: Path) -> None:
    owner = desired_owner("missing-path-owner", "./missing-path")
    expect_error(
        lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
        "Flux spec.path target does not exist",
    )


@case("all-paths-path-file-is-rejected")
def all_paths_path_not_directory(repo: Path) -> None:
    (repo / "path-file").write_text("not a directory\n", encoding="utf-8")
    owner = desired_owner("file-path-owner", "./path-file")
    expect_error(
        lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
        "Flux spec.path target is not a directory",
    )


@case("all-paths-path-embedded-nul-has-owner-context-exits-2")
def all_paths_path_embedded_nul(repo: Path) -> None:
    raw_path = "./managed\x00suffix"
    owner = desired_owner("nul-path-owner", raw_path)
    runner = FakeRunner(Result(stdout=yaml_stream(owner)))
    fragment = (
        f"owner flux-system/nul-path-owner spec.path {raw_path!r} "
        "could not be resolved"
    )
    expect_all_paths_main_error(
        repo,
        lambda requested: desired_load(requested, runner=runner)[0],
        fragment,
    )
    if len(runner.commands) != 1:
        raise AssertionError(f"embedded-NUL owner render count was wrong: {runner.commands!r}")


def register_invalid_owner_path_shape_cases() -> None:
    mutations = {
        "absent": lambda spec: spec.pop("path"),
        "empty": lambda spec: spec.__setitem__("path", ""),
        "non-string": lambda spec: spec.__setitem__("path", []),
    }
    for suffix, mutate in mutations.items():
        def run(repo: Path, suffix=suffix, mutate=mutate) -> None:
            owner = desired_owner(f"path-{suffix}", "./managed")
            mutate(owner["spec"])
            expect_error(
                lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
                "spec.path must be a non-empty string",
            )

        CASES.append((f"all-paths-path-{suffix}-is-rejected", run))


register_invalid_owner_path_shape_cases()


def register_invalid_owner_shape_cases() -> None:
    mutations = (
        (
            "spec-not-mapping",
            lambda doc: doc.__setitem__("spec", []),
            "spec must be a mapping",
        ),
        (
            "metadata-not-mapping",
            lambda doc: doc.__setitem__("metadata", []),
            "metadata must be a mapping",
        ),
        (
            "name-empty",
            lambda doc: doc["metadata"].__setitem__("name", ""),
            "metadata.name must be a non-empty string",
        ),
        (
            "name-non-string",
            lambda doc: doc["metadata"].__setitem__("name", 7),
            "metadata.name must be a non-empty string",
        ),
        (
            "namespace-empty",
            lambda doc: doc["metadata"].__setitem__("namespace", ""),
            "metadata.namespace must be a non-empty string",
        ),
        (
            "namespace-non-string",
            lambda doc: doc["metadata"].__setitem__("namespace", 7),
            "metadata.namespace must be a non-empty string",
        ),
        (
            "sourceRef-not-mapping",
            lambda doc: doc["spec"].__setitem__("sourceRef", []),
            "spec.sourceRef must be a mapping",
        ),
        (
            "sourceRef-kind-empty",
            lambda doc: doc["spec"]["sourceRef"].__setitem__("kind", ""),
            "spec.sourceRef.kind must be a non-empty string",
        ),
        (
            "sourceRef-name-empty",
            lambda doc: doc["spec"]["sourceRef"].__setitem__("name", ""),
            "spec.sourceRef.name must be a non-empty string",
        ),
    )
    for suffix, mutate, fragment in mutations:
        def run(
            repo: Path,
            suffix=suffix,
            mutate=mutate,
            fragment=fragment,
        ) -> None:
            owner = desired_owner(f"shape-{suffix}", "./managed")
            mutate(owner)
            expect_error(
                lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
                fragment,
            )

        CASES.append((f"all-paths-{suffix}-is-rejected", run))


register_invalid_owner_shape_cases()


def register_invalid_typed_field_cases() -> None:
    fields = {
        "targetNamespace": [],
        "serviceAccountName": [],
        "prune": "true",
        "wait": "true",
        "force": "false",
        "suspend": "false",
    }
    for field, value in fields.items():
        def run(repo: Path, field=field, value=value) -> None:
            owner = desired_owner(
                f"typed-{field}",
                "./managed",
                spec_updates={field: value},
            )
            expected = (
                f"spec.{field} must be a non-empty string"
                if field in {"targetNamespace", "serviceAccountName"}
                else f"spec.{field} must be boolean"
            )
            expect_error(
                lambda: desired_load(repo, Result(stdout=yaml_stream(owner))),
                expected,
            )

        CASES.append((f"all-paths-{field}-wrong-type-is-rejected", run))


register_invalid_typed_field_cases()


@case("all-paths-non-root-render-failure-has-owner-path-and-no-result")
def all_paths_non_root_render_failure(repo: Path) -> None:
    target = make_render_path(repo, "render-failure")
    owner = desired_owner("render-failure", "./render-failure")
    runner = FakeRunner(
        Result(stdout=yaml_stream(owner)),
        Result(returncode=23, stderr="fixture owner render failed"),
    )
    expect_error(
        lambda: desired_load(repo, runner=runner),
        "owner flux-system/render-failure path './render-failure' render failed "
        "with exit 23: fixture owner render failed",
    )
    if len(runner.commands) != 2 or Path(runner.commands[-1][-1]) != target:
        raise AssertionError(f"wrong failing render command: {runner.commands!r}")


@case("all-paths-explicit-null-render-document-is-rejected")
def all_paths_explicit_null_document(repo: Path) -> None:
    make_render_path(repo, "null-document-owner")
    owner = desired_owner("null-document-owner", "./null-document-owner")
    runner = FakeRunner(
        Result(stdout=yaml_stream(owner) + "---\nnull\n"),
    )
    expect_error(
        lambda: desired_load(repo, runner=runner),
        "ROOT bootstrap render document 2 is explicit null, not a mapping",
    )
    if len(runner.commands) != 1:
        raise AssertionError(f"explicit-null owner was rendered: {runner.commands!r}")


@case("all-paths-empty-render-document-is-skipped")
def all_paths_empty_document(repo: Path) -> None:
    make_render_path(repo, "empty-document-owner")
    owner = desired_owner("empty-document-owner", "./empty-document-owner")
    output = ordinary_doc("ConfigMap", "empty-document-output")
    inventory, runner = desired_load(
        repo,
        Result(stdout=yaml_stream(owner) + "---\n"),
        Result(stdout=yaml_stream(output)),
    )
    if len(runner.commands) != 2:
        raise AssertionError(f"empty document prevented render: {runner.commands!r}")
    if [document.document for document in inventory.documents] != [output]:
        raise AssertionError(inventory.documents)


@case("all-paths-owner-label-ignores-object-labels-and-annotations")
def all_paths_owner_label_ignores_metadata(repo: Path) -> None:
    make_render_path(repo, "attribution")
    owner = desired_owner("attribution", "./attribution")
    output = ordinary_doc("ConfigMap", "trusted-name")
    output["metadata"]["annotations"] = {
        "trust-root.nwarila.dev/source-path": "attacker-annotation"
    }
    output["metadata"]["labels"] = {"owner": "attacker-label"}
    inventory, _ = desired_load(
        repo,
        Result(stdout=yaml_stream(owner)),
        Result(stdout=yaml_stream(output)),
    )
    document = inventory.documents[0]
    label = helper.desired_build_document_label(
        document.document,
        document.owner_namespace,
        document.owner_name,
    )
    expected = "owner flux-system/attribution render 'ConfigMap'/'trusted-name'"
    if label != expected:
        raise AssertionError(f"expected {expected!r}, got {label!r}")


@case("all-paths-success-with-real-kubectl")
def all_paths_success_real_kubectl(repo: Path) -> None:
    cluster = repo / helper.ROOT_KUSTOMIZATION
    write_yaml(
        cluster / "kustomization.yaml",
        {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": ["../../desired-owner.yaml"],
        },
    )
    owner = desired_owner("real-desired-owner", "./managed")
    write_yaml(repo / "desired-owner.yaml", owner)
    inventory = helper.load_desired_build_inventory(repo)
    if [item.identity for item in inventory.owners] != [owner_identity(owner)]:
        raise AssertionError(inventory.owners)
    if len(inventory.documents) != 1:
        raise AssertionError(inventory.documents)
    document = inventory.documents[0]
    if document.owner_identity != owner_identity(owner) or document.document != config_doc():
        raise AssertionError(document)


def main() -> int:
    failures: list[tuple[str, str]] = []
    for name, function in CASES:
        with tempfile.TemporaryDirectory(prefix="rendered-inventory-") as tmp:
            repo = Path(tmp) / "repo"
            setup_repo(repo)
            try:
                function(repo)
            except Exception as exc:  # noqa: BLE001 - self-test reports every case
                failures.append((name, repr(exc)))
                print(f"FAIL  {name}")
            else:
                print(f"PASS  {name}")
    print()
    if failures:
        print(f"SELFTEST FAIL ({len(failures)} of {len(CASES)} cases)")
        for name, error in failures:
            print(f"  - {name}: {error}")
        return 1
    print(f"SELFTEST PASS ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
