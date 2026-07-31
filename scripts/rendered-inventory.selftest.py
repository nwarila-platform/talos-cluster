#!/usr/bin/env python3
"""Branch-complete self-test for rendered-inventory.py."""

from __future__ import annotations

import copy
import importlib.util
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
