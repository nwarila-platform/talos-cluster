#!/usr/bin/env python3
"""Render the Flux-applied vault-config-managed inventory, fail closed.

The ROOT render is the authority for selecting the Flux Kustomization.  Its
validated ``spec.path`` is then rendered with the same unrestricted loader
that Flux uses.  Consumers must not recover from ``InventoryError`` by
falling back to an authored-file scan.

The production ROOT contains a remote Gateway API base, so loading its
inventory requires network access until TD-0020 is closed with a pinned local
mirror.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

try:
    import yaml
except ImportError as exc:  # pragma: no cover - CI dependency
    print(f"ERROR: PyYAML is required: {exc}", file=sys.stderr)
    sys.exit(2)


ROOT_KUSTOMIZATION = Path("clusters/talos-cluster")
FLUX_API_VERSION = "kustomize.toolkit.fluxcd.io/v1"
FLUX_KIND = "Kustomization"
FLUX_NAME = "vault-config-managed"
FLUX_NAMESPACE = "flux-system"
RENDER_TIMEOUT_SECONDS = 60
REDHATCOP_API_VERSION = "redhatcop.redhat.io/v1alpha1"
SUPPORTED_MANAGED_REDHATCOP_KINDS = {
    "Policy",
    "KubernetesAuthEngineRole",
    "SecretEngineMount",
    "PKISecretEngineRole",
    "JWTOIDCAuthEngineConfig",
    "JWTOIDCAuthEngineRole",
}
HEALTH_CURRENT = (
    "has(status.conditions) && status.conditions.exists(c, c.type == "
    "'ReconcileSuccessful' && c.status == 'True' && "
    "c.observedGeneration == metadata.generation)"
)
JWT_KINDS = ("JWTOIDCAuthEngineConfig", "JWTOIDCAuthEngineRole")
ALLOWED_SPEC_KEYS = {
    "interval",
    "retryInterval",
    "timeout",
    "path",
    "healthChecks",
    "serviceAccountName",
    "deletionPolicy",
    "prune",
    "wait",
    "suspend",
    "force",
    "dependsOn",
    "sourceRef",
    "healthCheckExprs",
}
BUILD_CONTENT_KEYS = {
    "postBuild",
    "patches",
    "images",
    "targetNamespace",
    "commonMetadata",
    "namePrefix",
    "nameSuffix",
    "components",
    "ignoreMissingComponents",
    "buildMetadata",
    "decryption",
}
APPLY_TARGET_KEYS = {"kubeConfig"}
DRIFT_KEYS = {"ignore"}
SOURCE_PATH_ANNOTATION = "trust-root.nwarila.dev/source-path"


class InventoryError(RuntimeError):
    """The applied inventory could not be determined safely."""


@dataclass(frozen=True)
class RenderedInventory:
    repo_root: Path
    root_documents: tuple[dict, ...]
    flux_kustomization: dict
    managed_path: Path
    documents: tuple[dict, ...]
    flux_findings: tuple[str, ...]
    containment_findings: tuple[str, ...]


def _display(path: Path, repo: Path) -> str:
    try:
        return str(path.relative_to(repo))
    except ValueError:
        return str(path)


def rendered_document_label(doc: dict) -> str:
    """Return a stable diagnostic label without making origin authoritative."""
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    annotations = metadata.get("annotations")
    if isinstance(annotations, dict):
        source = annotations.get(SOURCE_PATH_ANNOTATION)
        if isinstance(source, str) and source:
            return source
    return (
        f"managed render {doc.get('kind')!r}/"
        f"{metadata.get('name')!r}"
    )


def _parse_rendered_yaml(stdout: object, label: str) -> tuple[dict, ...]:
    if not isinstance(stdout, str):
        raise InventoryError(f"{label} render stdout was not text")
    try:
        raw = list(yaml.safe_load_all(stdout))
    except yaml.YAMLError as exc:
        raise InventoryError(f"{label} render stdout is not parseable YAML: {exc}") from exc
    documents: list[dict] = []
    for index, doc in enumerate(raw, start=1):
        if doc is None:
            continue
        if not isinstance(doc, dict):
            raise InventoryError(
                f"{label} render document {index} is not a mapping"
            )
        documents.append(doc)
    return tuple(documents)


def _render(
    kubectl: str,
    target: Path,
    label: str,
    *,
    runner: Callable[..., object],
    timeout_seconds: int,
) -> tuple[dict, ...]:
    command = [
        kubectl,
        "kustomize",
        "--load-restrictor",
        "LoadRestrictionsNone",
        str(target),
    ]
    try:
        result = runner(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise InventoryError(
            f"{label} render timed out after {timeout_seconds}s"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise InventoryError(f"could not spawn {label} render: {exc}") from exc
    returncode = getattr(result, "returncode", None)
    if returncode != 0:
        stderr = getattr(result, "stderr", "")
        detail = stderr.strip() if isinstance(stderr, str) else repr(stderr)
        raise InventoryError(
            f"{label} render failed with exit {returncode}: {detail or 'no stderr'}"
        )
    return _parse_rendered_yaml(getattr(result, "stdout", None), label)


def _select_flux_kustomization(documents: Iterable[dict]) -> dict:
    candidates = []
    for doc in documents:
        metadata = doc.get("metadata")
        if not isinstance(metadata, dict):
            continue
        if (
            metadata.get("name") == FLUX_NAME
            and metadata.get("namespace") == FLUX_NAMESPACE
        ):
            candidates.append(doc)
    if len(candidates) != 1:
        raise InventoryError(
            "ROOT render must contain exactly one object named "
            f"{FLUX_NAMESPACE}/{FLUX_NAME}; found {len(candidates)}"
        )
    doc = candidates[0]
    if doc.get("apiVersion") != FLUX_API_VERSION or doc.get("kind") != FLUX_KIND:
        raise InventoryError(
            f"ROOT-selected {FLUX_NAMESPACE}/{FLUX_NAME} must be "
            f"{FLUX_API_VERSION} {FLUX_KIND}; found "
            f"{doc.get('apiVersion')!r} {doc.get('kind')!r}"
        )
    return doc


def _validate_dependency(
    depends_on: list[object], required_name: str, findings: list[str]
) -> None:
    matches = [
        entry
        for entry in depends_on
        if isinstance(entry, dict) and entry.get("name") == required_name
    ]
    if not matches:
        findings.append(
            f"Flux spec.dependsOn must contain dependency {required_name!r}"
        )
        return
    for entry in matches:
        if "namespace" in entry and entry.get("namespace") != FLUX_NAMESPACE:
            findings.append(
                f"Flux dependency {required_name!r} namespace must be absent "
                f"or {FLUX_NAMESPACE!r}"
            )
        if "readyExpr" in entry:
            findings.append(
                f"Flux dependency {required_name!r} must not set readyExpr"
            )


def _validate_flux_spec(doc: dict) -> tuple[str, tuple[str, ...]]:
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        raise InventoryError("ROOT-selected Flux Kustomization spec must be a mapping")

    unknown = set(spec) - ALLOWED_SPEC_KEYS
    if unknown:
        categories = []
        if unknown & BUILD_CONTENT_KEYS:
            categories.append("build-content altering")
        if unknown & APPLY_TARGET_KEYS:
            categories.append("apply-target altering")
        if unknown & DRIFT_KEYS:
            categories.append("drift-semantics altering")
        classification = f" ({', '.join(categories)})" if categories else ""
        raise InventoryError(
            "ROOT-selected Flux Kustomization has unsupported spec key(s)"
            f"{classification}: {sorted(unknown)!r}"
        )
    findings: list[str] = []
    if spec.get("prune") is not True:
        findings.append("Flux spec.prune must be true")
    if spec.get("wait") is not True:
        findings.append("Flux spec.wait must be true")
    if "suspend" in spec and spec.get("suspend") is not False:
        findings.append("Flux spec.suspend must be absent or false")
    if "force" in spec and spec.get("force") is not False:
        findings.append("Flux spec.force must be absent or false")

    depends_on = spec.get("dependsOn")
    if not isinstance(depends_on, list):
        findings.append("Flux spec.dependsOn must be a list")
    else:
        _validate_dependency(depends_on, "vault-config-operator", findings)
        _validate_dependency(depends_on, "vault", findings)

    source_ref = spec.get("sourceRef")
    if not isinstance(source_ref, dict):
        raise InventoryError("Flux spec.sourceRef must be a mapping")
    if source_ref.get("kind") != "GitRepository":
        raise InventoryError("Flux spec.sourceRef.kind must be 'GitRepository'")
    if source_ref.get("name") != "flux-system":
        raise InventoryError("Flux spec.sourceRef.name must be 'flux-system'")
    if (
        "namespace" in source_ref
        and source_ref.get("namespace") != FLUX_NAMESPACE
    ):
        raise InventoryError(
            "Flux spec.sourceRef.namespace must be absent or 'flux-system'"
        )

    expressions = spec.get("healthCheckExprs")
    if not isinstance(expressions, list):
        findings.append("Flux spec.healthCheckExprs must be a list")
    else:
        for kind in JWT_KINDS:
            expected = {
                "apiVersion": REDHATCOP_API_VERSION,
                "kind": kind,
                "current": HEALTH_CURRENT,
            }
            matches = [
                entry
                for entry in expressions
                if isinstance(entry, dict) and entry.get("kind") == kind
            ]
            if matches != [expected]:
                findings.append(
                    f"Flux spec.healthCheckExprs must contain exactly one ratified "
                    f"{kind} entry; found {matches!r}"
                )

    path = spec.get("path")
    if not isinstance(path, str) or not path.strip():
        raise InventoryError("Flux spec.path must be a non-empty string")
    return path, tuple(findings)


def _resolve_managed_path(repo: Path, raw_path: str) -> Path:
    try:
        target = (repo / raw_path).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise InventoryError(f"could not resolve Flux spec.path {raw_path!r}: {exc}") from exc
    if target != repo and repo not in target.parents:
        raise InventoryError(
            f"Flux spec.path escapes the repository: {raw_path!r} -> {target}"
        )
    if not target.exists():
        raise InventoryError(
            "managed dir not found: Flux spec.path target does not exist: "
            f"{_display(target, repo)}"
        )
    if not target.is_dir():
        raise InventoryError(
            f"Flux spec.path target is not a directory: {_display(target, repo)}"
        )
    return target


def _read_managed_kustomization(path: Path) -> tuple[dict, list[object]]:
    if not path.is_file():
        raise InventoryError(f"managed kustomization is missing: {path}")
    try:
        raw = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise InventoryError(f"failed to parse managed kustomization {path}: {exc}") from exc
    documents = [doc for doc in raw if doc is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise InventoryError(
            f"managed kustomization {path} must contain exactly one mapping document"
        )
    doc = documents[0]
    resources = doc.get("resources")
    if not isinstance(resources, list):
        raise InventoryError(
            f"managed kustomization {path} resources must be a list"
        )
    return doc, resources


def _referenced_build_inputs(kustomization: dict) -> set[str]:
    refs: set[str] = set()
    for entry in kustomization.get("patches", []) or []:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            refs.add(entry["path"])
    for entry in kustomization.get("patchesStrategicMerge", []) or []:
        if isinstance(entry, str):
            refs.add(entry)
    for key in ("configurations", "crds", "generators", "transformers"):
        for entry in kustomization.get(key, []) or []:
            if isinstance(entry, str):
                refs.add(entry)
    openapi = kustomization.get("openapi")
    if isinstance(openapi, dict) and isinstance(openapi.get("path"), str):
        refs.add(openapi["path"])
    for key in ("configMapGenerator", "secretGenerator"):
        for generator in kustomization.get(key, []) or []:
            if not isinstance(generator, dict):
                continue
            for field in ("files", "envs"):
                for entry in generator.get(field, []) or []:
                    if isinstance(entry, str):
                        refs.add(entry.split("=", 1)[-1])
            if isinstance(generator.get("env"), str):
                refs.add(generator["env"])
    return refs


def _resolved_ref(parent: Path, ref: str) -> Path:
    try:
        return (parent / ref).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise InventoryError(f"could not resolve managed build input {ref!r}: {exc}") from exc


def _containment_findings(
    managed: Path,
    repo: Path,
    *,
    directory_entries: Callable[[Path], Iterable[Path]],
) -> tuple[str, ...]:
    try:
        entries = sorted(directory_entries(managed), key=lambda path: path.name)
    except OSError as exc:
        raise InventoryError(f"managed directory is unreadable: {managed}: {exc}") from exc
    kustomization_path = managed / "kustomization.yaml"
    kustomization, resources = _read_managed_kustomization(kustomization_path)
    resource_targets = [
        _resolved_ref(managed, ref)
        for ref in resources
        if isinstance(ref, str)
    ]
    build_inputs = {
        _resolved_ref(managed, ref)
        for ref in _referenced_build_inputs(kustomization)
    }
    findings: list[str] = []
    for entry in entries:
        label = _display(entry, repo)
        if entry.is_dir():
            findings.append(
                f"{label}: subdirectories are forbidden by the flat "
                "manifest-only policy for the prune-armed managed directory; "
                "restructure the build input outside this directory"
            )
            continue
        if entry == kustomization_path:
            continue
        try:
            resolved = entry.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise InventoryError(f"could not resolve managed file {entry}: {exc}") from exc
        if resolved in build_inputs:
            findings.append(
                f"{label}: non-resource build inputs are forbidden in the "
                "prune-armed managed directory; restructure the build input "
                "outside this directory"
            )
            continue
        count = resource_targets.count(resolved)
        if count == 0:
            findings.append(
                f"{label}: authored in the prune-armed directory but not "
                "applied — list it in resources: or remove it"
            )
        elif count != 1:
            findings.append(
                f"{label}: every resource manifest in the prune-armed "
                f"directory must be listed exactly once in resources:; found {count}"
            )
    return tuple(findings)


def applied_inventory_findings(inventory: RenderedInventory) -> list[str]:
    supported = [
        doc
        for doc in inventory.documents
        if doc.get("apiVersion") == REDHATCOP_API_VERSION
        and doc.get("kind") in SUPPORTED_MANAGED_REDHATCOP_KINDS
    ]
    findings: list[str] = []
    if not supported:
        findings.append(
            "managed render must contain at least one supported managed "
            "redhatcop CR; found 0"
        )
    configs = [
        doc for doc in supported if doc.get("kind") == "JWTOIDCAuthEngineConfig"
    ]
    if len(configs) != 1:
        findings.append(
            "managed render must contain exactly one "
            "JWTOIDCAuthEngineConfig under the ratified single-GitHub-OIDC-engine "
            f"policy; found {len(configs)} — update this guard before ratifying "
            "another engine"
        )
    return findings


def load_rendered_inventory(
    repo_root: Path,
    *,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., object] = subprocess.run,
    timeout_seconds: int = RENDER_TIMEOUT_SECONDS,
    directory_entries: Callable[[Path], Iterable[Path]] = Path.iterdir,
) -> RenderedInventory:
    try:
        repo = repo_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise InventoryError(f"could not resolve repository root {repo_root}: {exc}") from exc
    if not repo.is_dir():
        raise InventoryError(f"repository root is not a directory: {repo}")
    kubectl = which("kubectl")
    if not kubectl:
        raise InventoryError("kubectl was not found on PATH")

    root_documents = _render(
        kubectl,
        repo / ROOT_KUSTOMIZATION,
        "ROOT",
        runner=runner,
        timeout_seconds=timeout_seconds,
    )
    flux_kustomization = _select_flux_kustomization(root_documents)
    raw_path, flux_findings = _validate_flux_spec(flux_kustomization)
    managed_path = _resolve_managed_path(repo, raw_path)
    documents = _render(
        kubectl,
        managed_path,
        "managed target",
        runner=runner,
        timeout_seconds=timeout_seconds,
    )
    containment = _containment_findings(
        managed_path,
        repo,
        directory_entries=directory_entries,
    )
    return RenderedInventory(
        repo_root=repo,
        root_documents=root_documents,
        flux_kustomization=flux_kustomization,
        managed_path=managed_path,
        documents=documents,
        flux_findings=flux_findings,
        containment_findings=containment,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render the validated Flux-applied vault-config-managed inventory."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        inventory = load_rendered_inventory(args.root)
    except InventoryError as exc:
        print(f"ERROR: cannot determine rendered inventory: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - unexpected tooling errors fail closed
        print(f"ERROR: rendered inventory tooling failure: {exc!r}", file=sys.stderr)
        return 2
    findings = inventory.flux_findings + inventory.containment_findings
    if findings:
        print("FAIL: rendered inventory guard:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    yaml.safe_dump_all(inventory.documents, sys.stdout, sort_keys=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
