#!/usr/bin/env python3
"""Render fail-closed inventories from the repository's Flux configuration.

The default mode preserves the single-target, Flux-applied
``vault-config-managed`` inventory used by the Vault guards.  The ROOT render
selects that Flux Kustomization, whose validated ``spec.path`` is rendered with
the same unrestricted loader that Flux uses.

``--all-paths`` instead reports a desired-build inventory of this repository,
not applied or live cluster state.  Discovery starts from the raw ROOT render
and expands every discovered in-repository, unmodified owner to a fixed point;
it is complete over that reachable unmodified subset only.  A document with
``kind: Kustomization`` is an owner candidate only when its ``apiVersion``
determines a non-empty API group; any indeterminable group fails closed, while
a determinable other-group Kustomization remains an ordinary document.  Every
discovered owner is classified as unmodified,
modified, or external and is excluded from owner-build expansion unless it is
unmodified.  A modified owner is named as partially searched in
``reach_limits`` whenever its resolved path was rendered during the run,
whether as the ROOT bootstrap or through an unmodified owner; the remaining
modified and external owners are named as wholly unsearched.  Only unmodified
owner builds contribute documents.  Desired-build renders reject explicit
null documents, while the default single-target mode retains its established
parser and still skips them.  ``apply_semantics`` surface state-affecting
fields without claiming that the desired build models whether objects are
applied or what survives in the cluster.

Faithful Flux build emulation, external-owner RBAC confinement,
``LoadRestrictionsNone`` input provenance, and a coverage ratchet remain
deferred to q1b-1c, q1b-1d, q1b-1e, and q1b-1f respectively.

Consumers must not recover from ``InventoryError`` by falling back to an
authored-file scan.  The production ROOT contains a remote Gateway API base,
so loading either inventory requires network access until TD-0020 is closed
with a pinned local mirror.
"""

from __future__ import annotations

import argparse
import json
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
DESIRED_BUILD_AFFECTING_KEYS = {
    "patches",
    "images",
    "components",
    "ignoreMissingComponents",
    "targetNamespace",
    "namePrefix",
    "nameSuffix",
    "commonMetadata",
    "postBuild",
    "decryption",
    "buildMetadata",
}
DESIRED_BUILD_ROUTING_KEYS = {"path", "sourceRef"}
DESIRED_BUILD_NEUTRAL_KEYS = {
    "interval",
    "retryInterval",
    "timeout",
    "prune",
    "wait",
    "force",
    "dependsOn",
    "healthChecks",
    "healthCheckExprs",
    "serviceAccountName",
    "deletionPolicy",
    "suspend",
}
DESIRED_BUILD_APPLY_SEMANTICS_KEYS = (
    "prune",
    "force",
    "deletionPolicy",
    "suspend",
    "serviceAccountName",
)
DESIRED_BUILD_BOOLEAN_KEYS = ("prune", "wait", "force", "suspend")
MAX_DISCOVERED_OWNERS = 100
ROOT_PARTIALLY_SEARCHED_REASON = (
    "partially searched: raw bootstrap scanned, but the modified owner build "
    "was not expanded; nested owners requiring its build semantics may be undiscovered"
)
MODIFIED_PARTIALLY_SEARCHED_REASON = (
    "partially searched: path was rendered through an unmodified owner, but the "
    "modified owner build was not expanded; nested owners requiring its build "
    "semantics may be undiscovered"
)
MODIFIED_WHOLELY_UNSEARCHED_REASON = (
    "wholly unsearched: modified owner build was not expanded; nested owners "
    "may be undiscovered"
)
EXTERNAL_WHOLELY_UNSEARCHED_REASON = (
    "wholly unsearched: external source is not available in this repository; "
    "nested owners may be undiscovered"
)


class InventoryError(RuntimeError):
    """The requested inventory could not be determined safely."""


@dataclass(frozen=True)
class RenderedInventory:
    repo_root: Path
    root_documents: tuple[dict, ...]
    flux_kustomization: dict
    managed_path: Path
    documents: tuple[dict, ...]
    flux_findings: tuple[str, ...]
    containment_findings: tuple[str, ...]


@dataclass(frozen=True)
class DesiredBuildOwner:
    """A discovered Flux owner and its total desired-build classification."""

    namespace: str
    name: str
    spec: dict
    raw_path: str
    resolved_path: Path | None
    source_kind: str
    source_namespace: str
    source_name: str
    classification: str
    build_affecting_keys: tuple[str, ...]
    apply_semantics: dict[str, object]

    @property
    def identity(self) -> tuple[str, str]:
        return self.namespace, self.name


@dataclass(frozen=True)
class DesiredBuildDocument:
    """A desired-build document attributed to the owner that emits it."""

    owner_namespace: str
    owner_name: str
    document: dict

    @property
    def owner_identity(self) -> tuple[str, str]:
        return self.owner_namespace, self.owner_name


@dataclass(frozen=True)
class ReachLimit:
    """A discovered owner whose descendants the closure cannot fully search."""

    owner_namespace: str
    owner_name: str
    classification: str
    reason: str

    @property
    def owner_identity(self) -> tuple[str, str]:
        return self.owner_namespace, self.owner_name


@dataclass(frozen=True)
class DesiredBuildInventory:
    """Desired repository build output, not an inventory of live state."""

    repo_root: Path
    root_documents: tuple[dict, ...]
    owners: tuple[DesiredBuildOwner, ...]
    documents: tuple[DesiredBuildDocument, ...]
    reach_limits: tuple[ReachLimit, ...]


def _display(path: Path, repo: Path) -> str:
    try:
        return str(path.relative_to(repo))
    except ValueError:
        return str(path)


def rendered_document_label(doc: dict) -> str:
    """Return a stable diagnostic label derived from rendered kind and name."""
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    return (
        f"managed render {doc.get('kind')!r}/"
        f"{metadata.get('name')!r}"
    )


def desired_build_document_label(
    doc: dict, owner_namespace: str, owner_name: str
) -> str:
    """Label a desired-build document using only render and owner identity."""
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    return (
        f"owner {owner_namespace}/{owner_name} render "
        f"{doc.get('kind')!r}/{metadata.get('name')!r}"
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


def _parse_desired_build_yaml(stdout: object, label: str) -> tuple[dict, ...]:
    """Parse desired-build output, skipping empty but rejecting explicit-null documents."""
    if isinstance(stdout, str):
        try:
            nodes = list(yaml.compose_all(stdout))
        except yaml.YAMLError:
            # Preserve the established parser's diagnostic for malformed YAML.
            return _parse_rendered_yaml(stdout, label)
        for index, node in enumerate(nodes, start=1):
            if (
                node.tag == "tag:yaml.org,2002:null"
                and node.start_mark.index != node.end_mark.index
            ):
                raise InventoryError(
                    f"{label} render document {index} is explicit null, not a mapping"
                )
    return _parse_rendered_yaml(stdout, label)


def _render(
    kubectl: str,
    target: Path,
    label: str,
    *,
    runner: Callable[..., object],
    timeout_seconds: int,
    parser: Callable[[object, str], tuple[dict, ...]] = _parse_rendered_yaml,
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
    return parser(getattr(result, "stdout", None), label)


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


def _owner_document_context(label: str, index: int, doc: dict) -> str:
    metadata = doc.get("metadata")
    if isinstance(metadata, dict):
        namespace = metadata.get("namespace")
        name = metadata.get("name")
        if isinstance(namespace, str) and namespace and isinstance(name, str) and name:
            return f"{label} document {index} {namespace}/{name}"
        if isinstance(name, str) and name:
            return f"{label} document {index} {name}"
    return f"{label} document {index}"


def _required_non_empty_string(value: object, field: str, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InventoryError(f"{context} {field} must be a non-empty string")
    return value


def _desired_build_owner(
    repo: Path,
    doc: dict,
    *,
    context: str,
) -> DesiredBuildOwner:
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        raise InventoryError(f"{context} metadata must be a mapping")
    name = _required_non_empty_string(metadata.get("name"), "metadata.name", context)
    namespace = _required_non_empty_string(
        metadata.get("namespace"), "metadata.namespace", context
    )
    owner_context = f"owner {namespace}/{name}"

    spec = doc.get("spec")
    if not isinstance(spec, dict):
        raise InventoryError(f"{owner_context} spec must be a mapping")

    if "kubeConfig" in spec:
        raise InventoryError(
            f"{owner_context} has unsupported spec key 'kubeConfig'"
        )
    recognised = (
        DESIRED_BUILD_AFFECTING_KEYS
        | DESIRED_BUILD_ROUTING_KEYS
        | DESIRED_BUILD_NEUTRAL_KEYS
    )
    unrecognised = [key for key in spec if key not in recognised]
    if unrecognised:
        ordered = sorted(unrecognised, key=repr)
        raise InventoryError(
            f"{owner_context} has unrecognised spec key(s): {ordered!r}"
        )

    raw_path = _required_non_empty_string(
        spec.get("path"), "spec.path", owner_context
    )
    source_ref = spec.get("sourceRef")
    if not isinstance(source_ref, dict):
        raise InventoryError(f"{owner_context} spec.sourceRef must be a mapping")
    source_kind = _required_non_empty_string(
        source_ref.get("kind"), "spec.sourceRef.kind", owner_context
    )
    source_name = _required_non_empty_string(
        source_ref.get("name"), "spec.sourceRef.name", owner_context
    )
    if "namespace" in source_ref:
        source_namespace = _required_non_empty_string(
            source_ref.get("namespace"),
            "spec.sourceRef.namespace",
            owner_context,
        )
    else:
        source_namespace = namespace

    for field in ("serviceAccountName", "targetNamespace"):
        if field in spec:
            _required_non_empty_string(spec.get(field), f"spec.{field}", owner_context)
    for field in DESIRED_BUILD_BOOLEAN_KEYS:
        if field in spec and not isinstance(spec.get(field), bool):
            raise InventoryError(f"{owner_context} spec.{field} must be boolean")

    build_affecting_keys = tuple(
        sorted(key for key in DESIRED_BUILD_AFFECTING_KEYS if key in spec)
    )
    in_repository = (
        source_kind == "GitRepository"
        and source_namespace == FLUX_NAMESPACE
        and source_name == "flux-system"
    )
    if not in_repository:
        classification = "external"
        resolved_path = None
        apply_semantics: dict[str, object] = {}
    else:
        classification = "modified" if build_affecting_keys else "unmodified"
        try:
            resolved_path = _resolve_managed_path(repo, raw_path)
        except InventoryError as exc:
            raise InventoryError(
                f"{owner_context} spec.path {raw_path!r}: {exc}"
            ) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise InventoryError(
                f"{owner_context} spec.path {raw_path!r} could not be resolved: {exc}"
            ) from exc
        apply_semantics = (
            {
                key: spec[key]
                for key in DESIRED_BUILD_APPLY_SEMANTICS_KEYS
                if key in spec
            }
            if classification == "unmodified"
            else {}
        )

    return DesiredBuildOwner(
        namespace=namespace,
        name=name,
        spec=spec,
        raw_path=raw_path,
        resolved_path=resolved_path,
        source_kind=source_kind,
        source_namespace=source_namespace,
        source_name=source_name,
        classification=classification,
        build_affecting_keys=build_affecting_keys,
        apply_semantics=apply_semantics,
    )


def _flux_owner_from_document(
    repo: Path,
    doc: dict,
    *,
    label: str,
    index: int,
) -> DesiredBuildOwner | None:
    if doc.get("kind") != FLUX_KIND:
        return None
    context = _owner_document_context(label, index, doc)
    api_version = doc.get("apiVersion")
    if not isinstance(api_version, str):
        raise InventoryError(f"{context} apiVersion must be a string")
    api_group = api_version.split("/", 1)[0]
    if not api_group.strip():
        raise InventoryError(
            f"{context} apiVersion {api_version!r} has indeterminable API group"
        )
    if api_group != "kustomize.toolkit.fluxcd.io":
        return None
    if api_version != FLUX_API_VERSION:
        raise InventoryError(
            f"{context} uses unsupported Flux apiVersion {api_version!r}; "
            f"supported version is {FLUX_API_VERSION!r}"
        )
    return _desired_build_owner(repo, doc, context=context)


def _type_strict_equal(left: object, right: object) -> bool:
    """Compare parsed YAML values without Python's cross-type coercion."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        if len(left) != len(right):
            return False
        unmatched = list(right.items())
        for left_key, left_value in left.items():
            for index, (right_key, right_value) in enumerate(unmatched):
                if _type_strict_equal(left_key, right_key) and _type_strict_equal(
                    left_value, right_value
                ):
                    unmatched.pop(index)
                    break
            else:
                return False
        return True
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(
            _type_strict_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    if isinstance(left, (set, frozenset)):
        unmatched = list(right)
        for left_item in left:
            for index, right_item in enumerate(unmatched):
                if _type_strict_equal(left_item, right_item):
                    unmatched.pop(index)
                    break
            else:
                return False
        return True
    return left == right


def load_desired_build_inventory(
    repo_root: Path,
    *,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., object] = subprocess.run,
    timeout_seconds: int = RENDER_TIMEOUT_SECONDS,
    directory_entries: Callable[[Path], Iterable[Path]] = Path.iterdir,
    max_discovered_owners: int = MAX_DISCOVERED_OWNERS,
) -> DesiredBuildInventory:
    """Discover and render the unmodified Flux-owner desired-build closure.

    The raw ROOT build is an unconditional discovery bootstrap.  Only owners
    classified as unmodified are expanded, so discovery is complete only over
    the reachable unmodified subset.  ``reach_limits`` identifies every
    discovered modified or external frontier where nested owners may remain
    undiscovered; a modified owner is partially searched whenever its resolved
    path was rendered during this run.  Apply-semantics values are surfaced,
    but the returned documents describe desired repository output rather than
    live state.
    """
    try:
        repo = repo_root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise InventoryError(f"could not resolve repository root {repo_root}: {exc}") from exc
    if not repo.is_dir():
        raise InventoryError(f"repository root is not a directory: {repo}")
    kubectl = which("kubectl")
    if not kubectl:
        raise InventoryError("kubectl was not found on PATH")
    if (
        not isinstance(max_discovered_owners, int)
        or isinstance(max_discovered_owners, bool)
        or max_discovered_owners < 1
    ):
        raise InventoryError("maximum unique discovered owners must be a positive integer")

    # This retained seam keeps hermetic callers aligned with the existing
    # loader even though desired-build discovery does not inspect directory
    # contents outside kubectl's render.
    _ = directory_entries

    root_target = (repo / ROOT_KUSTOMIZATION).resolve(strict=False)
    root_documents = _render(
        kubectl,
        root_target,
        "ROOT bootstrap",
        runner=runner,
        timeout_seconds=timeout_seconds,
        parser=_parse_desired_build_yaml,
    )
    render_cache: dict[Path, tuple[dict, ...]] = {root_target: root_documents}
    owners: dict[tuple[str, str], DesiredBuildOwner] = {}
    pending: set[tuple[str, str]] = set()
    expanded: set[tuple[str, str]] = set()
    desired_documents: list[DesiredBuildDocument] = []

    def discover(documents: tuple[dict, ...], label: str) -> None:
        candidates: list[DesiredBuildOwner] = []
        for index, document in enumerate(documents, start=1):
            candidate = _flux_owner_from_document(
                repo,
                document,
                label=label,
                index=index,
            )
            if candidate is not None:
                candidates.append(candidate)

        for candidate in candidates:
            identity = candidate.identity
            previous = owners.get(identity)
            if previous is not None:
                if not _type_strict_equal(previous.spec, candidate.spec):
                    raise InventoryError(
                        f"duplicate owner {identity[0]}/{identity[1]} has differing specs"
                    )
                continue
            reached = len(owners) + 1
            if reached > max_discovered_owners:
                raise InventoryError(
                    "discovery limit exceeded: maximum unique discovered owners "
                    f"is {max_discovered_owners}; count reached {reached}"
                )
            owners[identity] = candidate
            if candidate.classification == "unmodified":
                pending.add(identity)

    discover(root_documents, "ROOT bootstrap render")
    while pending:
        identity = min(pending)
        pending.remove(identity)
        if identity in expanded:
            continue
        owner = owners[identity]
        expanded.add(identity)
        if owner.resolved_path is None:  # pragma: no cover - class invariant
            raise InventoryError(
                f"owner {owner.namespace}/{owner.name} has no resolved in-repository path"
            )
        documents = render_cache.get(owner.resolved_path)
        if documents is None:
            documents = _render(
                kubectl,
                owner.resolved_path,
                f"owner {owner.namespace}/{owner.name} path {owner.raw_path!r}",
                runner=runner,
                timeout_seconds=timeout_seconds,
                parser=_parse_desired_build_yaml,
            )
            render_cache[owner.resolved_path] = documents
        desired_documents.extend(
            DesiredBuildDocument(owner.namespace, owner.name, document)
            for document in documents
        )
        discover(documents, f"owner {owner.namespace}/{owner.name} render")

    ordered_owners = tuple(owners[key] for key in sorted(owners))
    reach_limits: list[ReachLimit] = []
    for owner in ordered_owners:
        if owner.classification == "unmodified":
            continue
        if owner.classification == "modified" and owner.resolved_path == root_target:
            reason = ROOT_PARTIALLY_SEARCHED_REASON
        elif owner.classification == "modified" and owner.resolved_path in render_cache:
            reason = MODIFIED_PARTIALLY_SEARCHED_REASON
        elif owner.classification == "modified":
            reason = MODIFIED_WHOLELY_UNSEARCHED_REASON
        else:
            reason = EXTERNAL_WHOLELY_UNSEARCHED_REASON
        reach_limits.append(
            ReachLimit(
                owner_namespace=owner.namespace,
                owner_name=owner.name,
                classification=owner.classification,
                reason=reason,
            )
        )

    return DesiredBuildInventory(
        repo_root=repo,
        root_documents=root_documents,
        owners=ordered_owners,
        documents=tuple(desired_documents),
        reach_limits=tuple(reach_limits),
    )


def _print_desired_build_inventory(inventory: DesiredBuildInventory) -> None:
    print("Desired-build inventory (repository output, not live state)")
    for classification in ("unmodified", "modified", "external"):
        members = [
            owner
            for owner in inventory.owners
            if owner.classification == classification
        ]
        print(f"{classification} ({len(members)}):")
        for owner in members:
            identity = f"{owner.namespace}/{owner.name}"
            if classification == "unmodified":
                semantics = json.dumps(owner.apply_semantics, sort_keys=True)
                print(
                    f"  - {identity}: path={owner.raw_path!r}; "
                    f"apply_semantics={semantics}"
                )
            elif classification == "modified":
                print(
                    f"  - {identity}: path={owner.raw_path!r}; "
                    f"build_affecting_keys={list(owner.build_affecting_keys)!r}"
                )
            else:
                source = (
                    f"{owner.source_kind} "
                    f"{owner.source_namespace}/{owner.source_name}"
                )
                print(
                    f"  - {identity}: source={source}; path={owner.raw_path!r}"
                )
    print(f"reach_limits ({len(inventory.reach_limits)}):")
    for limit in inventory.reach_limits:
        print(
            f"  - {limit.owner_namespace}/{limit.owner_name} "
            f"[{limit.classification}]: {limit.reason}"
        )


def _all_paths_main(root: Path) -> int:
    try:
        inventory = load_desired_build_inventory(root)
    except InventoryError as exc:
        print(
            f"ERROR: cannot determine desired-build inventory: {exc}",
            file=sys.stderr,
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - unexpected tooling errors fail closed
        print(f"ERROR: desired-build inventory tooling failure: {exc!r}", file=sys.stderr)
        return 2
    _print_desired_build_inventory(inventory)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Render the validated single-target inventory or report desired-build "
            "owner discovery."
        )
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--all-paths",
        action="store_true",
        help="report the Flux-owner desired-build discovery closure",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.all_paths:
        return _all_paths_main(args.root)
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
