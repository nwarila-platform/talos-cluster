#!/usr/bin/env python3
"""Fail if Flux CRD served/storage versions drift from the reviewed map."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

try:
    import yaml
    from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


DEFAULT_GOTK_COMPONENTS = Path(
    "clusters/talos-cluster/flux-system/gotk-components.yaml"
)

REMOVAL_WARNING = (
    "a served version was removed — before merging, confirm live "
    "`status.storedVersions` for this CRD no longer lists it and 0 resources "
    "use it (see [[flux_crd_served_version_removal]] runbook), then update "
    "EXPECTED_FLUX_CRD_VERSIONS."
)
DELIBERATE_UPDATE = (
    "deliberate map update required after review in "
    "EXPECTED_FLUX_CRD_VERSIONS."
)

EXPECTED_FLUX_CRD_VERSIONS = {
    "buckets.source.toolkit.fluxcd.io": {
        "served": ["v1"],
        "storage": "v1",
    },
    "externalartifacts.source.toolkit.fluxcd.io": {
        "served": ["v1"],
        "storage": "v1",
    },
    "gitrepositories.source.toolkit.fluxcd.io": {
        "served": ["v1"],
        "storage": "v1",
    },
    "helmcharts.source.toolkit.fluxcd.io": {
        "served": ["v1"],
        "storage": "v1",
    },
    "helmrepositories.source.toolkit.fluxcd.io": {
        "served": ["v1"],
        "storage": "v1",
    },
    "ocirepositories.source.toolkit.fluxcd.io": {
        "served": ["v1"],
        "storage": "v1",
    },
    "kustomizations.kustomize.toolkit.fluxcd.io": {
        "served": ["v1"],
        "storage": "v1",
    },
    "helmreleases.helm.toolkit.fluxcd.io": {
        "served": ["v2"],
        "storage": "v2",
    },
    "alerts.notification.toolkit.fluxcd.io": {
        "served": ["v1beta3"],
        "storage": "v1beta3",
    },
    "providers.notification.toolkit.fluxcd.io": {
        "served": ["v1beta3"],
        "storage": "v1beta3",
    },
    "receivers.notification.toolkit.fluxcd.io": {
        "served": ["v1"],
        "storage": "v1",
    },
}


@dataclass(frozen=True)
class CrdVersionShape:
    name: str
    served: tuple[str, ...]
    storage: str


class GuardUsageError(Exception):
    """A tooling or input error that should exit with code 2."""


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Check Flux CRD served/storage versions in gotk-components.yaml "
            "against the reviewed expected map."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=DEFAULT_GOTK_COMPONENTS,
        help=(
            "gotk-components.yaml path to check "
            "(default: clusters/talos-cluster/flux-system/gotk-components.yaml)"
        ),
    )
    return parser.parse_args(argv)


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def scalar_value(node: Node) -> str | None:
    if isinstance(node, ScalarNode):
        return node.value
    return None


def mapping_fields(node: MappingNode) -> dict[str, Node]:
    fields: dict[str, Node] = {}
    for key_node, value_node in node.value:
        key = scalar_value(key_node)
        if key is not None:
            fields[key] = value_node
    return fields


def require_mapping(node: Node | None, path: Path, context: str) -> MappingNode:
    if not isinstance(node, MappingNode):
        raise GuardUsageError(f"{display_path(path)}: {context} must be a mapping")
    return node


def require_sequence(node: Node | None, path: Path, context: str) -> SequenceNode:
    if not isinstance(node, SequenceNode):
        raise GuardUsageError(f"{display_path(path)}: {context} must be a list")
    return node


def require_scalar(node: Node | None, path: Path, context: str) -> str:
    value = scalar_value(node) if node is not None else None
    if value is None or value == "":
        raise GuardUsageError(
            f"{display_path(path)}: {context} must be a non-empty scalar"
        )
    return value


def optional_bool(node: Node | None, path: Path, context: str) -> bool:
    if node is None:
        return False
    if not isinstance(node, ScalarNode) or node.tag != "tag:yaml.org,2002:bool":
        raise GuardUsageError(f"{display_path(path)}: {context} must be a boolean")
    return node.value.lower() in {"true", "yes", "on"}


def load_yaml_documents(path: Path) -> list[Node | None]:
    try:
        with path.open(encoding="utf-8") as handle:
            return list(yaml.compose_all(handle, Loader=yaml.SafeLoader))
    except FileNotFoundError as exc:
        raise GuardUsageError(f"{display_path(path)}: missing file") from exc
    except yaml.YAMLError as exc:
        raise GuardUsageError(
            f"{display_path(path)}: YAML parse error: {exc}"
        ) from exc
    except OSError as exc:
        raise GuardUsageError(f"{display_path(path)}: failed to read: {exc}") from exc


def extract_crd_shape(document: MappingNode, path: Path) -> CrdVersionShape | None:
    fields = mapping_fields(document)
    if scalar_value(fields.get("kind")) != "CustomResourceDefinition":
        return None

    metadata = require_mapping(fields.get("metadata"), path, "CRD metadata")
    name = require_scalar(
        mapping_fields(metadata).get("name"),
        path,
        "CRD metadata.name",
    )

    spec = require_mapping(fields.get("spec"), path, f"{name} spec")
    spec_fields = mapping_fields(spec)
    versions = require_sequence(
        spec_fields.get("versions"),
        path,
        f"{name} spec.versions",
    )

    served: list[str] = []
    storage: list[str] = []
    seen_versions: set[str] = set()
    for index, version_node in enumerate(versions.value):
        version = require_mapping(version_node, path, f"{name} spec.versions[{index}]")
        version_fields = mapping_fields(version)
        version_name = require_scalar(
            version_fields.get("name"),
            path,
            f"{name} spec.versions[{index}].name",
        )
        if version_name in seen_versions:
            raise GuardUsageError(
                f"{display_path(path)}: {name} repeats version {version_name}"
            )
        seen_versions.add(version_name)

        if optional_bool(
            version_fields.get("served"),
            path,
            f"{name} spec.versions[{index}].served",
        ):
            served.append(version_name)
        if optional_bool(
            version_fields.get("storage"),
            path,
            f"{name} spec.versions[{index}].storage",
        ):
            storage.append(version_name)

    if not served:
        raise GuardUsageError(f"{display_path(path)}: {name} has no served versions")
    if len(storage) != 1:
        raise GuardUsageError(
            f"{display_path(path)}: {name} must have exactly one storage version "
            f"(found {format_versions(storage)})"
        )

    return CrdVersionShape(name=name, served=tuple(served), storage=storage[0])


def load_crd_shapes(path: Path) -> dict[str, CrdVersionShape]:
    shapes: dict[str, CrdVersionShape] = {}
    for document in load_yaml_documents(path):
        if document is None:
            continue
        if not isinstance(document, MappingNode):
            continue

        shape = extract_crd_shape(document, path)
        if shape is None:
            continue
        if shape.name in shapes:
            raise GuardUsageError(f"{display_path(path)}: duplicate CRD {shape.name}")
        shapes[shape.name] = shape
    return shapes


def normalize_expected_map() -> dict[str, CrdVersionShape]:
    shapes: dict[str, CrdVersionShape] = {}
    for name, raw_shape in EXPECTED_FLUX_CRD_VERSIONS.items():
        served = raw_shape.get("served")
        storage = raw_shape.get("storage")
        if (
            not isinstance(name, str)
            or not isinstance(served, list)
            or not served
            or not all(isinstance(version, str) and version for version in served)
            or len(served) != len(set(served))
            or not isinstance(storage, str)
            or not storage
            or storage not in served
        ):
            raise GuardUsageError(
                "EXPECTED_FLUX_CRD_VERSIONS must map each CRD to unique "
                "served versions and one served storage version"
            )
        shapes[name] = CrdVersionShape(name=name, served=tuple(served), storage=storage)
    return shapes


def format_versions(versions: Sequence[str]) -> str:
    return "[" + ", ".join(versions) + "]"


def compare_shapes(
    expected: dict[str, CrdVersionShape],
    actual: dict[str, CrdVersionShape],
) -> list[str]:
    findings: list[str] = []

    expected_names = set(expected)
    actual_names = set(actual)

    for name in sorted(expected_names - actual_names):
        findings.append(
            f"ERROR: {name}: CRD is in EXPECTED_FLUX_CRD_VERSIONS but missing "
            f"from gotk-components.yaml; {DELIBERATE_UPDATE}"
        )

    for name in sorted(actual_names - expected_names):
        findings.append(
            f"ERROR: {name}: CRD is present in gotk-components.yaml but missing "
            f"from EXPECTED_FLUX_CRD_VERSIONS; {DELIBERATE_UPDATE}"
        )

    for name in sorted(expected_names & actual_names):
        expected_shape = expected[name]
        actual_shape = actual[name]
        expected_served = set(expected_shape.served)
        actual_served = set(actual_shape.served)

        removed_versions = expected_served - actual_served
        for version in sorted(removed_versions):
            findings.append(
                f"ERROR: {name}: served version {version} is missing from "
                f"gotk-components.yaml; {REMOVAL_WARNING}"
            )

        added_versions = actual_served - expected_served
        if added_versions:
            findings.append(
                f"ERROR: {name}: served versions added "
                f"{format_versions(sorted(added_versions))}; {DELIBERATE_UPDATE}"
            )

        if actual_shape.storage != expected_shape.storage:
            findings.append(
                f"ERROR: {name}: storage version changed from "
                f"{expected_shape.storage} to {actual_shape.storage}; "
                f"{DELIBERATE_UPDATE}"
            )

    return findings


def print_pass(actual: dict[str, CrdVersionShape]) -> None:
    print(
        "PASS: Flux CRD served/storage versions match "
        f"EXPECTED_FLUX_CRD_VERSIONS for {len(actual)} CRDs:"
    )
    for name in EXPECTED_FLUX_CRD_VERSIONS:
        shape = actual[name]
        print(
            f"  - {name}: served={format_versions(shape.served)} "
            f"storage={shape.storage}"
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    try:
        expected = normalize_expected_map()
        actual = load_crd_shapes(args.path)
    except GuardUsageError as exc:
        print(f"ERROR: GuardUsageError: {exc}", file=sys.stderr)
        return 2

    findings = compare_shapes(expected, actual)
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1

    print_pass(actual)
    return 0


if __name__ == "__main__":
    sys.exit(main())
