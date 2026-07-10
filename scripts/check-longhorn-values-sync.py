#!/usr/bin/env python3
"""Fail if retained Longhorn addon values drift from Flux HelmRelease values."""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


DEFAULT_ADDON_VALUES = Path("addons/longhorn/values.yaml")
DEFAULT_HELMRELEASE = Path("clusters/talos-cluster/apps/longhorn/release/helmrelease.yaml")


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must parse to a YAML mapping")
    return data


def canonical_yaml(value: Any) -> list[str]:
    text = yaml.safe_dump(value, sort_keys=True, default_flow_style=False)
    return text.splitlines(keepends=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare addons/longhorn/values.yaml with the Flux Longhorn "
            "HelmRelease spec.values mapping after YAML normalization."
        )
    )
    parser.add_argument(
        "--addon-values",
        type=Path,
        default=DEFAULT_ADDON_VALUES,
        help=f"retained addon values file (default: {DEFAULT_ADDON_VALUES})",
    )
    parser.add_argument(
        "--helmrelease",
        type=Path,
        default=DEFAULT_HELMRELEASE,
        help=f"Flux HelmRelease file (default: {DEFAULT_HELMRELEASE})",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        addon_values = load_yaml_mapping(args.addon_values)
        helmrelease = load_yaml_mapping(args.helmrelease)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: failed to load Longhorn values inputs: {exc}", file=sys.stderr)
        return 1

    spec = helmrelease.get("spec")
    if not isinstance(spec, dict):
        print(f"ERROR: {args.helmrelease} must contain a spec mapping", file=sys.stderr)
        return 1

    helmrelease_values = spec.get("values")
    if not isinstance(helmrelease_values, dict):
        print(
            f"ERROR: {args.helmrelease} must contain a spec.values mapping",
            file=sys.stderr,
        )
        return 1

    if addon_values == helmrelease_values:
        print(
            f"Longhorn values match: {args.addon_values} == "
            f"{args.helmrelease} spec.values"
        )
        return 0

    diff = difflib.unified_diff(
        canonical_yaml(addon_values),
        canonical_yaml(helmrelease_values),
        fromfile=str(args.addon_values),
        tofile=f"{args.helmrelease}:spec.values",
    )
    print(
        "ERROR: retained Longhorn addon values drift from Flux HelmRelease "
        "spec.values:",
        file=sys.stderr,
    )
    for line in diff:
        print(line, end="", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
