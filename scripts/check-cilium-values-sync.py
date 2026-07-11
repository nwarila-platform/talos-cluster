#!/usr/bin/env python3
"""Fail if retained Cilium addon values or version drift from Flux."""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


DEFAULT_ADDON_VALUES = Path("addons/cilium/values.yaml")
DEFAULT_CONFIG_ENV = Path("cluster/config.env")
DEFAULT_HELMRELEASE = Path("clusters/talos-cluster/apps/cilium/release/helmrelease.yaml")


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must parse to a YAML mapping")
    return data


def canonical_yaml(value: Any) -> list[str]:
    text = yaml.safe_dump(value, sort_keys=True, default_flow_style=False)
    return text.splitlines(keepends=True)


def load_config_value(path: Path, name: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)}=(?P<quote>[\"']?)(?P<value>.*?)(?P=quote)\s*$")
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            match = pattern.match(line.strip())
            if match:
                return match.group("value")
    raise ValueError(f"{path} must define {name}")


def helmrelease_chart_version(helmrelease: dict[str, Any], path: Path) -> str:
    spec = helmrelease.get("spec")
    if not isinstance(spec, dict):
        raise ValueError(f"{path} must contain a spec mapping")

    chart = spec.get("chart")
    if not isinstance(chart, dict):
        raise ValueError(f"{path} must contain a spec.chart mapping")

    chart_spec = chart.get("spec")
    if not isinstance(chart_spec, dict):
        raise ValueError(f"{path} must contain a spec.chart.spec mapping")

    version = chart_spec.get("version")
    if not isinstance(version, str):
        raise ValueError(f"{path} spec.chart.spec.version must be a string")
    return version


def helmrelease_values(helmrelease: dict[str, Any], path: Path) -> dict[str, Any]:
    spec = helmrelease.get("spec")
    if not isinstance(spec, dict):
        raise ValueError(f"{path} must contain a spec mapping")

    values = spec.get("values")
    if not isinstance(values, dict):
        raise ValueError(f"{path} must contain a spec.values mapping")
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare addons/cilium/values.yaml with the Flux Cilium "
            "HelmRelease spec.values mapping after YAML normalization, and "
            "ensure cluster/config.env CILIUM_VERSION matches the chart version."
        )
    )
    parser.add_argument(
        "--addon-values",
        type=Path,
        default=DEFAULT_ADDON_VALUES,
        help=f"retained addon values file (default: {DEFAULT_ADDON_VALUES})",
    )
    parser.add_argument(
        "--config-env",
        type=Path,
        default=DEFAULT_CONFIG_ENV,
        help=f"cluster config.env file (default: {DEFAULT_CONFIG_ENV})",
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
        cilium_version = load_config_value(args.config_env, "CILIUM_VERSION")
        chart_version = helmrelease_chart_version(helmrelease, args.helmrelease)
        release_values = helmrelease_values(helmrelease, args.helmrelease)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: failed to load Cilium guard inputs: {exc}", file=sys.stderr)
        return 1

    failed = False
    if addon_values != release_values:
        diff = difflib.unified_diff(
            canonical_yaml(addon_values),
            canonical_yaml(release_values),
            fromfile=str(args.addon_values),
            tofile=f"{args.helmrelease}:spec.values",
        )
        print(
            "ERROR: retained Cilium addon values drift from Flux HelmRelease "
            "spec.values:",
            file=sys.stderr,
        )
        for line in diff:
            print(line, end="", file=sys.stderr)
        failed = True

    if cilium_version != chart_version:
        print(
            "ERROR: cluster/config.env CILIUM_VERSION drift from Flux "
            f"HelmRelease chart version: {cilium_version!r} != {chart_version!r}",
            file=sys.stderr,
        )
        failed = True

    if failed:
        return 1

    print(
        f"Cilium values match: {args.addon_values} == "
        f"{args.helmrelease} spec.values"
    )
    print(
        "Cilium version matches: "
        f"{args.config_env} CILIUM_VERSION == {chart_version}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
