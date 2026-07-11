#!/usr/bin/env python3
"""Render README version pins from canonical cluster version sources."""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path


README = Path("README.md")
CONFIG_ENV = Path("cluster/config.env")
KYVERNO_HELMRELEASE = Path("clusters/talos-cluster/apps/kyverno/release/helmrelease.yaml")
METRICS_SERVER_HELMRELEASE = Path("clusters/talos-cluster/apps/metrics-server/helmrelease.yaml")
KUBELET_CSR_APPROVER_HELMRELEASE = Path(
    "clusters/talos-cluster/apps/kubelet-csr-approver/helmrelease.yaml"
)
GOTK_COMPONENTS = Path("clusters/talos-cluster/flux-system/gotk-components.yaml")
GATEWAY_API_KUSTOMIZATION = Path("clusters/talos-cluster/apps/gateway-api/kustomization.yaml")


class RenderError(RuntimeError):
    """Raised when a canonical source or README target cannot be resolved."""


def read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except FileNotFoundError as exc:
        raise RenderError(f"missing required source: {path}") from exc
    except UnicodeDecodeError as exc:
        raise RenderError(f"{path} is not valid UTF-8") from exc


def parse_config_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r'^([A-Z0-9_]+)="([^"]*)"$', line.strip())
        if match:
            values[match.group(1)] = match.group(2)
    return values


def require_values(values: dict[str, str], names: list[str], source: Path) -> dict[str, str]:
    missing = [name for name in names if not values.get(name)]
    if missing:
        raise RenderError(f"{source} missing required values: {', '.join(missing)}")
    return {name: values[name] for name in names}


def read_helm_chart_version(path: Path, chart: str) -> str:
    found_chart = False
    for line in read_text(path).splitlines():
        if re.match(rf"^\s*chart:\s*{re.escape(chart)}\s*(?:#.*)?$", line):
            found_chart = True
            continue
        if found_chart:
            match = re.match(r"^\s*version:\s*([^\s#]+)\s*(?:#.*)?$", line)
            if match:
                return match.group(1)
    raise RenderError(f"could not derive {chart} chart version from {path}")


def read_flux_version(path: Path) -> str:
    matches = re.findall(r"(?m)^# Flux Version:\s+(\S+)\s*$", read_text(path))
    if len(matches) != 1:
        raise RenderError(f"expected exactly one Flux Version comment in {path}, found {len(matches)}")
    return matches[0]


def read_gateway_api_version(path: Path) -> str:
    matches = re.findall(
        r"releases/download/(v[0-9]+\.[0-9]+\.[0-9]+)/standard-install\.yaml",
        read_text(path),
    )
    unique = sorted(set(matches))
    if len(unique) != 1:
        raise RenderError(f"expected exactly one Gateway API standard-install version in {path}, found {unique}")
    return unique[0]


def collect_versions() -> dict[str, str]:
    config_values = require_values(
        parse_config_env(read_text(CONFIG_ENV)),
        ["TALOS_VERSION", "KUBERNETES_VERSION", "CILIUM_VERSION", "LONGHORN_VERSION"],
        CONFIG_ENV,
    )
    return {
        "TalosOS": config_values["TALOS_VERSION"],
        "Kubernetes": config_values["KUBERNETES_VERSION"],
        "Cilium": config_values["CILIUM_VERSION"],
        "CoreDNS": "bundled with Kubernetes",
        "Flux": read_flux_version(GOTK_COMPONENTS),
        "Kyverno": read_helm_chart_version(KYVERNO_HELMRELEASE, "kyverno"),
        "Gateway API CRDs": read_gateway_api_version(GATEWAY_API_KUSTOMIZATION),
        "metrics-server": read_helm_chart_version(METRICS_SERVER_HELMRELEASE, "metrics-server"),
        "Longhorn": config_values["LONGHORN_VERSION"],
        "postfinance/kubelet-csr-approver": read_helm_chart_version(
            KUBELET_CSR_APPROVER_HELMRELEASE, "kubelet-csr-approver"
        ),
    }


def replace_table_versions(text: str, versions: dict[str, str]) -> str:
    lines = text.splitlines()
    seen = {name: 0 for name in versions}
    rendered: list[str] = []
    table_headers = [
        index
        for index, line in enumerate(lines)
        if line == "| Software | Version | What It Does | Why We Need It |"
    ]
    if len(table_headers) != 1:
        raise RenderError(f"README software table header must occur exactly once, found {len(table_headers)}")
    table_index = table_headers[0]
    table_end = table_index
    while table_end + 1 < len(lines) and lines[table_end + 1].startswith("|"):
        table_end += 1

    for index, line in enumerate(lines):
        in_software_table = table_index < index <= table_end
        match = re.match(r"^\| \*\*(.+)\*\* \| ", line) if in_software_table else None
        if not match:
            rendered.append(line)
            continue

        name = match.group(1)
        if name not in versions:
            rendered.append(line)
            continue

        parts = line.split("|")
        if len(parts) != 6:
            raise RenderError(f"README table row for {name!r} does not have four columns")
        parts[2] = f" {versions[name]} "
        rendered.append("|".join(parts))
        seen[name] += 1

    bad_counts = {name: count for name, count in seen.items() if count != 1}
    if bad_counts:
        details = ", ".join(f"{name}={count}" for name, count in bad_counts.items())
        raise RenderError(f"README software table target count must be exactly one per row: {details}")

    return "\n".join(rendered) + "\n"


def replace_once(pattern: str, replacement: str, text: str, description: str) -> str:
    rendered, count = re.subn(pattern, replacement, text, count=0, flags=re.MULTILINE)
    if count != 1:
        raise RenderError(f"README target for {description} must occur exactly once, found {count}")
    return rendered


def replace_prose_versions(text: str, versions: dict[str, str]) -> str:
    rendered = text
    rendered = replace_once(
        r"(- \*\*GitOps:\*\* Flux `)[^`]+(` bootstraps from )",
        rf"\g<1>{versions['Flux']}\2",
        rendered,
        "Current Architecture Flux prose pin",
    )
    rendered = replace_once(
        r"(- \*\*Networking and ingress:\*\* Cilium `)[^`]+(` replaces kube-proxy and is the Gateway API dataplane\. Gateway API `)[^`]+(` CRDs and the `cilium` `GatewayClass` live under )",
        rf"\g<1>{versions['Cilium']}\2{versions['Gateway API CRDs']}\3",
        rendered,
        "Current Architecture Cilium/Gateway API prose pins",
    )
    rendered = replace_once(
        r"(- \*\*Policy:\*\* Kyverno `)[^`]+(` is reconciled by Flux\.)",
        rf"\g<1>{versions['Kyverno']}\2",
        rendered,
        "Current Architecture Kyverno prose pin",
    )
    rendered = replace_once(
        r"(- \*\*Storage:\*\* Longhorn `)[^`]+(` is the default replicated block-storage layer)",
        rf"\g<1>{versions['Longhorn']}\2",
        rendered,
        "Current Architecture Longhorn prose pin",
    )
    rendered = replace_once(
        r"(- `postfinance/kubelet-csr-approver` `)[^`]+(`)",
        rf"\g<1>{versions['postfinance/kubelet-csr-approver']}\2",
        rendered,
        "Step 10 kubelet-csr-approver prose pin",
    )
    rendered = replace_once(
        r"(- `metrics-server` `)[^`]+(`)",
        rf"\g<1>{versions['metrics-server']}\2",
        rendered,
        "Step 10 metrics-server prose pin",
    )
    rendered = replace_once(
        r"(- `kyverno` `)[^`]+(`)",
        rf"\g<1>{versions['Kyverno']}\2",
        rendered,
        "Step 10 kyverno prose pin",
    )
    rendered = replace_once(
        r"(- `longhorn` `)[^`]+(`)",
        rf"\g<1>{versions['Longhorn']}\2",
        rendered,
        "Step 10 longhorn prose pin",
    )
    rendered = replace_once(
        r"(- Gateway API `)[^`]+(` CRDs and the `cilium` `GatewayClass`)",
        rf"\g<1>{versions['Gateway API CRDs']}\2",
        rendered,
        "Step 10 Gateway API prose pin",
    )
    rendered = replace_once(
        r"(The `longhorn` HelmRelease adopts the existing release, pins chart version\n`)[^`]+(`, and inlines values that mirror )",
        rf"\g<1>{versions['Longhorn']}\2",
        rendered,
        "Longhorn HelmRelease paragraph prose pin",
    )
    return rendered


def render_readme(current: str) -> str:
    versions = collect_versions()
    rendered = replace_table_versions(current, versions)
    rendered = replace_prose_versions(rendered, versions)
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if README.md version pins are stale")
    args = parser.parse_args()

    try:
        current = read_text(README)
        rendered = render_readme(current)
    except RenderError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.check:
        if current != rendered:
            print(f"{README} version pins are stale; run scripts/render-readme-versions.py", file=sys.stderr)
            diff = difflib.unified_diff(
                current.splitlines(keepends=True),
                rendered.splitlines(keepends=True),
                fromfile=f"{README} (current)",
                tofile=f"{README} (expected)",
            )
            sys.stderr.writelines(diff)
            return 1
        print(f"{README} version pins match canonical sources")
        return 0

    README.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"wrote {README}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
