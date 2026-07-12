#!/usr/bin/env python3
"""Fail if per-node Talos patches drift from systems + cluster/config.env.

For each node row in the root systems inventory, this guard checks the matching
cluster/patches/<hostname>.yaml install disk, static address, default gateway,
and role-appropriate control-plane VIP. The NIC is deliberately out of scope:
systems records a NIC name such as eno1, while these patches pin interfaces by
deviceSelector.busPath, and this repository has no source-of-truth mapping
between the human NIC name and the PCI bus path.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


DEFAULT_CONFIG_ENV = Path("cluster/config.env")
DEFAULT_INVENTORY = Path("systems")
DEFAULT_PATCH_DIR = Path("cluster/patches")

SYSTEMS_HEADER = [
    "HOSTNAME",
    "ASSET_NAME",
    "ROLE",
    "IP",
    "INSTALL_DISK",
    "NIC",
    "BOOTSTRAP",
]
VALID_ROLES = {"control-plane", "worker"}


@dataclass(frozen=True)
class ClusterNetwork:
    gateway: str
    netmask: str
    vip: str


@dataclass(frozen=True)
class SystemsNode:
    hostname: str
    role: str
    ip: str
    install_disk: str


@dataclass(frozen=True)
class Violation:
    node: str
    field: str
    expected: str
    actual: str

    def __str__(self) -> str:
        return (
            f"{self.node}: {self.field}: expected {self.expected}, "
            f"got {self.actual}"
        )


def load_config_value(path: Path, name: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)}=(?P<quote>[\"']?)(?P<value>.*?)(?P=quote)\s*$")
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            match = pattern.match(line.strip())
            if match:
                return match.group("value")
    raise ValueError(f"{path} must define {name}")


def load_cluster_network(path: Path) -> ClusterNetwork:
    return ClusterNetwork(
        gateway=load_config_value(path, "CLUSTER_GATEWAY"),
        netmask=load_config_value(path, "CLUSTER_NETMASK"),
        vip=load_config_value(path, "CLUSTER_VIP"),
    )


def parse_systems(path: Path) -> dict[str, SystemsNode]:
    seen_header = False
    rows: dict[str, SystemsNode] = {}

    with path.open(encoding="utf-8") as handle:
        for lineno, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("Hostname convention:"):
                continue

            fields = line.split()
            if fields == SYSTEMS_HEADER:
                seen_header = True
                continue

            if fields[0] == "VIP":
                continue

            if not seen_header:
                raise ValueError(f"{path}:{lineno}: node row appears before header")

            if len(fields) != len(SYSTEMS_HEADER):
                raise ValueError(
                    f"{path}:{lineno}: node rows must have "
                    f"{len(SYSTEMS_HEADER)} fields"
                )

            hostname, _asset_name, role, ip, install_disk, _nic, _bootstrap = fields
            if role not in VALID_ROLES:
                raise ValueError(
                    f"{path}:{lineno}: ROLE must be one of "
                    f"{', '.join(sorted(VALID_ROLES))}"
                )
            if hostname in rows:
                raise ValueError(f"{path}:{lineno}: duplicate hostname {hostname!r}")

            rows[hostname] = SystemsNode(
                hostname=hostname,
                role=role,
                ip=ip,
                install_disk=install_disk,
            )

    if not seen_header:
        raise ValueError(f"{path}: missing systems header row")
    if not rows:
        raise ValueError(f"{path}: no node rows found")
    return rows


def load_patch_mapping(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must parse to a YAML mapping")
    return data


def nested_value(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    value: Any = data
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def sorted_set(values: set[str]) -> str:
    return "[" + ", ".join(repr(value) for value in sorted(values)) + "]"


def collect_network_values(patch: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    addresses: set[str] = set()
    gateways: set[str] = set()
    vips: set[str] = set()

    interfaces = nested_value(patch, ("machine", "network", "interfaces"))
    if not isinstance(interfaces, list):
        return addresses, gateways, vips

    for interface in interfaces:
        if not isinstance(interface, dict):
            continue

        interface_addresses = interface.get("addresses")
        if isinstance(interface_addresses, list):
            addresses.update(str(address) for address in interface_addresses)

        routes = interface.get("routes")
        if isinstance(routes, list):
            for route in routes:
                if isinstance(route, dict) and "gateway" in route:
                    gateways.add(str(route["gateway"]))

        vip = interface.get("vip")
        if isinstance(vip, dict) and "ip" in vip:
            vips.add(str(vip["ip"]))

    return addresses, gateways, vips


def check_node(
    node: SystemsNode,
    network: ClusterNetwork,
    patch_dir: Path,
) -> list[Violation]:
    patch_path = patch_dir / f"{node.hostname}.yaml"
    violations: list[Violation] = []

    try:
        patch = load_patch_mapping(patch_path)
    except FileNotFoundError:
        return [
            Violation(
                node.hostname,
                str(patch_path),
                "YAML mapping",
                "missing file",
            )
        ]
    except yaml.YAMLError as exc:
        return [
            Violation(
                node.hostname,
                str(patch_path),
                "valid YAML mapping",
                f"YAML error: {exc}",
            )
        ]
    except (OSError, ValueError) as exc:
        return [
            Violation(
                node.hostname,
                str(patch_path),
                "YAML mapping",
                str(exc),
            )
        ]

    install_disk = nested_value(patch, ("machine", "install", "disk"))
    if install_disk != node.install_disk:
        violations.append(
            Violation(
                node.hostname,
                "machine.install.disk",
                repr(node.install_disk),
                repr(install_disk),
            )
        )

    addresses, gateways, vips = collect_network_values(patch)

    expected_address = f"{node.ip}/{network.netmask}"
    if expected_address not in addresses:
        violations.append(
            Violation(
                node.hostname,
                "machine.network.interfaces[*].addresses",
                repr(expected_address),
                sorted_set(addresses),
            )
        )

    if network.gateway not in gateways:
        violations.append(
            Violation(
                node.hostname,
                "machine.network.interfaces[*].routes[*].gateway",
                repr(network.gateway),
                sorted_set(gateways),
            )
        )

    if node.role == "control-plane":
        if network.vip not in vips:
            violations.append(
                Violation(
                    node.hostname,
                    "machine.network.interfaces[*].vip.ip",
                    repr(network.vip),
                    sorted_set(vips),
                )
            )
    elif vips:
        violations.append(
            Violation(
                node.hostname,
                "machine.network.interfaces[*].vip.ip",
                "no vip",
                sorted_set(vips),
            )
        )

    return violations


def check_consistency(
    config_env: Path,
    inventory: Path,
    patch_dir: Path,
) -> tuple[int, list[Violation]]:
    network = load_cluster_network(config_env)
    nodes = parse_systems(inventory)

    violations: list[Violation] = []
    for hostname in sorted(nodes):
        violations.extend(check_node(nodes[hostname], network, patch_dir))

    return len(nodes), violations


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare per-node Talos patches with the systems inventory and "
            "cluster/config.env network settings."
        )
    )
    parser.add_argument(
        "--config-env",
        type=Path,
        default=DEFAULT_CONFIG_ENV,
        help=f"cluster config.env file (default: {DEFAULT_CONFIG_ENV})",
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY,
        help=f"human inventory file (default: {DEFAULT_INVENTORY})",
    )
    parser.add_argument(
        "--patch-dir",
        type=Path,
        default=DEFAULT_PATCH_DIR,
        help=f"Talos node patch directory (default: {DEFAULT_PATCH_DIR})",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        node_count, violations = check_consistency(
            args.config_env,
            args.inventory,
            args.patch_dir,
        )
    except (OSError, ValueError) as exc:
        print(f"ERROR: failed to load node patch consistency inputs: {exc}", file=sys.stderr)
        return 2

    if violations:
        print("ERROR: per-node Talos patch consistency violations:", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1

    print(
        "PASS: "
        f"{node_count} node patches verified against {args.inventory}, "
        f"{args.config_env}, and {args.patch_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
