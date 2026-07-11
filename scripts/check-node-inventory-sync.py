#!/usr/bin/env python3
"""Fail if the human node inventory drifts from cluster/config.env."""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CONFIG_ENV = Path("cluster/config.env")
DEFAULT_INVENTORY = Path("systems")

REQUIRED_CONFIG_KEYS = ("CP_NODES", "WORKER_NODES", "BOOTSTRAP_NODE", "CLUSTER_VIP")
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
VALID_BOOTSTRAP_VALUES = {"yes", "no"}

ASSIGNMENT_RE = re.compile(
    r'^\s*(?P<key>CP_NODES|WORKER_NODES|BOOTSTRAP_NODE|CLUSTER_VIP)="'
    r'(?P<value>[^"]*)"\s*(?:#.*)?$'
)
NODE_TOKEN_RE = re.compile(
    r"^(?P<hostname>[A-Za-z0-9][A-Za-z0-9-]*):(?P<ip>\d{1,3}(?:\.\d{1,3}){3})$"
)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class ParseError(ValueError):
    """Raised when an inventory source is missing or malformed."""


@dataclass(frozen=True)
class ConfigInventory:
    vip: str
    cp_nodes: dict[str, str]
    worker_nodes: dict[str, str]
    bootstrap_name: str
    bootstrap_ip: str

    def all_nodes(self) -> dict[str, str]:
        return {**self.cp_nodes, **self.worker_nodes}


@dataclass(frozen=True)
class SystemsRow:
    hostname: str
    asset_name: str
    role: str
    ip: str
    install_disk: str
    nic: str
    bootstrap: str


@dataclass(frozen=True)
class SystemsInventory:
    vip: str
    rows: dict[str, SystemsRow]

    def role_names(self, role: str) -> set[str]:
        return {name for name, row in self.rows.items() if row.role == role}

    def bootstrap_row(self) -> SystemsRow:
        matches = [row for row in self.rows.values() if row.bootstrap == "yes"]
        if len(matches) != 1:
            raise ParseError("systems must contain exactly one BOOTSTRAP=yes row")
        return matches[0]


def validate_ip(ip: str, context: str) -> str:
    if not IP_RE.fullmatch(ip):
        raise ParseError(f"{context}: invalid IP address {ip!r}")
    invalid_octets = [octet for octet in ip.split(".") if int(octet) > 255]
    if invalid_octets:
        raise ParseError(f"{context}: invalid IP address {ip!r}")
    return ip


def duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    repeated: set[str] = set()
    for value in values:
        if value in seen:
            repeated.add(value)
        seen.add(value)
    return sorted(repeated)


def parse_node_token(token: str, context: str) -> tuple[str, str]:
    match = NODE_TOKEN_RE.fullmatch(token)
    if not match:
        raise ParseError(f"{context}: token {token!r} must be hostname:ip")
    hostname = match.group("hostname")
    ip = validate_ip(match.group("ip"), context)
    return hostname, ip


def parse_node_list(value: str, key: str) -> dict[str, str]:
    nodes: dict[str, str] = {}
    names: list[str] = []
    ips: list[str] = []

    for token in value.split():
        hostname, ip = parse_node_token(token, key)
        names.append(hostname)
        ips.append(ip)
        nodes[hostname] = ip

    repeated_names = duplicates(names)
    if repeated_names:
        raise ParseError(f"{key}: duplicate hostnames: {', '.join(repeated_names)}")

    repeated_ips = duplicates(ips)
    if repeated_ips:
        raise ParseError(f"{key}: duplicate IPs: {', '.join(repeated_ips)}")

    return nodes


def parse_config_env(path: Path) -> ConfigInventory:
    assignments: dict[str, list[tuple[int, str]]] = {
        key: [] for key in REQUIRED_CONFIG_KEYS
    }

    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            match = ASSIGNMENT_RE.fullmatch(line.rstrip("\n"))
            if match:
                assignments[match.group("key")].append((lineno, match.group("value")))

    for key, matches in assignments.items():
        if len(matches) != 1:
            raise ParseError(
                f"{path}: expected exactly one {key}= assignment, found {len(matches)}"
            )

    cp_nodes = parse_node_list(assignments["CP_NODES"][0][1], "CP_NODES")
    worker_nodes = parse_node_list(assignments["WORKER_NODES"][0][1], "WORKER_NODES")

    all_names = list(cp_nodes) + list(worker_nodes)
    repeated_names = duplicates(all_names)
    if repeated_names:
        raise ParseError(
            "cluster/config.env: duplicate hostnames across CP_NODES and "
            f"WORKER_NODES: {', '.join(repeated_names)}"
        )

    all_ips = list(cp_nodes.values()) + list(worker_nodes.values())
    repeated_ips = duplicates(all_ips)
    if repeated_ips:
        raise ParseError(
            "cluster/config.env: duplicate IPs across CP_NODES and "
            f"WORKER_NODES: {', '.join(repeated_ips)}"
        )

    bootstrap_name, bootstrap_ip = parse_node_token(
        assignments["BOOTSTRAP_NODE"][0][1], "BOOTSTRAP_NODE"
    )
    if bootstrap_name not in cp_nodes:
        raise ParseError(
            "BOOTSTRAP_NODE hostname must be listed in CP_NODES: "
            f"{bootstrap_name!r}"
        )

    vip = validate_ip(assignments["CLUSTER_VIP"][0][1], "CLUSTER_VIP")
    return ConfigInventory(
        vip=vip,
        cp_nodes=cp_nodes,
        worker_nodes=worker_nodes,
        bootstrap_name=bootstrap_name,
        bootstrap_ip=bootstrap_ip,
    )


def parse_systems(path: Path) -> SystemsInventory:
    vip_values: list[str] = []
    header_count = 0
    seen_header = False
    rows: dict[str, SystemsRow] = {}
    asset_names: list[str] = []
    ips: list[str] = []
    bootstrap_yes = 0

    with path.open(encoding="utf-8") as handle:
        for lineno, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("Hostname convention:"):
                continue

            fields = line.split()
            if fields == SYSTEMS_HEADER:
                header_count += 1
                seen_header = True
                continue

            if fields[0] == "VIP":
                if len(fields) != 2:
                    raise ParseError(f"{path}:{lineno}: VIP line must be 'VIP <ip>'")
                vip_values.append(validate_ip(fields[1], f"{path}:{lineno}"))
                continue

            if not seen_header:
                raise ParseError(f"{path}:{lineno}: node row appears before header")

            if len(fields) != len(SYSTEMS_HEADER):
                raise ParseError(
                    f"{path}:{lineno}: node rows must have "
                    f"{len(SYSTEMS_HEADER)} fields"
                )

            hostname, asset_name, role, ip, install_disk, nic, bootstrap = fields
            if role not in VALID_ROLES:
                raise ParseError(
                    f"{path}:{lineno}: ROLE must be one of "
                    f"{', '.join(sorted(VALID_ROLES))}"
                )
            if bootstrap not in VALID_BOOTSTRAP_VALUES:
                raise ParseError(
                    f"{path}:{lineno}: BOOTSTRAP must be one of "
                    f"{', '.join(sorted(VALID_BOOTSTRAP_VALUES))}"
                )
            if hostname in rows:
                raise ParseError(f"{path}:{lineno}: duplicate hostname {hostname!r}")

            row = SystemsRow(
                hostname=hostname,
                asset_name=asset_name,
                role=role,
                ip=validate_ip(ip, f"{path}:{lineno}"),
                install_disk=install_disk,
                nic=nic,
                bootstrap=bootstrap,
            )
            rows[hostname] = row
            asset_names.append(asset_name)
            ips.append(row.ip)
            if bootstrap == "yes":
                bootstrap_yes += 1

    if len(vip_values) != 1:
        raise ParseError(
            f"{path}: expected exactly one VIP line, found {len(vip_values)}"
        )
    if header_count != 1:
        raise ParseError(
            f"{path}: expected exactly one systems header row, found {header_count}"
        )

    repeated_assets = duplicates(asset_names)
    if repeated_assets:
        raise ParseError(f"{path}: duplicate asset names: {', '.join(repeated_assets)}")

    repeated_ips = duplicates(ips)
    if repeated_ips:
        raise ParseError(f"{path}: duplicate node IPs: {', '.join(repeated_ips)}")

    if bootstrap_yes != 1:
        raise ParseError(
            f"{path}: expected exactly one BOOTSTRAP=yes row, found {bootstrap_yes}"
        )

    return SystemsInventory(vip=vip_values[0], rows=rows)


def format_set_drift(label: str, expected: set[str], actual: set[str]) -> str:
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    parts: list[str] = []
    if missing:
        parts.append(f"missing from systems: {', '.join(missing)}")
    if extra:
        parts.append(f"extra in systems: {', '.join(extra)}")
    return f"{label}: " + "; ".join(parts)


def drift_messages(config: ConfigInventory, systems: SystemsInventory) -> list[str]:
    messages: list[str] = []
    config_nodes = config.all_nodes()
    systems_nodes = systems.rows

    config_names = set(config_nodes)
    systems_names = set(systems_nodes)
    if config_names != systems_names:
        messages.append(
            format_set_drift("node-name set drift", config_names, systems_names)
        )

    config_cp_names = set(config.cp_nodes)
    systems_cp_names = systems.role_names("control-plane")
    if config_cp_names != systems_cp_names:
        messages.append(
            format_set_drift(
                "control-plane role partition drift",
                config_cp_names,
                systems_cp_names,
            )
        )

    config_worker_names = set(config.worker_nodes)
    systems_worker_names = systems.role_names("worker")
    if config_worker_names != systems_worker_names:
        messages.append(
            format_set_drift(
                "worker role partition drift",
                config_worker_names,
                systems_worker_names,
            )
        )

    for hostname in sorted(config_names & systems_names):
        config_ip = config_nodes[hostname]
        systems_ip = systems_nodes[hostname].ip
        if config_ip != systems_ip:
            messages.append(
                f"IP drift for {hostname}: cluster/config.env={config_ip}, "
                f"systems={systems_ip}"
            )

    if config.vip != systems.vip:
        messages.append(
            f"VIP drift: cluster/config.env={config.vip}, systems={systems.vip}"
        )

    systems_bootstrap = systems.bootstrap_row()
    config_bootstrap = (config.bootstrap_name, config.bootstrap_ip)
    systems_bootstrap_pair = (systems_bootstrap.hostname, systems_bootstrap.ip)
    if config_bootstrap != systems_bootstrap_pair:
        messages.append(
            "bootstrap drift: "
            f"cluster/config.env={config.bootstrap_name}:{config.bootstrap_ip}, "
            f"systems={systems_bootstrap.hostname}:{systems_bootstrap.ip}"
        )

    return messages


def config_compare_lines(config: ConfigInventory) -> list[str]:
    lines = [f"VIP {config.vip}\n"]
    for hostname in sorted(config.cp_nodes):
        lines.append(f"CONTROL_PLANE {hostname} {config.cp_nodes[hostname]}\n")
    for hostname in sorted(config.worker_nodes):
        lines.append(f"WORKER {hostname} {config.worker_nodes[hostname]}\n")
    lines.append(f"BOOTSTRAP {config.bootstrap_name} {config.bootstrap_ip}\n")
    return lines


def systems_compare_lines(systems: SystemsInventory) -> list[str]:
    lines = [f"VIP {systems.vip}\n"]
    control_plane_rows = [
        row for row in systems.rows.values() if row.role == "control-plane"
    ]
    worker_rows = [row for row in systems.rows.values() if row.role == "worker"]
    for row in sorted(control_plane_rows, key=lambda item: item.hostname):
        lines.append(f"CONTROL_PLANE {row.hostname} {row.ip}\n")
    for row in sorted(worker_rows, key=lambda item: item.hostname):
        lines.append(f"WORKER {row.hostname} {row.ip}\n")
    bootstrap = systems.bootstrap_row()
    lines.append(f"BOOTSTRAP {bootstrap.hostname} {bootstrap.ip}\n")
    return lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare cluster/config.env machine node inventory with the root "
            "systems human inventory table."
        )
    )
    parser.add_argument(
        "--config-env",
        type=Path,
        default=DEFAULT_CONFIG_ENV,
        help=f"machine inventory file (default: {DEFAULT_CONFIG_ENV})",
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY,
        help=f"human inventory file (default: {DEFAULT_INVENTORY})",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        config = parse_config_env(args.config_env)
        systems = parse_systems(args.inventory)
    except (OSError, ParseError) as exc:
        print(f"ERROR: failed to load node inventory inputs: {exc}", file=sys.stderr)
        return 2

    messages = drift_messages(config, systems)
    config_lines = config_compare_lines(config)
    systems_lines = systems_compare_lines(systems)
    if not messages and config_lines == systems_lines:
        print(f"Node inventory matches: {args.config_env} == {args.inventory}")
        return 0

    print(
        "ERROR: systems node inventory drifts from cluster/config.env:",
        file=sys.stderr,
    )
    for message in messages:
        print(f"  - {message}", file=sys.stderr)

    diff = difflib.unified_diff(
        config_lines,
        systems_lines,
        fromfile=f"{args.config_env}:machine-inventory",
        tofile=f"{args.inventory}:human-inventory",
    )
    for line in diff:
        print(line, end="", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
