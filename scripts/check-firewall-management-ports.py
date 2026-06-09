#!/usr/bin/env python3
"""Fail if the Talos host firewall omits required management-plane ports."""

from __future__ import annotations

import re
import sys
from pathlib import Path


FIREWALL_PATH = Path("cluster/patches/firewall.yaml")

# Required Talos management-plane ports:
# - 50000/apid: talosctl management API.
# - 50001/trustd: node certificate issuance and renewal.
# Omitting either from the default-block firewall silently strands Talos node
# management; omitting trustd caused the 2026 worker certificate outage.
REQUIRED_PORTS = {
    50000: "apid management API",
    50001: "trustd certificate issuance",
}


def without_inline_comment(line: str) -> str:
    return line.split("#", 1)[0].rstrip()


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def split_documents(text: str) -> list[list[str]]:
    documents: list[list[str]] = []
    current: list[str] = []

    for line in text.splitlines():
        if re.fullmatch(r"\s*---\s*", line):
            if current:
                documents.append(current)
                current = []
            continue
        current.append(line)

    if current:
        documents.append(current)

    return documents


def is_network_rule_config(lines: list[str]) -> bool:
    for raw_line in lines:
        line = without_inline_comment(raw_line).strip()
        if re.fullmatch(r"kind:\s*NetworkRuleConfig", line):
            return True
    return False


def parse_port_values(raw_values: str) -> set[int]:
    ports: set[int] = set()
    for raw_value in raw_values.split(","):
        value = raw_value.strip()
        if re.fullmatch(r"[0-9]+", value):
            ports.add(int(value))
    return ports


def collect_port_selector_ports(lines: list[str]) -> set[int]:
    ports: set[int] = set()
    in_port_selector = False
    port_selector_indent = -1
    in_ports = False
    ports_indent = -1

    for raw_line in lines:
        uncommented = without_inline_comment(raw_line)
        if not uncommented.strip():
            continue

        indent = indentation(uncommented)
        line = uncommented.strip()

        if in_port_selector and indent <= port_selector_indent and line != "portSelector:":
            in_port_selector = False
            in_ports = False

        if line == "portSelector:":
            in_port_selector = True
            port_selector_indent = indent
            in_ports = False
            continue

        if not in_port_selector:
            continue

        inline_list = re.fullmatch(r"ports:\s*\[(.*)\]", line)
        if inline_list:
            ports.update(parse_port_values(inline_list.group(1)))
            in_ports = False
            continue

        scalar_port = re.fullmatch(r"ports:\s*([0-9]+)", line)
        if scalar_port:
            ports.add(int(scalar_port.group(1)))
            in_ports = False
            continue

        if line == "ports:":
            in_ports = True
            ports_indent = indent
            continue

        if in_ports:
            list_item = re.fullmatch(r"-\s*([0-9]+)", line)
            if list_item:
                ports.add(int(list_item.group(1)))
                continue

            if indent <= ports_indent:
                in_ports = False

    return ports


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else FIREWALL_PATH
    text = path.read_text(encoding="utf-8")

    found_ports: set[int] = set()
    for document in split_documents(text):
        if is_network_rule_config(document):
            found_ports.update(collect_port_selector_ports(document))

    missing = [port for port in REQUIRED_PORTS if port not in found_ports]
    if missing:
        print(
            "FAIL: missing required Talos management-plane port(s) in "
            f"{path} NetworkRuleConfig.portSelector.ports:"
        )
        for port in missing:
            print(f"  - {port} ({REQUIRED_PORTS[port]})")
        return 1

    required = ", ".join(f"{port} ({reason})" for port, reason in REQUIRED_PORTS.items())
    print(
        "PASS: Talos firewall allows required management-plane ports in "
        f"NetworkRuleConfig.portSelector.ports: {required}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())