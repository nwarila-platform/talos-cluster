#!/usr/bin/env python3
"""Fail if ARC runner GitHub-egress CNP FQDN sets drift apart."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


FQDN_KEYS = ("matchName", "matchPattern")


@dataclass(frozen=True)
class Policy:
    name: str
    relpath: Path


@dataclass(frozen=True, order=True)
class FqdnEntry:
    kind: str
    value: str

    def label(self) -> str:
        return f"{self.kind} {self.value}"


@dataclass(frozen=True)
class PolicyFqdns:
    policy: Policy
    path: Path
    entries: frozenset[FqdnEntry]


class GuardError(Exception):
    """A fail-closed repository state or input error."""


POLICIES = (
    Policy(
        name="arc-runners",
        relpath=Path(
            "clusters/talos-cluster/tenants/arc-runners/"
            "ciliumnetworkpolicy-runner-egress.yaml"
        ),
    ),
    Policy(
        name="arc-runners-repo-sync",
        relpath=Path(
            "clusters/talos-cluster/tenants/arc-runners-repo-sync/"
            "ciliumnetworkpolicy-runner-egress.yaml"
        ),
    ),
)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Check that the two ARC runner-egress CiliumNetworkPolicies expose "
            "the same GitHub infrastructure FQDN set."
        )
    )
    parser.add_argument(
        "repo_root",
        nargs="?",
        type=Path,
        default=Path.cwd(),
        help="repository root to check (default: current directory)",
    )
    return parser.parse_args(argv)


def load_yaml_documents(path: Path) -> list[Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            return list(yaml.safe_load_all(handle))
    except FileNotFoundError as exc:
        raise GuardError(f"{path}: missing file") from exc
    except yaml.YAMLError as exc:
        raise GuardError(f"{path}: YAML parse error: {exc}") from exc
    except OSError as exc:
        raise GuardError(f"{path}: failed to read file: {exc}") from exc


def extract_fqdns_from_document(document: Any, path: Path) -> set[FqdnEntry]:
    if document is None:
        return set()
    if not isinstance(document, dict):
        raise GuardError(f"{path}: YAML document must be a mapping")

    spec = document.get("spec")
    if not isinstance(spec, dict):
        return set()

    egress = spec.get("egress")
    if egress is None:
        return set()
    if not isinstance(egress, list):
        raise GuardError(f"{path}: spec.egress must be a list")

    entries: set[FqdnEntry] = set()
    for egress_index, egress_rule in enumerate(egress):
        if not isinstance(egress_rule, dict):
            raise GuardError(f"{path}: spec.egress[{egress_index}] must be a mapping")

        fqdn_selectors = egress_rule.get("toFQDNs")
        if fqdn_selectors is None:
            continue
        if not isinstance(fqdn_selectors, list):
            raise GuardError(
                f"{path}: spec.egress[{egress_index}].toFQDNs must be a list"
            )

        for fqdn_index, fqdn_selector in enumerate(fqdn_selectors):
            if not isinstance(fqdn_selector, dict):
                raise GuardError(
                    f"{path}: spec.egress[{egress_index}].toFQDNs[{fqdn_index}] "
                    "must be a mapping"
                )

            found_key = False
            for key in FQDN_KEYS:
                if key not in fqdn_selector:
                    continue
                found_key = True
                value = fqdn_selector[key]
                if not isinstance(value, str) or not value:
                    raise GuardError(
                        f"{path}: spec.egress[{egress_index}].toFQDNs[{fqdn_index}]."
                        f"{key} must be a non-empty string"
                    )
                entries.add(FqdnEntry(kind=key, value=value))

            if not found_key:
                raise GuardError(
                    f"{path}: spec.egress[{egress_index}].toFQDNs[{fqdn_index}] "
                    "must define matchName or matchPattern"
                )

    return entries


def load_policy_fqdns(repo_root: Path, policy: Policy) -> PolicyFqdns:
    path = repo_root / policy.relpath
    entries: set[FqdnEntry] = set()
    for document in load_yaml_documents(path):
        entries.update(extract_fqdns_from_document(document, path))

    if not entries:
        raise GuardError(f"{policy.name}: zero toFQDNs entries found in {path}")

    return PolicyFqdns(policy=policy, path=path, entries=frozenset(entries))


def print_entry_list(title: str, entries: set[FqdnEntry]) -> None:
    print(title, file=sys.stderr)
    if not entries:
        print("  - none", file=sys.stderr)
        return
    for entry in sorted(entries):
        print(f"  - {entry.label()}", file=sys.stderr)


def compare(left: PolicyFqdns, right: PolicyFqdns) -> int:
    if left.entries == right.entries:
        print("Runner GitHub-egress CNP parity OK.")
        print(f"Shared GitHub FQDN set ({len(left.entries)} entries):")
        for entry in sorted(left.entries):
            print(f"  - {entry.label()}")
        return 0

    left_only = set(left.entries - right.entries)
    right_only = set(right.entries - left.entries)
    print("Runner GitHub-egress CNP parity FAILED.", file=sys.stderr)
    print(
        f"Compared {left.policy.name} ({left.policy.relpath}) against "
        f"{right.policy.name} ({right.policy.relpath}).",
        file=sys.stderr,
    )
    print_entry_list(
        f"Present in {left.policy.name}, missing from {right.policy.name}:",
        left_only,
    )
    print_entry_list(
        f"Present in {right.policy.name}, missing from {left.policy.name}:",
        right_only,
    )
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo_root = args.repo_root.resolve()

    try:
        left = load_policy_fqdns(repo_root, POLICIES[0])
        right = load_policy_fqdns(repo_root, POLICIES[1])
    except GuardError as exc:
        print(f"Runner GitHub-egress CNP parity FAILED: {exc}", file=sys.stderr)
        return 1

    return compare(left, right)


if __name__ == "__main__":
    sys.exit(main())
