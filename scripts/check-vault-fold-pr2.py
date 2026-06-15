#!/usr/bin/env python3
"""Check Vault fold PR2 renders without semantic drift from deploy-vault pin."""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("PyYAML is required: install python3-yaml or PyYAML")


EXPECTED_CONFIGMAP_NAME = "vault-config-62842h8b69"
FORCE_ENABLED = "kustomize.toolkit.fluxcd.io/force: Enabled"
PRUNE_ANNOTATION = "kustomize.toolkit.fluxcd.io/prune"
STATEFULSET_FIELDS = ("selector", "serviceName", "volumeClaimTemplates", "template")
PRUNE_PATCH_TARGETS = {
    ("StatefulSet", "vault"),
    ("Service", "vault"),
    ("Service", "vault-internal"),
    ("ConfigMap", "vault-config"),
}


def load_yaml_documents(path: Path) -> tuple[str, list[dict]]:
    raw = path.read_text(encoding="utf-8")
    docs = [doc for doc in yaml.safe_load_all(raw) if doc]
    return raw, docs


def resource_id(doc: dict) -> tuple[str, str, str]:
    metadata = doc.get("metadata") or {}
    return (doc.get("kind", ""), metadata.get("namespace", ""), metadata.get("name", ""))


def find_resource(docs: list[dict], kind: str, name: str) -> dict:
    matches = [doc for doc in docs if resource_id(doc)[0] == kind and resource_id(doc)[2] == name]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one {kind}/{name}, found {len(matches)}")
    return matches[0]


def find_vault_configmap(docs: list[dict]) -> dict:
    matches = [
        doc
        for doc in docs
        if resource_id(doc)[0] == "ConfigMap" and resource_id(doc)[2].startswith("vault-config-")
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one generated vault-config ConfigMap, found {len(matches)}")
    return matches[0]


def normalized_yaml(value: object) -> list[str]:
    return yaml.safe_dump(value, sort_keys=True, allow_unicode=False).splitlines(keepends=True)


def assert_equal(label: str, old: object, new: object) -> None:
    if old == new:
        print(f"OK {label} identical")
        return
    diff = "".join(difflib.unified_diff(normalized_yaml(old), normalized_yaml(new), "old", "new"))
    raise AssertionError(f"{label} drifted\n{diff}")


def assert_statefulset_fields(old_docs: list[dict], new_docs: list[dict]) -> None:
    old_spec = find_resource(old_docs, "StatefulSet", "vault").get("spec") or {}
    new_spec = find_resource(new_docs, "StatefulSet", "vault").get("spec") or {}
    for field in STATEFULSET_FIELDS:
        assert_equal(f"StatefulSet .spec.{field}", old_spec.get(field), new_spec.get(field))


def assert_configmap(old_docs: list[dict], new_docs: list[dict]) -> None:
    old_cm = find_vault_configmap(old_docs)
    new_cm = find_vault_configmap(new_docs)
    old_name = resource_id(old_cm)[2]
    new_name = resource_id(new_cm)[2]
    if old_name != new_name:
        raise AssertionError(f"ConfigMap name drifted: old={old_name} new={new_name}")
    if new_name != EXPECTED_CONFIGMAP_NAME:
        raise AssertionError(f"ConfigMap name is {new_name}, expected {EXPECTED_CONFIGMAP_NAME}")
    print(f"OK ConfigMap name identical: {new_name}")

    old_hcl = ((old_cm.get("data") or {}).get("vault.hcl") or "").encode("utf-8")
    new_hcl = ((new_cm.get("data") or {}).get("vault.hcl") or "").encode("utf-8")
    if old_hcl != new_hcl:
        diff = "".join(
            difflib.unified_diff(
                old_hcl.decode("utf-8", "replace").splitlines(keepends=True),
                new_hcl.decode("utf-8", "replace").splitlines(keepends=True),
                "old vault.hcl",
                "new vault.hcl",
            )
        )
        raise AssertionError(f"vault.hcl bytes drifted\n{diff}")
    print("OK vault.hcl byte-identical in rendered ConfigMap data")


def assert_no_force_enabled(*raw_documents: str) -> None:
    for raw in raw_documents:
        if FORCE_ENABLED in raw:
            raise AssertionError(f"found forbidden force annotation: {FORCE_ENABLED}")
    print("OK no kustomize.toolkit.fluxcd.io/force: Enabled annotation found")


def assert_flux_kustomization(flux_path: Path) -> None:
    raw, docs = load_yaml_documents(flux_path)
    assert_no_force_enabled(raw)
    flux = find_resource(docs, "Kustomization", "vault")
    spec = flux.get("spec") or {}
    expected_scalars = {
        "path": "./clusters/talos-cluster/apps/vault",
        "targetNamespace": "deploy-vault",
        "force": False,
    }
    for field, expected in expected_scalars.items():
        actual = spec.get(field)
        if actual != expected:
            raise AssertionError(f"Flux Kustomization spec.{field}={actual!r}, expected {expected!r}")
    print("OK Flux Kustomization path, targetNamespace, and force:false")

    seen_targets: set[tuple[str, str]] = set()
    for item in spec.get("patches") or []:
        target = item.get("target") or {}
        target_id = (target.get("kind", ""), target.get("name", ""))
        if target_id not in PRUNE_PATCH_TARGETS:
            continue
        patch = yaml.safe_load(item.get("patch") or "") or {}
        annotations = ((patch.get("metadata") or {}).get("annotations") or {})
        if annotations.get(PRUNE_ANNOTATION) == "disabled":
            seen_targets.add(target_id)

    missing = sorted(PRUNE_PATCH_TARGETS - seen_targets)
    if missing:
        raise AssertionError(f"missing prune-disabled Flux patches: {missing}")
    print("OK prune-disabled patches present for StatefulSet/vault, Services, and vault-config generator")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", required=True, type=Path, help="Rendered deploy-vault@bf7f0e0 overlay")
    parser.add_argument("--new", required=True, type=Path, help="Rendered relocated apps/vault overlay")
    parser.add_argument("--flux", required=True, type=Path, help="New Flux Kustomization manifest")
    args = parser.parse_args()

    old_raw, old_docs = load_yaml_documents(args.old)
    new_raw, new_docs = load_yaml_documents(args.new)
    assert_no_force_enabled(old_raw, new_raw)
    assert_statefulset_fields(old_docs, new_docs)
    assert_configmap(old_docs, new_docs)
    assert_flux_kustomization(args.flux)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        raise SystemExit(1)
