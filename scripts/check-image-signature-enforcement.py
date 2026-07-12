#!/usr/bin/env python3
"""Fail if first-party GHCR images are not signature-Enforced by Kyverno.

This guard scans raw YAML files under the configured roots, including standalone
trees such as apps/vault/restore-drill/ that are intentionally not rendered by
Flux validation.

Deliberate scope:
- Extract inline ``image:`` string scalars.
- Extract kustomize ``images:`` list entries carrying ``name`` and/or
  ``newName``.
- Normalize extracted image refs to the bare repository name, with tag and
  digest stripped.
- Ignore extracted values containing ``*`` because those are match patterns,
  not concrete deployed images.
- Discover Kyverno Policy/ClusterPolicy ``verifyImages`` blocks and require
  first-party GHCR orgs plus deployed first-party image refs to be covered by
  effective ``failureAction: Enforce``.

Deliberately out of scope:
- Verifying image digests or tags. That is check-image-digest-sync.py's job.
- HelmRelease-injected upstream images. This guard only covers the declared
  first-party GHCR orgs.
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    import yaml
    from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


DEFAULT_ROOTS = (Path("clusters"), Path("addons"))
FIRST_PARTY_ORG_GLOBS = (
    "ghcr.io/nwarila-platform/*",
    "ghcr.io/nwarila/*",
    "ghcr.io/the-hero-wars-guys/*",
)
FIRST_PARTY_IMAGE_PREFIXES = tuple(
    org_glob[:-1] for org_glob in FIRST_PARTY_ORG_GLOBS
)
YAML_SUFFIXES = {".yaml", ".yml"}
KYVERNO_POLICY_KINDS = {"ClusterPolicy", "Policy"}


@dataclass(frozen=True)
class ImageRef:
    name: str
    path: Path
    line: int
    value: str
    source: str


@dataclass(frozen=True)
class VerifyImagesBlock:
    image_references: tuple[str, ...]
    skip_image_references: tuple[str, ...]
    action: str
    path: Path
    line: int


@dataclass(frozen=True)
class GuardResult:
    paths: list[Path]
    refs: list[ImageRef]
    first_party_refs: list[ImageRef]
    verify_images_blocks: list[VerifyImagesBlock]
    enforce_blocks: list[VerifyImagesBlock]
    findings: list[str]


class GuardUsageError(Exception):
    """A tooling or input error that should exit with code 2."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan raw YAML for first-party GHCR image refs that are not covered "
            "by Kyverno verifyImages rules with effective failureAction: Enforce."
        )
    )
    parser.add_argument(
        "roots",
        nargs="*",
        type=Path,
        help="YAML roots to scan (default: clusters addons)",
    )
    return parser.parse_args()


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def iter_yaml_paths(roots: Iterable[Path]) -> list[Path]:
    paths: set[Path] = set()
    for root in roots:
        if not root.exists():
            raise GuardUsageError(f"{root} does not exist")
        if root.is_file():
            if root.suffix in YAML_SUFFIXES:
                paths.add(root)
            continue
        if not root.is_dir():
            raise GuardUsageError(f"{root} is neither a file nor a directory")
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in YAML_SUFFIXES:
                paths.add(path)
    return sorted(paths)


def scalar_value(node: Node) -> str | None:
    if isinstance(node, ScalarNode):
        return node.value
    return None


def node_line(node: Node) -> int:
    return node.start_mark.line + 1


def split_tag_ref(value: str) -> tuple[str, str | None]:
    slash_index = value.rfind("/")
    colon_index = value.rfind(":")
    if colon_index > slash_index and colon_index < len(value) - 1:
        return value[:colon_index], value[colon_index + 1 :]
    return value, None


def normalize_image_name(value: str) -> str:
    name = value.split("@", 1)[0]
    name, _tag = split_tag_ref(name)
    return name


def parse_inline_image(value: str, path: Path, line: int) -> ImageRef | None:
    value = value.strip()
    if not value or "*" in value:
        return None

    name = normalize_image_name(value)
    if not name:
        return None

    return ImageRef(
        name=name,
        path=path,
        line=line,
        value=value,
        source="inline image",
    )


def mapping_fields(node: MappingNode) -> dict[str, tuple[Node, int]]:
    fields: dict[str, tuple[Node, int]] = {}
    for key_node, value_node in node.value:
        key = scalar_value(key_node)
        if key is not None:
            fields[key] = (value_node, node_line(value_node))
    return fields


def parse_kustomize_images(sequence: SequenceNode, path: Path) -> list[ImageRef]:
    refs: list[ImageRef] = []
    for item in sequence.value:
        if not isinstance(item, MappingNode):
            continue

        fields = mapping_fields(item)
        name_pair = fields.get("newName") or fields.get("name")
        if name_pair is None:
            continue
        name_node, name_line = name_pair
        raw_name = scalar_value(name_node)
        if raw_name is None:
            continue

        raw_name = raw_name.strip()
        if not raw_name or "*" in raw_name:
            continue

        name = normalize_image_name(raw_name)
        if not name:
            continue

        refs.append(
            ImageRef(
                name=name,
                path=path,
                line=name_line,
                value=raw_name,
                source="kustomize images",
            )
        )
    return refs


def extract_refs_from_node(node: Node, path: Path) -> list[ImageRef]:
    refs: list[ImageRef] = []
    seen: set[int] = set()

    def walk(current: Node) -> None:
        node_id = id(current)
        if node_id in seen:
            return
        seen.add(node_id)

        if isinstance(current, MappingNode):
            for key_node, value_node in current.value:
                key = scalar_value(key_node)
                if key == "image" and isinstance(value_node, ScalarNode):
                    ref = parse_inline_image(value_node.value, path, node_line(value_node))
                    if ref is not None:
                        refs.append(ref)
                elif key == "images" and isinstance(value_node, SequenceNode):
                    refs.extend(parse_kustomize_images(value_node, path))
                walk(value_node)
        elif isinstance(current, SequenceNode):
            for item in current.value:
                walk(item)

    walk(node)
    return refs


def string_list(node: Node | None) -> tuple[str, ...]:
    if node is None:
        return ()
    if isinstance(node, ScalarNode):
        value = node.value.strip()
        return (value,) if value else ()
    if not isinstance(node, SequenceNode):
        return ()

    values: list[str] = []
    for item in node.value:
        value = scalar_value(item)
        if value is not None:
            value = value.strip()
            if value:
                values.append(value)
    return tuple(values)


def scalar_field(
    fields: dict[str, tuple[Node, int]], key: str, default: str | None = None
) -> str | None:
    pair = fields.get(key)
    if pair is None:
        return default
    value = scalar_value(pair[0])
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def extract_verify_images_blocks_from_policy(
    document: Node, path: Path
) -> list[VerifyImagesBlock]:
    if not isinstance(document, MappingNode):
        return []

    document_fields = mapping_fields(document)
    api_version = scalar_field(document_fields, "apiVersion")
    kind = scalar_field(document_fields, "kind")
    if (
        api_version is None
        or not api_version.startswith("kyverno.io/")
        or kind not in KYVERNO_POLICY_KINDS
    ):
        return []

    spec_pair = document_fields.get("spec")
    if spec_pair is None or not isinstance(spec_pair[0], MappingNode):
        return []

    spec_fields = mapping_fields(spec_pair[0])
    policy_action = scalar_field(spec_fields, "validationFailureAction", "Audit")
    rules_pair = spec_fields.get("rules")
    if rules_pair is None or not isinstance(rules_pair[0], SequenceNode):
        return []

    blocks: list[VerifyImagesBlock] = []
    for rule in rules_pair[0].value:
        if not isinstance(rule, MappingNode):
            continue
        rule_fields = mapping_fields(rule)
        verify_images_pair = rule_fields.get("verifyImages")
        if verify_images_pair is None or not isinstance(
            verify_images_pair[0], SequenceNode
        ):
            continue

        for block in verify_images_pair[0].value:
            if not isinstance(block, MappingNode):
                continue
            block_fields = mapping_fields(block)
            image_references = string_list(
                block_fields.get("imageReferences", (None, 0))[0]
            )
            skip_image_references = string_list(
                block_fields.get("skipImageReferences", (None, 0))[0]
            )
            action = scalar_field(block_fields, "failureAction", policy_action)
            blocks.append(
                VerifyImagesBlock(
                    image_references=image_references,
                    skip_image_references=skip_image_references,
                    action=action or "Audit",
                    path=path,
                    line=node_line(block),
                )
            )
    return blocks


def parse_yaml_file(path: Path) -> tuple[list[ImageRef], list[VerifyImagesBlock]]:
    try:
        with path.open(encoding="utf-8") as handle:
            documents = list(yaml.compose_all(handle, Loader=yaml.SafeLoader))
    except (OSError, yaml.YAMLError) as exc:
        raise GuardUsageError(f"failed to parse {path}: {exc}") from exc

    refs: list[ImageRef] = []
    verify_images_blocks: list[VerifyImagesBlock] = []
    for document in documents:
        if document is None:
            continue
        refs.extend(extract_refs_from_node(document, path))
        verify_images_blocks.extend(extract_verify_images_blocks_from_policy(document, path))
    return refs, verify_images_blocks


def is_first_party(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in FIRST_PARTY_IMAGE_PREFIXES)


def org_probe(org_glob: str) -> str:
    if not org_glob.endswith("*"):
        raise ValueError(f"first-party org glob must end with '*': {org_glob}")
    return f"{org_glob[:-1]}__enforce_probe__"


def block_covers(block: VerifyImagesBlock, image_name: str) -> bool:
    matched = any(
        fnmatch.fnmatch(image_name, image_glob)
        for image_glob in block.image_references
    )
    if not matched:
        return False
    return not any(
        fnmatch.fnmatch(image_name, skip_glob)
        for skip_glob in block.skip_image_references
    )


def find_violations(
    first_party_refs: list[ImageRef], enforce_blocks: list[VerifyImagesBlock]
) -> list[str]:
    findings: list[str] = []
    if not enforce_blocks:
        findings.append("no Enforce image-signature policy found")

    for org_glob in FIRST_PARTY_ORG_GLOBS:
        probe = org_probe(org_glob)
        if not any(block_covers(block, probe) for block in enforce_blocks):
            findings.append(
                f"first-party org {org_glob} has no Enforce signature rule"
            )

    for ref in sorted(first_party_refs, key=lambda item: (display_path(item.path), item.line)):
        if not any(block_covers(block, ref.name) for block in enforce_blocks):
            findings.append(
                "first-party image not signature-Enforced: "
                f"{display_path(ref.path)}:{ref.line} ({ref.name})"
            )

    return findings


def evaluate_roots(roots: Iterable[Path]) -> GuardResult:
    paths = iter_yaml_paths(roots)
    refs: list[ImageRef] = []
    verify_images_blocks: list[VerifyImagesBlock] = []
    for path in paths:
        path_refs, path_blocks = parse_yaml_file(path)
        refs.extend(path_refs)
        verify_images_blocks.extend(path_blocks)

    first_party_refs = [ref for ref in refs if is_first_party(ref.name)]
    enforce_blocks = [
        block for block in verify_images_blocks if block.action == "Enforce"
    ]
    findings = find_violations(first_party_refs, enforce_blocks)
    return GuardResult(
        paths=paths,
        refs=refs,
        first_party_refs=first_party_refs,
        verify_images_blocks=verify_images_blocks,
        enforce_blocks=enforce_blocks,
        findings=findings,
    )


def exit_code_for_findings(findings: list[str]) -> int:
    return 1 if findings else 0


def print_findings(findings: list[str]) -> None:
    for finding in findings:
        print(f"ERROR: {finding}", file=sys.stderr)


def print_pass(result: GuardResult) -> None:
    print(
        f"PASS: {len(result.first_party_refs)} first-party image refs covered "
        "by Enforce signature rules; "
        f"{len(FIRST_PARTY_ORG_GLOBS)} first-party orgs Enforce-locked across "
        f"{len(result.paths)} YAML files."
    )
    print("Covered first-party image refs:")
    for ref in sorted(
        result.first_party_refs, key=lambda item: (display_path(item.path), item.line)
    ):
        print(
            f"  - {display_path(ref.path)}:{ref.line} "
            f"({ref.source}: {ref.name})"
        )
    print("Enforce-locked first-party org globs:")
    for org_glob in FIRST_PARTY_ORG_GLOBS:
        print(f"  - {org_glob}")


def main() -> int:
    args = parse_args()
    roots = tuple(args.roots) if args.roots else DEFAULT_ROOTS

    try:
        result = evaluate_roots(roots)
    except GuardUsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if result.findings:
        print_findings(result.findings)
        return exit_code_for_findings(result.findings)

    print_pass(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
