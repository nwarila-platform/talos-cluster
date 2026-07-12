#!/usr/bin/env python3
"""Fail if raw manifest image digests drift or first-party refs use tags.

This guard scans YAML files under the configured roots, including standalone
trees such as apps/vault/restore-drill/ that are intentionally not rendered by
Flux validation.

Deliberate scope:
- Extract inline ``image:`` string scalars.
- Extract kustomize ``images:`` list entries carrying ``name`` plus ``digest``,
  ``newTag``, and/or ``newName``.
- Ignore extracted values containing ``*`` because those are match patterns, not
  concrete pins.

Deliberately out of scope for SM3a:
- HelmRelease split-image maps such as ``image: {repository, tag, digest}``.
  Those are single-occurrence third-party refs covered by other work.
- Proving that a bare first-party ``image: <name>`` is covered by a kustomize
  ``images:`` transformer. That requires cross-referencing the kustomize tree
  and is deferred; SM3a only rejects explicit mutable tags.
"""

from __future__ import annotations

import argparse
import re
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
FIRST_PARTY_IMAGE_PREFIXES = (
    "ghcr.io/nwarila-platform/",
    "ghcr.io/nwarila/",
    "ghcr.io/the-hero-wars-guys/",
)

DIGEST_VALUE_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
DIGEST_REF_RE = re.compile(
    r"^(?P<name>[^\s@]+)@(?P<digest>sha256:[0-9a-fA-F]{64})$"
)
YAML_SUFFIXES = {".yaml", ".yml"}


@dataclass(frozen=True)
class ImageRef:
    name: str
    kind: str
    digest: str | None
    path: Path
    line: int
    value: str
    source: str


class GuardUsageError(Exception):
    """A tooling or input error that should exit with code 2."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan raw YAML for duplicate image digest drift and explicit "
            "mutable tags on first-party GHCR images."
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
    digest_match = DIGEST_REF_RE.match(value)
    if digest_match:
        return digest_match.group("name")
    name, _tag = split_tag_ref(value)
    return name


def parse_inline_image(value: str, path: Path, line: int) -> ImageRef | None:
    value = value.strip()
    if not value or "*" in value:
        return None

    digest_match = DIGEST_REF_RE.match(value)
    if digest_match:
        return ImageRef(
            name=digest_match.group("name"),
            kind="digest",
            digest=digest_match.group("digest").lower(),
            path=path,
            line=line,
            value=value,
            source="inline image",
        )

    if "@" in value:
        return None

    name, tag = split_tag_ref(value)
    if tag is not None:
        return ImageRef(
            name=name,
            kind="tag",
            digest=None,
            path=path,
            line=line,
            value=value,
            source="inline image",
        )

    return ImageRef(
        name=value,
        kind="bare",
        digest=None,
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

        name = normalize_image_name(raw_name.strip())
        if not name or "*" in name:
            continue

        digest_pair = fields.get("digest")
        if digest_pair is not None:
            digest_node, digest_line = digest_pair
            digest = scalar_value(digest_node)
            if digest is not None and DIGEST_VALUE_RE.match(digest.strip()):
                normalized_digest = digest.strip().lower()
                refs.append(
                    ImageRef(
                        name=name,
                        kind="digest",
                        digest=normalized_digest,
                        path=path,
                        line=digest_line,
                        value=f"{name}@{normalized_digest}",
                        source="kustomize images",
                    )
                )
                continue

        new_tag_pair = fields.get("newTag")
        if new_tag_pair is not None:
            tag_node, tag_line = new_tag_pair
            tag = scalar_value(tag_node)
            if tag is not None:
                tag = tag.strip()
                if tag and "*" not in tag:
                    refs.append(
                        ImageRef(
                            name=name,
                            kind="tag",
                            digest=None,
                            path=path,
                            line=tag_line,
                            value=f"{name}:{tag}",
                            source="kustomize images",
                        )
                    )
                    continue

        refs.append(
            ImageRef(
                name=name,
                kind="bare",
                digest=None,
                path=path,
                line=name_line,
                value=name,
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


def extract_refs(path: Path) -> list[ImageRef]:
    try:
        with path.open(encoding="utf-8") as handle:
            documents = list(yaml.compose_all(handle, Loader=yaml.SafeLoader))
    except (OSError, yaml.YAMLError) as exc:
        raise GuardUsageError(f"failed to parse {path}: {exc}") from exc

    refs: list[ImageRef] = []
    for document in documents:
        if document is not None:
            refs.extend(extract_refs_from_node(document, path))
    return refs


def is_first_party(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in FIRST_PARTY_IMAGE_PREFIXES)


def find_digest_drifts(refs: list[ImageRef]) -> dict[str, dict[str, list[ImageRef]]]:
    by_name: dict[str, dict[str, list[ImageRef]]] = {}
    for ref in refs:
        if ref.kind != "digest" or ref.digest is None:
            continue
        by_name.setdefault(ref.name, {}).setdefault(ref.digest, []).append(ref)
    return {
        name: digest_refs
        for name, digest_refs in by_name.items()
        if len(digest_refs) > 1
    }


def find_first_party_tags(refs: list[ImageRef]) -> list[ImageRef]:
    return [ref for ref in refs if ref.kind == "tag" and is_first_party(ref.name)]


def print_digest_drifts(drifts: dict[str, dict[str, list[ImageRef]]]) -> None:
    for name in sorted(drifts):
        print(f"ERROR: image digest drift detected for {name}:", file=sys.stderr)
        for digest in sorted(drifts[name]):
            print(f"  {digest}:", file=sys.stderr)
            for ref in sorted(
                drifts[name][digest], key=lambda item: (display_path(item.path), item.line)
            ):
                print(
                    f"    - {display_path(ref.path)}:{ref.line} "
                    f"({ref.source}: {ref.value})",
                    file=sys.stderr,
                )


def print_first_party_tags(tags: list[ImageRef]) -> None:
    for ref in sorted(tags, key=lambda item: (display_path(item.path), item.line)):
        print(
            "ERROR: first-party image uses an explicit mutable tag: "
            f"{display_path(ref.path)}:{ref.line} ({ref.source}: {ref.value})",
            file=sys.stderr,
        )


def main() -> int:
    args = parse_args()
    roots = tuple(args.roots) if args.roots else DEFAULT_ROOTS

    try:
        paths = iter_yaml_paths(roots)
        refs = [ref for path in paths for ref in extract_refs(path)]
    except GuardUsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    drifts = find_digest_drifts(refs)
    tags = find_first_party_tags(refs)
    if drifts or tags:
        print_digest_drifts(drifts)
        print_first_party_tags(tags)
        return 1

    print(
        "PASS: image digest guard found no duplicate digest drift and no "
        f"explicit first-party image tags across {len(paths)} YAML files "
        f"({len(refs)} extracted refs)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
