#!/usr/bin/env python3
"""Reject privilege-escalation grants in managed Vault policy HCL.

This guard scans the Vault policy HCL that can be applied through GitOps:

- ``*.hcl`` files under ``clusters/talos-cluster/apps/vault/vault-config/policies``
- raw ``spec.policy`` HCL in redhatcop.redhat.io/v1alpha1 Policy CRs under
  ``clusters/talos-cluster/apps/vault``

The parser is intentionally small and fail-closed. It understands Vault ACL
``path "..." { capabilities = [...] }`` stanzas, comments, quoted strings, and
multi-line capability lists. It does not try to evaluate general HCL.
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
except ImportError as exc:  # pragma: no cover - exercised by missing CI dependency
    print("PyYAML is required; install python3-yaml.", file=sys.stderr)
    raise SystemExit(2) from exc


DEFAULT_POLICY_DIR = Path(
    "clusters/talos-cluster/apps/vault/vault-config/policies"
)
DEFAULT_POLICY_CR_ROOT = Path("clusters/talos-cluster/apps/vault")
YAML_SUFFIXES = {".yaml", ".yml"}
WRITE_CAPABILITIES = {"create", "update", "patch", "delete", "sudo"}
GLOBAL_WILDCARD_PATHS = {"*", "/*"}
BROAD_SYS_WRITE_PATHS = {"sys", "sys/*"}
SELF_TOKEN_OP_GLOBS = (
    "auth/token/renew-self",
    "auth/token/lookup-self",
    "auth/token/*-self",
)
E3_SURFACE_GLOBS = (
    "sys/policies/*",
    "sys/policy/*",
    "auth/*/role/*",
    "auth/*/config*",
    "sys/auth/*",
    "sys/mounts/*",
    "identity/entity*",
    "identity/group*",
    "identity/*/aliases*",
)


class GuardUsageError(Exception):
    """A tooling or input error that should exit with code 2."""


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int


@dataclass(frozen=True)
class PolicySource:
    label: str
    content: str


@dataclass(frozen=True)
class PolicyStanza:
    source: PolicySource
    line: int
    path: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class GuardResult:
    sources: list[PolicySource]
    stanzas: list[PolicyStanza]
    findings: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reject sudo, global wildcard, and control-plane write grants in "
            "managed Vault policy HCL."
        )
    )
    parser.add_argument(
        "--policy-root",
        dest="policy_roots",
        action="append",
        type=Path,
        help=(
            "managed .hcl file or directory to scan; may be passed multiple "
            f"times (default: {DEFAULT_POLICY_DIR})"
        ),
    )
    parser.add_argument(
        "--cr-root",
        dest="cr_roots",
        action="append",
        type=Path,
        help=(
            "YAML file or directory to scan for redhatcop Policy CR "
            f"spec.policy HCL; may be passed multiple times (default: "
            f"{DEFAULT_POLICY_CR_ROOT})"
        ),
    )
    return parser.parse_args()


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def describe_token(token: Token | None) -> str:
    if token is None:
        return "end of file"
    if token.kind == "SYMBOL":
        return repr(token.value)
    return f"{token.kind.lower()} {token.value!r}"


def tokenize_hcl(content: str, source: PolicySource) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    line = 1
    length = len(content)

    while index < length:
        char = content[index]

        if char in " \t\r":
            index += 1
            continue
        if char == "\n":
            line += 1
            index += 1
            continue
        if char == "#":
            index += 1
            while index < length and content[index] != "\n":
                index += 1
            continue
        if char == "/" and index + 1 < length and content[index + 1] == "/":
            index += 2
            while index < length and content[index] != "\n":
                index += 1
            continue
        if char == "/" and index + 1 < length and content[index + 1] == "*":
            start_line = line
            index += 2
            while index + 1 < length:
                if content[index] == "\n":
                    line += 1
                    index += 1
                    continue
                if content[index] == "*" and content[index + 1] == "/":
                    index += 2
                    break
                index += 1
            else:
                raise GuardUsageError(
                    f"{source.label}:{start_line}: unterminated block comment"
                )
            continue
        if char == '"':
            start_line = line
            index += 1
            value: list[str] = []
            while index < length:
                current = content[index]
                if current == "\n":
                    raise GuardUsageError(
                        f"{source.label}:{start_line}: unterminated quoted string"
                    )
                if current == '"':
                    index += 1
                    tokens.append(Token("STRING", "".join(value), start_line))
                    break
                if current == "\\":
                    if index + 1 >= length:
                        raise GuardUsageError(
                            f"{source.label}:{start_line}: unterminated escape"
                        )
                    escape = content[index + 1]
                    value.append(
                        {
                            '"': '"',
                            "\\": "\\",
                            "n": "\n",
                            "r": "\r",
                            "t": "\t",
                        }.get(escape, escape)
                    )
                    index += 2
                    continue
                value.append(current)
                index += 1
            else:
                raise GuardUsageError(
                    f"{source.label}:{start_line}: unterminated quoted string"
                )
            continue
        if char in "{}[]=,":
            tokens.append(Token("SYMBOL", char, line))
            index += 1
            continue
        if char.isalpha() or char in "_-":
            start = index
            start_line = line
            index += 1
            while index < length and (
                content[index].isalnum() or content[index] in "_-"
            ):
                index += 1
            tokens.append(Token("IDENT", content[start:index], start_line))
            continue
        if char.isdigit():
            start = index
            start_line = line
            index += 1
            while index < length and content[index].isdigit():
                index += 1
            tokens.append(Token("NUMBER", content[start:index], start_line))
            continue

        raise GuardUsageError(
            f"{source.label}:{line}: unexpected HCL character {char!r}"
        )

    return tokens


class HclPolicyParser:
    def __init__(self, source: PolicySource):
        self.source = source
        self.tokens = tokenize_hcl(source.content, source)
        self.index = 0

    def peek(self) -> Token | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def consume(self) -> Token:
        token = self.peek()
        if token is None:
            raise GuardUsageError(f"{self.source.label}: unexpected end of file")
        self.index += 1
        return token

    def accept(self, value: str) -> bool:
        token = self.peek()
        if token is not None and token.kind == "SYMBOL" and token.value == value:
            self.index += 1
            return True
        return False

    def expect_symbol(self, value: str) -> Token:
        token = self.consume()
        if token.kind == "SYMBOL" and token.value == value:
            return token
        raise GuardUsageError(
            f"{self.source.label}:{token.line}: expected {value!r}, "
            f"found {describe_token(token)}"
        )

    def expect_string(self) -> Token:
        token = self.consume()
        if token.kind == "STRING":
            return token
        raise GuardUsageError(
            f"{self.source.label}:{token.line}: expected quoted string, "
            f"found {describe_token(token)}"
        )

    def expect_identifier(self, value: str | None = None) -> Token:
        token = self.consume()
        if token.kind != "IDENT":
            raise GuardUsageError(
                f"{self.source.label}:{token.line}: expected identifier, "
                f"found {describe_token(token)}"
            )
        if value is not None and token.value != value:
            raise GuardUsageError(
                f"{self.source.label}:{token.line}: expected {value!r}, "
                f"found {token.value!r}"
            )
        return token

    def parse(self) -> list[PolicyStanza]:
        stanzas: list[PolicyStanza] = []
        while self.peek() is not None:
            token = self.peek()
            if token is None:
                break
            if token.kind != "IDENT" or token.value != "path":
                raise GuardUsageError(
                    f"{self.source.label}:{token.line}: expected path block, "
                    f"found {describe_token(token)}"
                )
            stanzas.append(self.parse_path_block())

        if not stanzas:
            raise GuardUsageError(f"{self.source.label}: contains no path stanzas")
        return stanzas

    def parse_path_block(self) -> PolicyStanza:
        start = self.expect_identifier("path")
        path_token = self.expect_string()
        self.expect_symbol("{")

        capabilities: tuple[str, ...] | None = None
        while not self.accept("}"):
            token = self.peek()
            if token is None:
                raise GuardUsageError(
                    f"{self.source.label}:{start.line}: unterminated path block "
                    f"for {path_token.value!r}"
                )
            if token.kind != "IDENT":
                raise GuardUsageError(
                    f"{self.source.label}:{token.line}: expected path-block "
                    f"attribute, found {describe_token(token)}"
                )

            name = self.consume()
            if name.value == "capabilities":
                if capabilities is not None:
                    raise GuardUsageError(
                        f"{self.source.label}:{name.line}: duplicate "
                        "capabilities attribute"
                    )
                self.expect_symbol("=")
                capabilities = self.parse_capabilities_list()
                continue

            if self.accept("="):
                self.skip_value()
                continue
            if self.accept("{"):
                self.skip_block_body(name)
                continue

            raise GuardUsageError(
                f"{self.source.label}:{name.line}: expected '=' or '{{' after "
                f"attribute {name.value!r}"
            )

        if capabilities is None:
            raise GuardUsageError(
                f"{self.source.label}:{start.line}: path {path_token.value!r} "
                "has no capabilities list"
            )
        return PolicyStanza(
            source=self.source,
            line=start.line,
            path=path_token.value,
            capabilities=capabilities,
        )

    def parse_capabilities_list(self) -> tuple[str, ...]:
        self.expect_symbol("[")
        capabilities: list[str] = []
        if self.accept("]"):
            return ()

        while True:
            value = self.expect_string()
            capabilities.append(value.value)
            if self.accept(","):
                if self.accept("]"):
                    return tuple(capabilities)
                continue
            self.expect_symbol("]")
            return tuple(capabilities)

    def skip_value(self) -> None:
        token = self.peek()
        if token is None:
            raise GuardUsageError(f"{self.source.label}: expected value, found EOF")
        if token.kind == "SYMBOL" and token.value in {"[", "{"}:
            opening = self.consume()
            self.skip_collection(opening)
            return
        if token.kind in {"STRING", "IDENT", "NUMBER"}:
            self.consume()
            return
        raise GuardUsageError(
            f"{self.source.label}:{token.line}: expected value, "
            f"found {describe_token(token)}"
        )

    def skip_block_body(self, opening_name: Token) -> None:
        depth = 1
        while depth > 0:
            token = self.peek()
            if token is None:
                raise GuardUsageError(
                    f"{self.source.label}:{opening_name.line}: unterminated "
                    f"block {opening_name.value!r}"
                )
            token = self.consume()
            if token.kind == "SYMBOL" and token.value == "{":
                depth += 1
            elif token.kind == "SYMBOL" and token.value == "}":
                depth -= 1

    def skip_collection(self, opening: Token) -> None:
        pairs = {"[": "]", "{": "}"}
        closing = pairs[opening.value]
        depth = 1
        while depth > 0:
            token = self.peek()
            if token is None:
                raise GuardUsageError(
                    f"{self.source.label}:{opening.line}: unterminated "
                    f"{opening.value!r} collection"
                )
            token = self.consume()
            if token.kind != "SYMBOL":
                continue
            if token.value == opening.value:
                depth += 1
            elif token.value == closing:
                depth -= 1


def iter_hcl_paths(roots: Iterable[Path]) -> list[Path]:
    paths: set[Path] = set()
    for root in roots:
        if not root.exists():
            raise GuardUsageError(f"{root} does not exist")
        if root.is_file():
            if root.suffix != ".hcl":
                raise GuardUsageError(f"{root} is not an .hcl file")
            paths.add(root)
            continue
        if not root.is_dir():
            raise GuardUsageError(f"{root} is neither a file nor a directory")
        for path in root.rglob("*.hcl"):
            if path.is_file():
                paths.add(path)
    return sorted(paths, key=display_path)


def iter_yaml_paths(roots: Iterable[Path]) -> list[Path]:
    paths: set[Path] = set()
    for root in roots:
        if not root.exists():
            raise GuardUsageError(f"{root} does not exist")
        if root.is_file():
            if root.suffix not in YAML_SUFFIXES:
                raise GuardUsageError(f"{root} is not a YAML file")
            paths.add(root)
            continue
        if not root.is_dir():
            raise GuardUsageError(f"{root} is neither a file nor a directory")
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in YAML_SUFFIXES:
                paths.add(path)
    return sorted(paths, key=display_path)


def load_policy_file_source(path: Path) -> PolicySource:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GuardUsageError(f"failed to read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise GuardUsageError(f"{path} is not valid UTF-8: {exc}") from exc
    return PolicySource(label=display_path(path), content=content)


def collect_hcl_sources(policy_roots: Iterable[Path]) -> list[PolicySource]:
    return [load_policy_file_source(path) for path in iter_hcl_paths(policy_roots)]


def collect_policy_cr_sources(cr_roots: Iterable[Path]) -> list[PolicySource]:
    sources: list[PolicySource] = []
    for path in iter_yaml_paths(cr_roots):
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except OSError as exc:
            raise GuardUsageError(f"failed to read {path}: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise GuardUsageError(f"{path} is not valid UTF-8: {exc}") from exc
        except yaml.YAMLError as exc:
            raise GuardUsageError(f"{path} does not parse as YAML: {exc}") from exc

        for document in documents:
            if not isinstance(document, dict):
                continue
            if document.get("apiVersion") != "redhatcop.redhat.io/v1alpha1":
                continue
            if document.get("kind") != "Policy":
                continue

            metadata = document.get("metadata")
            name = "<unnamed>"
            if isinstance(metadata, dict) and isinstance(metadata.get("name"), str):
                name = metadata["name"]

            spec = document.get("spec")
            if not isinstance(spec, dict):
                raise GuardUsageError(
                    f"{display_path(path)} Policy CR {name!r} has no mapping spec"
                )
            policy = spec.get("policy")
            if not isinstance(policy, str) or not policy.strip():
                raise GuardUsageError(
                    f"{display_path(path)} Policy CR {name!r} has no non-empty "
                    "string spec.policy"
                )

            sources.append(
                PolicySource(
                    label=f"{display_path(path)} (Policy CR {name})",
                    content=policy,
                )
            )
    return sources


def parse_hcl_source(source: PolicySource) -> list[PolicyStanza]:
    return HclPolicyParser(source).parse()


def is_self_token_operation(path: str) -> bool:
    normalized = path.strip().lstrip("/")
    return any(fnmatch.fnmatchcase(normalized, glob) for glob in SELF_TOKEN_OP_GLOBS)


def first_matching_e3_surface(path: str) -> str | None:
    normalized = path.strip().lstrip("/")
    if is_self_token_operation(normalized):
        return None
    for glob in E3_SURFACE_GLOBS:
        if fnmatch.fnmatchcase(normalized, glob):
            return glob
    return None


def format_caps(capabilities: Iterable[str]) -> str:
    return ", ".join(sorted(set(capabilities)))


def check_stanza(stanza: PolicyStanza) -> list[str]:
    findings: list[str] = []
    path = stanza.path.strip()
    normalized_path = path.lstrip("/")
    lower_caps = tuple(capability.lower() for capability in stanza.capabilities)
    write_caps = sorted(set(lower_caps).intersection(WRITE_CAPABILITIES))
    location = f"{stanza.source.label}:{stanza.line}"

    if "sudo" in lower_caps:
        findings.append(
            f"{location}: E1 sudo capability: path {stanza.path!r} grants sudo"
        )

    if path in GLOBAL_WILDCARD_PATHS:
        findings.append(
            f"{location}: E2 global wildcard path: path {stanza.path!r} is "
            "root-equivalent in managed Vault policy HCL"
        )

    e3_surface = first_matching_e3_surface(path)
    if e3_surface is not None and write_caps:
        findings.append(
            f"{location}: E3 self-escalation surface: path {stanza.path!r} "
            f"matches {e3_surface!r} with write capability/capabilities "
            f"{format_caps(write_caps)}"
        )

    if normalized_path in BROAD_SYS_WRITE_PATHS and write_caps:
        findings.append(
            f"{location}: E4 broad sys write: path {stanza.path!r} grants "
            f"write capability/capabilities {format_caps(write_caps)}"
        )

    return findings


def evaluate_roots(
    policy_roots: Iterable[Path],
    cr_roots: Iterable[Path],
) -> GuardResult:
    sources = collect_hcl_sources(policy_roots) + collect_policy_cr_sources(cr_roots)
    if not sources:
        raise GuardUsageError("no managed Vault policy HCL sources were found")

    stanzas: list[PolicyStanza] = []
    findings: list[str] = []
    for source in sources:
        source_stanzas = parse_hcl_source(source)
        stanzas.extend(source_stanzas)
        for stanza in source_stanzas:
            findings.extend(check_stanza(stanza))

    return GuardResult(sources=sources, stanzas=stanzas, findings=findings)


def print_findings(findings: list[str]) -> None:
    print("ERROR: managed Vault policy HCL escalation guard failed:", file=sys.stderr)
    for finding in findings:
        print(f"  - {finding}", file=sys.stderr)


def print_pass(result: GuardResult) -> None:
    print(
        "PASS: managed Vault policy no-escalation guard scanned "
        f"{len(result.sources)} policy source(s), {len(result.stanzas)} path "
        "stanza(s); no escalation findings."
    )
    print("Scanned managed Vault policy HCL:")
    for source in result.sources:
        stanza_count = sum(1 for stanza in result.stanzas if stanza.source == source)
        print(f"  - {source.label} ({stanza_count} path stanza(s))")


def run(policy_roots: Iterable[Path], cr_roots: Iterable[Path]) -> int:
    try:
        result = evaluate_roots(policy_roots, cr_roots)
    except GuardUsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if result.findings:
        print_findings(result.findings)
        return 1

    print_pass(result)
    return 0


def main() -> int:
    args = parse_args()
    policy_roots = (
        tuple(args.policy_roots) if args.policy_roots else (DEFAULT_POLICY_DIR,)
    )
    cr_roots = (
        tuple(args.cr_roots) if args.cr_roots else (DEFAULT_POLICY_CR_ROOT,)
    )
    return run(policy_roots, cr_roots)


if __name__ == "__main__":
    sys.exit(main())
