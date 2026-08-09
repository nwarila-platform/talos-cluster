#!/usr/bin/env python3
"""Build commit-bound, fail-closed evidence from eligible validation gates."""

from __future__ import annotations

import argparse
import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Any

import yaml
from yaml.events import AliasEvent, ScalarEvent
from yaml.nodes import ScalarNode


GENERATOR_PATH = "scripts/build-review-evidence.py"
WORKFLOW_PATH = ".github/workflows/validate.yaml"
MATERIALIZATION = "git worktree add --detach"
WORKFLOW_KEYS = frozenset({"name", "on", "permissions", "jobs"})
JOB_KEYS = frozenset({"name", "runs-on", "steps"})
STEP_KEYS = frozenset({"name", "id", "run"})
STATUSES = frozenset({"pass", "failed", "signaled", "not-run", "timed-out"})
REASON_CODES = frozenset(
    {
        "outside-grammar",
        "outside-guard-family",
        "step-key-not-allowlisted",
        "job-context-not-allowlisted",
        "workflow-context-not-allowlisted",
        "path-not-tracked-regular-blob",
        "path-escapes-root",
        "interpreter-absent",
        "gate-timed-out",
        "gate-signaled",
        "gate-nonzero-exit",
    }
)
COMMAND_RE = re.compile(
    r"^(?P<interpreter>python|python3|bash) "
    r"(?P<path>scripts/[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*)"
    r"(?P<flags>(?: --[a-z0-9][a-z0-9-]*)*)$"
)
CHECK_PY_RE = re.compile(r"^scripts/check-[A-Za-z0-9][A-Za-z0-9._-]*\.py$")
CHECK_SH_RE = re.compile(r"^scripts/check-[A-Za-z0-9][A-Za-z0-9._-]*\.sh$")
RENDER_RE = re.compile(r"^scripts/render-[A-Za-z0-9][A-Za-z0-9._-]*\.py$")
SELFTEST_RE = re.compile(r"^scripts/([A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*\.selftest\.py$")
MERGE_TAG = "tag:yaml.org,2002:merge"
TRUST_BOUNDARY = [
    "This tool is not a GitHub Actions runner; workflow bodies outside the closed grammar are never executed directly.",
    "This tool is not a sandbox and does not confine selected scripts or their transitive commands.",
    "The generator self-binding detects accidental source drift but is not tamper-resistant because the check runs inside the program whose bytes it reads.",
    "Every selected script and its transitive commands must be effect-audited before use.",
    "The controller must have no ambient live-state capability that a runaway selected script could use.",
    "Credential-free HOME/TMPDIR child-environment scrubbing is defense in depth, not confinement.",
    "Eligible gates run without reproducing ineligible CI setup; nested-tool failures are observed local failures, not CI-equivalent results.",
    "GitHub job isolation and scheduling are not reproduced; gates run deterministically in workflow order.",
    "The orchestrator writes the artifact, a throwaway worktree, and Git worktree administrative metadata.",
]


class Refusal(RuntimeError):
    """A fail-closed condition that must produce exit status 3."""


@dataclass(frozen=True)
class ScalarPresentation:
    """Source-level scalar properties that composition would otherwise discard."""

    value: str
    style: str | None
    anchor: str | None
    tag: str | None
    start_line: int
    end_line: int

    def is_plain_single_line_implicit(self) -> bool:
        return (
            self.style is None
            and self.anchor is None
            and self.tag is None
            and self.start_line == self.end_line
        )


class PresentedMapping(dict[Any, Any]):
    """Constructed mapping retaining source presentation for each authored pair."""

    def __init__(self) -> None:
        super().__init__()
        self.key_presentations: list[ScalarPresentation | None] = []
        self.value_presentations: dict[Any, ScalarPresentation | None] = {}


class DuplicateTrackingLoader(yaml.SafeLoader):
    """Safe loader that retains scalar presentation and refuses unsafe YAML forms."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self.scalar_presentations: dict[int, ScalarPresentation] = {}

    def compose_node(self, parent: Any, index: Any) -> yaml.Node:
        if self.check_event(AliasEvent):
            raise Refusal("workflow YAML contains an alias")
        return super().compose_node(parent, index)

    def compose_scalar_node(self, anchor: str | None) -> ScalarNode:
        event = self.get_event()
        if not isinstance(event, ScalarEvent):
            raise Refusal("workflow YAML scalar event was not available during composition")
        tag = event.tag
        if tag is None or tag == "!":
            tag = self.resolve(ScalarNode, event.value, event.implicit)
        node = ScalarNode(
            tag,
            event.value,
            event.start_mark,
            event.end_mark,
            style=event.style,
        )
        if anchor is not None:
            self.anchors[anchor] = node
        self.scalar_presentations[id(node)] = ScalarPresentation(
            value=event.value,
            style=event.style,
            anchor=event.anchor,
            tag=event.tag,
            start_line=event.start_mark.line,
            end_line=event.end_mark.line,
        )
        return node

    def scalar_presentation(self, node: yaml.Node) -> ScalarPresentation | None:
        return self.scalar_presentations.get(id(node))

    def construct_yaml_map(self, node: yaml.MappingNode) -> Any:
        mapping = PresentedMapping()
        yield mapping
        constructed = self.construct_mapping(node)
        mapping.update(constructed)
        mapping.key_presentations = constructed.key_presentations
        mapping.value_presentations = constructed.value_presentations

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> PresentedMapping:
        if not isinstance(node, yaml.MappingNode):
            raise Refusal("workflow contains a non-mapping node where a mapping was required")
        mapping = PresentedMapping()
        for key_node, value_node in node.value:
            if key_node.tag == MERGE_TAG:
                raise Refusal("workflow YAML contains a merge key")
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise Refusal("workflow contains an unhashable YAML mapping key") from exc
            if duplicate:
                raise Refusal("workflow YAML contains a duplicate mapping key")
            mapping.key_presentations.append(self.scalar_presentation(key_node))
            mapping[key] = self.construct_object(value_node, deep=deep)
            mapping.value_presentations[key] = self.scalar_presentation(value_node)
        return mapping


DuplicateTrackingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    DuplicateTrackingLoader.construct_yaml_map,
)


@dataclass(frozen=True)
class ParsedCommand:
    argv: list[str]
    script_path: str


@dataclass(frozen=True)
class Classification:
    parsed: ParsedCommand | None
    reason_code: str | None
    reason: str | None


@dataclass
class PublicationOps:
    """Injectable wrappers for the ordered publication durability operations."""

    def create_temp(self, name: str, directory_fd: int) -> int:
        return os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )

    def fsync_file(self, file_fd: int) -> None:
        os.fsync(file_fd)

    def link(self, source: str, destination: str, directory_fd: int) -> None:
        os.link(
            source,
            destination,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )

    def unlink(self, name: str, directory_fd: int) -> None:
        os.unlink(name, dir_fd=directory_fd)

    def fsync_directory(self, directory_fd: int) -> None:
        os.fsync(directory_fd)


@dataclass(frozen=True)
class PublicationFailure:
    step: str
    detail: str
    committed: bool
    temp_path: Path | None


class PublicationError(Refusal):
    def __init__(self, failure: PublicationFailure) -> None:
        super().__init__(f"publication failed at {failure.step}: {failure.detail}")
        self.failure = failure


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def run_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        list(argv),
        cwd=cwd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        if not detail:
            detail = completed.stdout.decode("utf-8", errors="replace").strip()
        raise Refusal(
            f"command failed ({completed.returncode}): {' '.join(argv)}"
            + (f": {detail}" if detail else "")
        )
    return completed


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return run_command(["git", *args], cwd=repo, check=check)


def resolve_commit(repo: Path, revision: str) -> str:
    completed = git(
        repo,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{revision}^{{commit}}",
        check=False,
    )
    if completed.returncode != 0:
        raise Refusal(f"commit does not resolve: {revision}")
    commit = completed.stdout.decode("ascii", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise Refusal(f"resolved commit is not a full 40-character SHA: {commit}")
    return commit


def tree_entry(repo: Path, commit: str, path: str) -> tuple[str, str, str] | None:
    completed = git(repo, "ls-tree", "-z", commit, "--", path)
    if not completed.stdout:
        return None
    records = [record for record in completed.stdout.split(b"\0") if record]
    if len(records) != 1:
        return None
    metadata, separator, found_path = records[0].partition(b"\t")
    if not separator or found_path.decode("utf-8", errors="strict") != path:
        return None
    fields = metadata.decode("ascii", errors="strict").split()
    if len(fields) != 3:
        return None
    return fields[0], fields[1], fields[2]


def regular_blob_sha(repo: Path, commit: str, path: str) -> str:
    entry = tree_entry(repo, commit, path)
    if entry is None:
        raise Refusal(f"target path is absent: {path}")
    mode, object_type, object_sha = entry
    if object_type != "blob" or mode not in {"100644", "100755"}:
        raise Refusal(f"target path is not a tracked regular blob: {path}")
    if not re.fullmatch(r"[0-9a-f]{40}", object_sha):
        raise Refusal(f"target blob ID is not a 40-character SHA: {path}")
    return object_sha


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def verify_generator_binding(repo: Path, commit: str) -> str:
    try:
        invoked_path = Path(__file__).absolute()
        actual_stat = invoked_path.lstat()
        if invoked_path.is_symlink():
            raise Refusal("generator source at __file__ is not a regular non-symlink file")
        actual_path = invoked_path.resolve(strict=True)
        actual_bytes = actual_path.read_bytes()
    except OSError as exc:
        raise Refusal(f"cannot read generator source at __file__: {exc}") from exc
    if not stat.S_ISREG(actual_stat.st_mode) or actual_path.is_symlink():
        raise Refusal("generator source at __file__ is not a regular non-symlink file")
    target_sha = regular_blob_sha(repo, commit, GENERATOR_PATH)
    actual_sha = git_blob_sha(actual_bytes)
    if actual_sha != target_sha:
        raise Refusal(
            "generator binding mismatch: source read at __file__ at check time does not match "
            f"{commit}:{GENERATOR_PATH}"
        )
    return target_sha


def tracked_tree(repo: Path, commit: str) -> list[tuple[str, str, str, str]]:
    completed = git(repo, "ls-tree", "-r", "-z", commit)
    entries: list[tuple[str, str, str, str]] = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise Refusal("git ls-tree returned a malformed record")
        fields = metadata.decode("ascii", errors="strict").split()
        if len(fields) != 3:
            raise Refusal("git ls-tree returned malformed metadata")
        entries.append(
            (*fields, raw_path.decode("utf-8", errors="strict"))
        )
    return entries


def refuse_gitlinks_and_active_filters(repo: Path, commit: str) -> None:
    entries = tracked_tree(repo, commit)
    gitlinks = [path for mode, object_type, _sha, path in entries if mode == "160000" or object_type == "commit"]
    if gitlinks:
        raise Refusal(f"gitlink/submodule entry is not allowed: {gitlinks[0]}")

    paths = [path for mode, object_type, _sha, path in entries if object_type == "blob"]
    if not paths:
        return
    payload = b"\0".join(path.encode("utf-8") for path in paths) + b"\0"
    attrs = run_command(
        ["git", "check-attr", "--source", commit, "--stdin", "-z", "filter"],
        cwd=repo,
        input_bytes=payload,
    ).stdout.split(b"\0")
    configured = git(
        repo,
        "config",
        "--includes",
        "--get-regexp",
        r"^filter\..*\.(smudge|process)$",
        check=False,
    )
    active_drivers: set[str] = set()
    if configured.returncode == 0:
        for line in configured.stdout.decode("utf-8", errors="strict").splitlines():
            key = line.split(None, 1)[0]
            match = re.fullmatch(r"filter\.(.+)\.(?:smudge|process)", key)
            if match:
                active_drivers.add(match.group(1))
    for index in range(0, len(attrs) - 2, 3):
        raw_path, attribute, value = attrs[index : index + 3]
        if attribute != b"filter":
            raise Refusal("git check-attr returned malformed filter output")
        driver = value.decode("utf-8", errors="strict")
        if driver in active_drivers:
            path = raw_path.decode("utf-8", errors="strict")
            raise Refusal(f"active checkout filter is not allowed: {driver} on {path}")


def load_workflow(path: Path) -> Mapping[Any, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise Refusal(f"cannot read workflow as UTF-8: {exc}") from exc
    loader = DuplicateTrackingLoader(text)
    try:
        document = loader.get_single_data()
    except Refusal:
        raise
    except yaml.YAMLError as exc:
        raise Refusal(f"cannot parse workflow YAML: {exc}") from exc
    finally:
        loader.dispose()
    if not isinstance(document, Mapping):
        raise Refusal("workflow document is not a mapping")
    return document


def mapping_has_only_keys(mapping: Mapping[Any, Any], allowlist: frozenset[str]) -> bool:
    if not isinstance(mapping, PresentedMapping):
        return False
    return len(mapping.key_presentations) == len(mapping) and all(
        presentation is not None
        and presentation.is_plain_single_line_implicit()
        and presentation.value in allowlist
        for presentation in mapping.key_presentations
    )


def scalar_value_presentation(
    mapping: Mapping[Any, Any],
    key: object,
) -> ScalarPresentation | None:
    if not isinstance(mapping, PresentedMapping):
        return None
    try:
        return mapping.value_presentations.get(key)
    except TypeError:
        return None


def parse_command_body(run_body: str) -> ParsedCommand | None:
    body = run_body[:-1] if run_body.endswith("\n") else run_body
    if "\n" in body or "\r" in body:
        return None
    if not body or any(ord(character) < 0x20 or ord(character) > 0x7E for character in body):
        return None
    if body.startswith(" ") or body.endswith(" ") or "  " in body:
        return None
    match = COMMAND_RE.fullmatch(body)
    if match is None:
        return None
    interpreter = match.group("interpreter")
    script_path = match.group("path")
    if interpreter in {"python", "python3"} and not script_path.endswith(".py"):
        return None
    if interpreter == "bash" and not script_path.endswith(".sh"):
        return None
    return ParsedCommand(argv=body.split(" "), script_path=script_path)


def is_guard_family(argv: Sequence[str]) -> bool:
    if list(argv) == ["python3", "scripts/rendered-inventory.py", "--all-paths"]:
        return True
    if len(argv) == 2:
        interpreter, path = argv
        if interpreter == "python3" and SELFTEST_RE.fullmatch(path):
            return True
        if interpreter in {"python", "python3"} and CHECK_PY_RE.fullmatch(path):
            return True
        if interpreter == "bash" and CHECK_SH_RE.fullmatch(path):
            return True
    if len(argv) == 3:
        interpreter, path, flag = argv
        if interpreter == "python3" and RENDER_RE.fullmatch(path) and flag == "--check":
            return True
    return False


def classify_step(
    repo: Path,
    commit: str,
    root: Path,
    step: Mapping[Any, Any],
    run_body: str,
    run_presentation: ScalarPresentation,
    *,
    workflow_context_allowed: bool,
    job_context_allowed: bool,
) -> Classification:
    if not workflow_context_allowed:
        return Classification(None, "workflow-context-not-allowlisted", "workflow mapping contains a non-allowlisted key")
    if not job_context_allowed:
        return Classification(None, "job-context-not-allowlisted", "job mapping contains a non-allowlisted key")
    if not mapping_has_only_keys(step, STEP_KEYS):
        return Classification(None, "step-key-not-allowlisted", "step mapping contains a non-allowlisted key")
    if not run_presentation.is_plain_single_line_implicit():
        return Classification(None, "outside-grammar", "run body is outside the closed command grammar")
    parsed = parse_command_body(run_body)
    if parsed is None:
        return Classification(None, "outside-grammar", "run body is outside the closed command grammar")
    if not is_guard_family(parsed.argv):
        return Classification(None, "outside-guard-family", "script is outside the read-only guard family")

    entry = tree_entry(repo, commit, parsed.script_path)
    if entry is None or entry[0] not in {"100644", "100755"} or entry[1] != "blob":
        return Classification(None, "path-not-tracked-regular-blob", "script path is not a tracked regular blob")
    disk_path = root / parsed.script_path
    try:
        disk_stat = disk_path.lstat()
    except OSError:
        return Classification(None, "path-not-tracked-regular-blob", "script path is not a regular non-symlink file on disk")
    if not stat.S_ISREG(disk_stat.st_mode) or disk_path.is_symlink():
        return Classification(None, "path-not-tracked-regular-blob", "script path is not a regular non-symlink file on disk")
    try:
        disk_path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return Classification(None, "path-escapes-root", "script path resolves outside the materialized root")
    return Classification(parsed, None, None)


def stream_object(data: bytes) -> dict[str, str]:
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return {"encoding": "base64", "data": base64.b64encode(data).decode("ascii")}
    return {"encoding": "utf-8", "data": decoded}


def empty_stream() -> dict[str, str]:
    return {"encoding": "utf-8", "data": ""}


def not_run_gate(
    job: str,
    step_name: str | None,
    run_body: str,
    reason_code: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "job": job,
        "step_name": step_name,
        "run_body": run_body,
        "status": "not-run",
        "reason": reason,
        "argv": None,
        "resolved_interpreter": None,
        "exit_status": None,
        "signal": None,
        "reason_code": reason_code,
        "stdout": empty_stream(),
        "stderr": empty_stream(),
    }


def child_environment(home: Path, temp_directory: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "TMPDIR": str(temp_directory),
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def execute_gate(
    job: str,
    step_name: str | None,
    run_body: str,
    parsed: ParsedCommand,
    *,
    root: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> dict[str, Any]:
    resolved = shutil.which(parsed.argv[0], path=environment.get("PATH"))
    if resolved is None:
        return not_run_gate(
            job,
            step_name,
            run_body,
            "interpreter-absent",
            f"interpreter not found in PATH: {parsed.argv[0]}",
        )
    resolved = str(Path(resolved).resolve())
    process = subprocess.Popen(
        parsed.argv,
        executable=resolved,
        cwd=root,
        env=dict(environment),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()

    if timed_out:
        return {
            "job": job,
            "step_name": step_name,
            "run_body": run_body,
            "status": "timed-out",
            "reason": f"gate exceeded timeout of {timeout_seconds} seconds",
            "argv": list(parsed.argv),
            "resolved_interpreter": resolved,
            "exit_status": None,
            "signal": None,
            "reason_code": "gate-timed-out",
            "stdout": stream_object(stdout),
            "stderr": stream_object(stderr),
        }
    if process.returncode < 0:
        number = -process.returncode
        return {
            "job": job,
            "step_name": step_name,
            "run_body": run_body,
            "status": "signaled",
            "reason": f"gate terminated by signal {number}",
            "argv": list(parsed.argv),
            "resolved_interpreter": resolved,
            "exit_status": None,
            "signal": number,
            "reason_code": "gate-signaled",
            "stdout": stream_object(stdout),
            "stderr": stream_object(stderr),
        }
    if process.returncode != 0:
        return {
            "job": job,
            "step_name": step_name,
            "run_body": run_body,
            "status": "failed",
            "reason": f"gate exited with status {process.returncode}",
            "argv": list(parsed.argv),
            "resolved_interpreter": resolved,
            "exit_status": process.returncode,
            "signal": None,
            "reason_code": "gate-nonzero-exit",
            "stdout": stream_object(stdout),
            "stderr": stream_object(stderr),
        }
    return {
        "job": job,
        "step_name": step_name,
        "run_body": run_body,
        "status": "pass",
        "reason": None,
        "argv": list(parsed.argv),
        "resolved_interpreter": resolved,
        "exit_status": 0,
        "signal": None,
        "reason_code": None,
        "stdout": stream_object(stdout),
        "stderr": stream_object(stderr),
    }


def canonical_scalar(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def collect_workflow(
    repo: Path,
    commit: str,
    root: Path,
    workflow: Mapping[Any, Any],
    *,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    workflow_allowed = mapping_has_only_keys(workflow, WORKFLOW_KEYS)
    jobs = workflow.get("jobs")
    if not isinstance(jobs, Mapping):
        raise Refusal("workflow jobs value is not a mapping")

    gates: list[dict[str, Any]] = []
    ineligible: list[dict[str, Any]] = []
    non_run: list[dict[str, Any]] = []
    context: list[dict[str, str]] = []
    permissions = workflow.get("permissions")
    if permissions is not None:
        if not isinstance(permissions, Mapping):
            raise Refusal("workflow permissions value is not a mapping")
        for key, value in permissions.items():
            context.append({"kind": "permissions", "value": f"{key}={canonical_scalar(value)}"})

    for job_index, (job_id, raw_job) in enumerate(jobs.items()):
        if not isinstance(job_id, str) or not isinstance(raw_job, Mapping):
            raise Refusal("workflow job IDs must be strings and job values must be mappings")
        context.append({"kind": "job-order", "value": f"{job_index}:{job_id}"})
        runs_on = raw_job.get("runs-on")
        if isinstance(runs_on, list):
            for runner in runs_on:
                context.append({"kind": "runs-on", "value": canonical_scalar(runner)})
        elif runs_on is not None:
            context.append({"kind": "runs-on", "value": canonical_scalar(runs_on)})
        job_allowed = mapping_has_only_keys(raw_job, JOB_KEYS)
        steps = raw_job.get("steps")
        if not isinstance(steps, list):
            raise Refusal(f"job steps value is not a list: {job_id}")
        for step in steps:
            if not isinstance(step, Mapping):
                raise Refusal(f"workflow step is not a mapping in job {job_id}")
            raw_name = step.get("name")
            if raw_name is not None and not isinstance(raw_name, str):
                raise Refusal(f"step name is not a string in job {job_id}")
            step_name = raw_name
            if "run" not in step:
                raw_uses = step.get("uses")
                uses = raw_uses if isinstance(raw_uses, str) else None
                non_run.append({"job": job_id, "step_name": step_name, "uses": uses})
                continue
            run_presentation = scalar_value_presentation(step, "run")
            if run_presentation is None:
                raise Refusal(f"run body is not a scalar in job {job_id}")
            run_body = run_presentation.value
            classification = classify_step(
                repo,
                commit,
                root,
                step,
                run_body,
                run_presentation,
                workflow_context_allowed=workflow_allowed,
                job_context_allowed=job_allowed,
            )
            if classification.parsed is None:
                if classification.reason_code is None or classification.reason is None:
                    raise Refusal("classifier returned an incomplete ineligible result")
                gate = not_run_gate(
                    job_id,
                    step_name,
                    run_body,
                    classification.reason_code,
                    classification.reason,
                )
                gates.append(gate)
                ineligible.append(
                    {
                        "job": job_id,
                        "step_name": step_name,
                        "run_body": run_body,
                        "reason_code": classification.reason_code,
                        "reason": classification.reason,
                    }
                )
                continue
            gates.append(
                execute_gate(
                    job_id,
                    step_name,
                    run_body,
                    classification.parsed,
                    root=root,
                    environment=environment,
                    timeout_seconds=timeout_seconds,
                )
            )
    if not gates:
        raise Refusal("derived gate list is empty")
    return gates, {
        "ineligible_steps": ineligible,
        "non_run_steps": non_run,
        "unreproduced_context": context,
        "trust_boundary": list(TRUST_BOUNDARY),
    }


def open_directory_without_symlinks(path: Path) -> int:
    if not path.is_absolute():
        raise Refusal(f"destination directory is not absolute: {path}")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
    except OSError as exc:
        os.close(current_fd)
        raise Refusal(f"destination parent must exist and contain no symlink: {path}: {exc}") from exc
    return current_fd


def write_all(file_fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(file_fd, payload[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short write while publishing artifact")
        offset += written


def publish_atomic(
    destination: Path,
    payload: bytes,
    *,
    operations: PublicationOps | None = None,
) -> None:
    ops = operations or PublicationOps()
    parent = destination.parent
    directory_fd = open_directory_without_symlinks(parent)
    temp_name: str | None = None
    temp_exists = False
    file_fd: int | None = None
    committed = False
    failed_step = "temp create"
    primary_error: OSError | None = None
    cleanup_error: OSError | None = None
    try:
        for _attempt in range(64):
            candidate = f".{destination.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
            try:
                file_fd = ops.create_temp(candidate, directory_fd)
            except FileExistsError:
                continue
            temp_name = candidate
            temp_exists = True
            break
        if file_fd is None or temp_name is None:
            raise OSError(errno.EEXIST, "could not allocate a unique temporary file")
        os.fchmod(file_fd, 0o600)
        write_all(file_fd, payload)
        failed_step = "file fsync"
        ops.fsync_file(file_fd)
        os.close(file_fd)
        file_fd = None

        failed_step = "link"
        ops.link(temp_name, destination.name, directory_fd)
        committed = True

        failed_step = "temp unlink"
        ops.unlink(temp_name, directory_fd)
        temp_exists = False

        failed_step = "directory fsync"
        ops.fsync_directory(directory_fd)
        return
    except OSError as exc:
        primary_error = exc
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError as exc:
                if primary_error is None:
                    primary_error = exc
                    failed_step = "temp file close"
        if temp_exists and temp_name is not None:
            try:
                ops.unlink(temp_name, directory_fd)
                temp_exists = False
            except OSError as exc:
                cleanup_error = exc
        os.close(directory_fd)

    if primary_error is None:
        primary_error = OSError(errno.EIO, "unknown publication failure")
    if failed_step == "link" and isinstance(primary_error, FileExistsError):
        detail = "destination already exists; existing entry left untouched"
    else:
        detail = str(primary_error)
    if cleanup_error is not None:
        detail += f"; best-effort temp cleanup failed: {cleanup_error}"
    surviving_temp = parent / temp_name if temp_exists and temp_name is not None else None
    raise PublicationError(
        PublicationFailure(
            step=failed_step,
            detail=detail,
            committed=committed,
            temp_path=surviving_temp,
        )
    )


def materialize(repo: Path, commit: str, worktree: Path) -> None:
    completed = run_command(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "worktree",
            "add",
            "--detach",
            str(worktree),
            commit,
        ],
        cwd=repo,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise Refusal(f"materialization failed: {detail or 'git worktree add failed'}")


def remove_materialized_worktree(repo: Path, worktree: Path) -> None:
    completed = run_command(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "worktree",
            "remove",
            "--force",
            str(worktree),
        ],
        cwd=repo,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise Refusal(detail or "git worktree remove failed")


def recovery_worktree_command(repo: Path, worktree: Path) -> str:
    return f"git -C {repo} worktree remove --force {worktree}"


def worktree_is_registered(repo: Path, worktree: Path) -> bool:
    completed = git(repo, "worktree", "list", "--porcelain")
    expected = str(worktree.resolve(strict=False))
    for line in completed.stdout.decode("utf-8", errors="strict").splitlines():
        if line.startswith("worktree ") and line.removeprefix("worktree ") == expected:
            return True
    return False


def counts_for(gates: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "pass": sum(gate["status"] == "pass" for gate in gates),
        "failed": sum(gate["status"] == "failed" for gate in gates),
        "signaled": sum(gate["status"] == "signaled" for gate in gates),
        "not_run": sum(gate["status"] == "not-run" for gate in gates),
        "timed_out": sum(gate["status"] == "timed-out" for gate in gates),
    }


def positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


class RefusingArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Refusal(f"argument error: {message}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = RefusingArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--commit", required=True, help="commit or revision to materialize")
    parser.add_argument("--out", required=True, help="new artifact path (must not exist)")
    parser.add_argument(
        "--timeout-seconds",
        type=positive_integer,
        default=600,
        help="per-gate timeout (default: 600)",
    )
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments in (["-h"], ["--help"]):
        parser.print_help()
        raise SystemExit(0)
    return parser.parse_args(arguments)


def build(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    started_at = utc_now()
    destination = Path(os.path.abspath(args.out))
    if destination.name in {"", ".", ".."}:
        raise Refusal(f"invalid artifact destination: {destination}")
    destination_parent_fd = open_directory_without_symlinks(destination.parent)
    os.close(destination_parent_fd)

    top = run_command(["git", "rev-parse", "--show-toplevel"], cwd=Path.cwd())
    repo = Path(top.stdout.decode("utf-8", errors="strict").strip()).resolve(strict=True)
    commit = resolve_commit(repo, args.commit)
    generator_blob_sha = verify_generator_binding(repo, commit)
    workflow_blob_sha = regular_blob_sha(repo, commit, WORKFLOW_PATH)
    refuse_gitlinks_and_active_filters(repo, commit)

    temporary_root = Path(tempfile.mkdtemp(prefix="review-evidence-"))
    worktree = temporary_root / "worktree"
    child_home = temporary_root / "home"
    child_temp = temporary_root / "tmp"
    child_home.mkdir(mode=0o700)
    child_temp.mkdir(mode=0o700)
    materialized = False
    cleanup_failure: Refusal | None = None
    cleanup_recovery: str | None = None
    build_failure: BaseException | None = None
    artifact: dict[str, Any] | None = None
    try:
        try:
            materialize(repo, commit, worktree)
            materialized = True
        except Refusal:
            materialized = worktree_is_registered(repo, worktree)
            raise
        try:
            destination.relative_to(worktree)
        except ValueError:
            pass
        else:
            raise Refusal("artifact destination must not lie inside the materialized tree")
        workflow = load_workflow(worktree / WORKFLOW_PATH)
        gates, coverage = collect_workflow(
            repo,
            commit,
            worktree,
            workflow,
            environment=child_environment(child_home, child_temp),
            timeout_seconds=args.timeout_seconds,
        )
        artifact = {
            "schema_version": 1,
            "generator": {
                "path": GENERATOR_PATH,
                "blob_sha": generator_blob_sha,
                "argv": list(sys.argv),
            },
            "target": {
                "commit": commit,
                "workflow_path": WORKFLOW_PATH,
                "workflow_blob_sha": workflow_blob_sha,
                "materialization": MATERIALIZATION,
            },
            "run": {
                "started_at": started_at,
                "finished_at": "",
                "timeout_seconds": args.timeout_seconds,
                "counts": counts_for(gates),
            },
            "gates": gates,
            "coverage_limits": coverage,
        }
    except BaseException as exc:  # preserve the primary failure until cleanup is known
        build_failure = exc
    finally:
        if materialized:
            try:
                remove_materialized_worktree(repo, worktree)
            except Refusal as exc:
                cleanup_failure = exc
                cleanup_recovery = recovery_worktree_command(repo, worktree)
        if cleanup_failure is None:
            try:
                shutil.rmtree(temporary_root)
            except OSError as exc:
                cleanup_failure = Refusal(f"temporary-root cleanup failed: {exc}")
                cleanup_recovery = f"rm -rf -- {temporary_root}"
    if cleanup_failure is not None:
        raise Refusal(f"cleanup failed: {cleanup_failure}\nRecovery: {cleanup_recovery}")
    if build_failure is not None:
        raise build_failure
    if artifact is None:
        raise Refusal("internal error: artifact assembly did not complete")
    artifact["run"]["finished_at"] = utc_now()
    return artifact, destination


def report_publication_error(exc: PublicationError) -> None:
    failure = exc.failure
    print(f"REFUSAL: publication failed at {failure.step}: {failure.detail}", file=sys.stderr)
    if failure.committed:
        print(
            "REFUSAL: destination contains the complete artifact; finalization or durability failed",
            file=sys.stderr,
        )
    if failure.temp_path is not None:
        print(f"Recovery: rm -- {failure.temp_path}", file=sys.stderr)


def main() -> int:
    try:
        args = parse_args()
        artifact, destination = build(args)
        payload = (json.dumps(artifact, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        publish_atomic(destination, payload)
    except PublicationError as exc:
        report_publication_error(exc)
        return 3
    except Refusal as exc:
        print(f"REFUSAL: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001 - internal errors fail closed
        print(f"REFUSAL: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    counts = artifact["run"]["counts"]
    return 0 if counts["pass"] == len(artifact["gates"]) else 2


if __name__ == "__main__":
    sys.exit(main())
