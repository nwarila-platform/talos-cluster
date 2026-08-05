#!/usr/bin/env python3
"""Adversarial self-test for build-review-evidence.py."""

from __future__ import annotations

import base64
import contextlib
from dataclasses import dataclass
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts/build-review-evidence.py"
PYTHON = Path(sys.executable).resolve()
GIT = Path(shutil.which("git") or "git").resolve()
STATUSES = frozenset({"pass", "failed", "signaled", "not-run", "timed-out"})
REASON_CODES = frozenset(
    {
        "outside-grammar",
        "outside-guard-family",
        "step-key-not-allowlisted",
        "job-context-not-allowlisted",
        "workflow-context-not-allowlisted",
        "duplicate-yaml-key",
        "path-not-tracked-regular-blob",
        "path-escapes-root",
        "interpreter-absent",
        "gate-timed-out",
        "gate-signaled",
        "gate-nonzero-exit",
    }
)


def load_helper():
    spec = importlib.util.spec_from_file_location("_build_review_evidence", TOOL)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


helper = load_helper()


CASES: list[tuple[str, Callable[[Path], None]]] = []


def case(name: str):
    def register(function: Callable[[Path], None]):
        CASES.append((name, function))
        return function

    return register


def run(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        list(argv),
        cwd=cwd,
        env=dict(env) if env is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {argv!r}\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )
    return completed


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return run([str(GIT), *args], cwd=repo, check=check)


def write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def default_workflow(steps: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": "Fixture Validate",
        "on": {"pull_request": None},
        "permissions": {"contents": "read"},
        "jobs": {
            "fixture": {
                "name": "Fixture",
                "runs-on": "ubuntu-latest",
                "steps": steps,
            }
        },
    }


def initialize_repo(
    root: Path,
    *,
    steps: list[dict[str, Any]] | None = None,
    scripts: Mapping[str, str | bytes] | None = None,
    workflow: Mapping[str, Any] | None = None,
    raw_workflow: str | None = None,
    include_generator: bool = True,
    generator_bytes: bytes | None = None,
) -> tuple[Path, str]:
    repo = root / "repo"
    repo.mkdir(parents=True)
    git(repo, "init", "--initial-branch=main")
    git(repo, "config", "user.name", "Review Evidence Selftest")
    git(repo, "config", "user.email", "selftest@example.invalid")
    if include_generator:
        write(
            repo / helper.GENERATOR_PATH,
            TOOL.read_bytes() if generator_bytes is None else generator_bytes,
        )
    selected_scripts = scripts or {"scripts/check-pass.py": 'print("fixture-pass")\n'}
    for path, content in selected_scripts.items():
        write(repo / path, content)
    if raw_workflow is not None:
        write(repo / helper.WORKFLOW_PATH, raw_workflow)
    else:
        selected_steps = steps or [
            {"name": "pass", "run": "python3 scripts/check-pass.py"}
        ]
        document = default_workflow(selected_steps) if workflow is None else workflow
        rendered = yaml.safe_dump(document, sort_keys=False)
        if "on" in document:
            if rendered.count("'on':") != 1:
                raise AssertionError("fixture serializer did not emit exactly one quoted on key")
            rendered = rendered.replace("'on':", "on:", 1)
        write(repo / helper.WORKFLOW_PATH, rendered)
    git(repo, "add", "--all")
    git(repo, "commit", "-m", "fixture")
    commit = git(repo, "rev-parse", "HEAD").stdout.decode("ascii").strip()
    return repo, commit


def worktree_state(repo: Path) -> bytes:
    return git(repo, "worktree", "list", "--porcelain").stdout


def invoke(
    repo: Path,
    commit: str,
    out: Path,
    *,
    tool: Path = TOOL,
    timeout: int = 10,
    env_updates: Mapping[str, str] | None = None,
    assert_clean_lifecycle: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    before = worktree_state(repo)
    environment = os.environ.copy()
    if env_updates:
        environment.update(env_updates)
    completed = run(
        [
            str(PYTHON),
            str(tool),
            "--commit",
            commit,
            "--out",
            str(out),
            "--timeout-seconds",
            str(timeout),
        ],
        cwd=repo,
        env=environment,
        check=False,
    )
    if assert_clean_lifecycle and worktree_state(repo) != before:
        raise AssertionError("git worktree state changed across invocation")
    return completed


def artifact(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise AssertionError("artifact must have exactly one trailing newline")
    result = json.loads(raw)
    validate_schema(result)
    return result


def exact_keys(value: object, expected: Sequence[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or list(value) != list(expected):
        actual = list(value) if isinstance(value, dict) else type(value).__name__
        raise AssertionError(f"{where} keys: expected {list(expected)!r}, got {actual!r}")
    return value


def require_str(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise AssertionError(f"{where} must be str, got {type(value).__name__}")
    return value


def require_int(value: object, where: str) -> int:
    if type(value) is not int:
        raise AssertionError(f"{where} must be int, got {type(value).__name__}")
    return value


def validate_stream(value: object, where: str) -> None:
    stream = exact_keys(value, ["encoding", "data"], where)
    if stream["encoding"] not in {"utf-8", "base64"}:
        raise AssertionError(f"{where}.encoding is invalid")
    require_str(stream["data"], f"{where}.data")
    if stream["encoding"] == "base64":
        base64.b64decode(stream["data"], validate=True)


def validate_schema(value: object) -> None:
    top = exact_keys(
        value,
        ["schema_version", "generator", "target", "run", "gates", "coverage_limits"],
        "artifact",
    )
    if type(top["schema_version"]) is not int or top["schema_version"] != 1:
        raise AssertionError("schema_version must be integer 1")
    generator = exact_keys(top["generator"], ["path", "blob_sha", "argv"], "generator")
    if generator["path"] != helper.GENERATOR_PATH:
        raise AssertionError("generator.path is not canonical")
    if not re.fullmatch(r"[0-9a-f]{40}", require_str(generator["blob_sha"], "generator.blob_sha")):
        raise AssertionError("generator.blob_sha must be 40 lowercase hex characters")
    if not isinstance(generator["argv"], list) or not all(
        isinstance(item, str) for item in generator["argv"]
    ):
        raise AssertionError("generator.argv must be a string array")
    target = exact_keys(
        top["target"],
        ["commit", "workflow_path", "workflow_blob_sha", "materialization"],
        "target",
    )
    for key in target:
        require_str(target[key], f"target.{key}")
    for key in ("commit", "workflow_blob_sha"):
        if not re.fullmatch(r"[0-9a-f]{40}", target[key]):
            raise AssertionError(f"target.{key} must be 40 lowercase hex characters")
    if target["workflow_path"] != helper.WORKFLOW_PATH:
        raise AssertionError("target.workflow_path is not canonical")
    if target["materialization"] != helper.MATERIALIZATION:
        raise AssertionError("target.materialization is not canonical")
    run_object = exact_keys(
        top["run"],
        ["started_at", "finished_at", "timeout_seconds", "counts"],
        "run",
    )
    timestamp_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
    for key in ("started_at", "finished_at"):
        if not re.fullmatch(timestamp_pattern, require_str(run_object[key], f"run.{key}")):
            raise AssertionError(f"run.{key} is not second-precision UTC ISO-8601")
    if require_int(run_object["timeout_seconds"], "run.timeout_seconds") <= 0:
        raise AssertionError("run.timeout_seconds must be positive")
    counts = exact_keys(
        run_object["counts"],
        ["pass", "failed", "signaled", "not_run", "timed_out"],
        "run.counts",
    )
    for key, count in counts.items():
        if require_int(count, f"run.counts.{key}") < 0:
            raise AssertionError("counts cannot be negative")
    gates = top["gates"]
    if not isinstance(gates, list):
        raise AssertionError("gates must be a list")
    observed = {status: 0 for status in STATUSES}
    for index, value_gate in enumerate(gates):
        gate = exact_keys(
            value_gate,
            [
                "job",
                "step_name",
                "run_body",
                "status",
                "reason",
                "argv",
                "resolved_interpreter",
                "exit_status",
                "signal",
                "reason_code",
                "stdout",
                "stderr",
            ],
            f"gates[{index}]",
        )
        require_str(gate["job"], f"gates[{index}].job")
        if gate["step_name"] is not None:
            require_str(gate["step_name"], f"gates[{index}].step_name")
        require_str(gate["run_body"], f"gates[{index}].run_body")
        status_value = require_str(gate["status"], f"gates[{index}].status")
        if status_value not in STATUSES:
            raise AssertionError(f"unknown status: {status_value}")
        observed[status_value] += 1
        if (gate["reason"] is None) != (status_value == "pass"):
            raise AssertionError("reason null rule violated")
        if gate["reason"] is not None:
            require_str(gate["reason"], f"gates[{index}].reason")
        if (gate["reason_code"] is None) != (status_value == "pass"):
            raise AssertionError("reason_code null rule violated")
        if gate["reason_code"] is not None and gate["reason_code"] not in REASON_CODES:
            raise AssertionError(f"unknown reason_code: {gate['reason_code']}")
        executed = status_value in {"pass", "failed", "signaled", "timed-out"}
        if executed:
            if not isinstance(gate["argv"], list) or not all(
                isinstance(item, str) for item in gate["argv"]
            ):
                raise AssertionError("executed gate argv must be a string array")
            require_str(gate["resolved_interpreter"], "resolved_interpreter")
        elif gate["argv"] is not None or gate["resolved_interpreter"] is not None:
            raise AssertionError("non-executed gate argv/interpreter must be null")
        if status_value in {"pass", "failed"}:
            require_int(gate["exit_status"], "exit_status")
        elif gate["exit_status"] is not None:
            raise AssertionError("exit_status null rule violated")
        if status_value == "signaled":
            if require_int(gate["signal"], "signal") <= 0:
                raise AssertionError("signal must be positive")
        elif gate["signal"] is not None:
            raise AssertionError("signal null rule violated")
        validate_stream(gate["stdout"], f"gates[{index}].stdout")
        validate_stream(gate["stderr"], f"gates[{index}].stderr")
    expected_counts = {
        "pass": observed["pass"],
        "failed": observed["failed"],
        "signaled": observed["signaled"],
        "not_run": observed["not-run"],
        "timed_out": observed["timed-out"],
    }
    if counts != expected_counts:
        raise AssertionError(f"counts mismatch: {counts!r} != {expected_counts!r}")

    coverage = exact_keys(
        top["coverage_limits"],
        ["ineligible_steps", "non_run_steps", "unreproduced_context", "trust_boundary"],
        "coverage_limits",
    )
    if not isinstance(coverage["ineligible_steps"], list):
        raise AssertionError("ineligible_steps must be a list")
    for index, raw_item in enumerate(coverage["ineligible_steps"]):
        item = exact_keys(
            raw_item,
            ["job", "step_name", "run_body", "reason_code", "reason"],
            f"ineligible_steps[{index}]",
        )
        require_str(item["job"], "ineligible job")
        if item["step_name"] is not None:
            require_str(item["step_name"], "ineligible step_name")
        require_str(item["run_body"], "ineligible run_body")
        if item["reason_code"] not in REASON_CODES:
            raise AssertionError("ineligible reason code outside closed enum")
        require_str(item["reason"], "ineligible reason")
    if not isinstance(coverage["non_run_steps"], list):
        raise AssertionError("non_run_steps must be a list")
    for index, raw_item in enumerate(coverage["non_run_steps"]):
        item = exact_keys(raw_item, ["job", "step_name", "uses"], f"non_run_steps[{index}]")
        require_str(item["job"], "non-run job")
        for key in ("step_name", "uses"):
            if item[key] is not None:
                require_str(item[key], f"non-run {key}")
    if not isinstance(coverage["unreproduced_context"], list):
        raise AssertionError("unreproduced_context must be a list")
    for index, raw_item in enumerate(coverage["unreproduced_context"]):
        item = exact_keys(raw_item, ["kind", "value"], f"unreproduced_context[{index}]")
        if item["kind"] not in {"runs-on", "permissions", "job-order"}:
            raise AssertionError("unreproduced_context kind is not canonical")
        require_str(item["value"], "unreproduced_context value")
    if not isinstance(coverage["trust_boundary"], list) or not all(
        isinstance(item, str) for item in coverage["trust_boundary"]
    ):
        raise AssertionError("trust_boundary must be a string array")


def stderr_text(completed: subprocess.CompletedProcess[bytes]) -> str:
    return completed.stderr.decode("utf-8", errors="replace")


def assert_refusal(
    completed: subprocess.CompletedProcess[bytes],
    out: Path,
    fragment: str,
) -> None:
    if completed.returncode != 3:
        raise AssertionError(f"expected exit 3, got {completed.returncode}: {stderr_text(completed)!r}")
    if fragment not in stderr_text(completed):
        raise AssertionError(f"missing refusal fragment {fragment!r}: {stderr_text(completed)!r}")
    if out.exists() or out.is_symlink():
        raise AssertionError(f"refusal unexpectedly created {out}")


def gate_by_name(data: Mapping[str, Any], name: str) -> dict[str, Any]:
    matches = [gate for gate in data["gates"] if gate["step_name"] == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one gate named {name!r}, got {len(matches)}")
    return matches[0]


@case("01-unresolvable-commit-refuses")
def unresolvable_commit(root: Path) -> None:
    repo, _commit = initialize_repo(root)
    out = root / "evidence.json"
    completed = invoke(repo, "does-not-exist", out)
    assert_refusal(completed, out, "commit does not resolve: does-not-exist")


@case("01b-nonpositive-timeout-refuses-without-artifact")
def nonpositive_timeout(root: Path) -> None:
    repo, commit = initialize_repo(root)
    out = root / "evidence.json"
    completed = run(
        [
            str(PYTHON),
            str(TOOL),
            "--commit",
            commit,
            "--out",
            str(out),
            "--timeout-seconds",
            "0",
        ],
        cwd=repo,
        check=False,
    )
    assert_refusal(completed, out, "argument error: argument --timeout-seconds: must be a positive integer")


@case("02-existing-destination-is-unchanged")
def existing_destination(root: Path) -> None:
    repo, commit = initialize_repo(root)
    out = root / "evidence.json"
    original = b"pre-existing destination\x00"
    out.write_bytes(original)
    completed = invoke(repo, commit, out)
    if completed.returncode != 3 or "destination already exists" not in stderr_text(completed):
        raise AssertionError((completed.returncode, stderr_text(completed)))
    if out.read_bytes() != original:
        raise AssertionError("pre-existing destination bytes changed")


@case("03-destination-symlink-is-not-followed")
def destination_symlink(root: Path) -> None:
    repo, commit = initialize_repo(root)
    target = root / "target"
    original = b"symlink target bytes"
    target.write_bytes(original)
    out = root / "evidence.json"
    out.symlink_to(target)
    completed = invoke(repo, commit, out)
    if completed.returncode != 3 or "destination already exists" not in stderr_text(completed):
        raise AssertionError((completed.returncode, stderr_text(completed)))
    if not out.is_symlink() or target.read_bytes() != original:
        raise AssertionError("destination symlink or target changed")


@case("03b-symlinked-parent-is-refused")
def symlinked_parent(root: Path) -> None:
    repo, commit = initialize_repo(root)
    real_parent = root / "real-parent"
    real_parent.mkdir()
    linked_parent = root / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    out = linked_parent / "evidence.json"
    completed = invoke(repo, commit, out)
    assert_refusal(completed, out, "destination parent must exist and contain no symlink")
    if (real_parent / "evidence.json").exists():
        raise AssertionError("tool wrote through the symlinked parent")


class RacingOps(helper.PublicationOps):
    def __init__(self, competitor: Path, ready: threading.Event, linked: threading.Event) -> None:
        self.competitor = competitor
        self.ready = ready
        self.linked = linked

    def link(self, source: str, destination: str, directory_fd: int) -> None:
        self.ready.set()
        if not self.linked.wait(timeout=5):
            raise OSError(errno.ETIMEDOUT, "competitor did not publish")
        super().link(source, destination, directory_fd)


@case("04-publication-race-and-observer-see-only-complete-bytes")
def publication_race(root: Path) -> None:
    initialize_repo(root)
    out = root / "evidence.json"
    tool_payload = b"tool-complete:" + (b"t" * 1_000_000)
    competitor_payload = b"competitor-complete:" + (b"c" * 1_000_000)
    competitor = root / "competitor.tmp"
    competitor.write_bytes(competitor_payload)
    ready = threading.Event()
    linked = threading.Event()
    stop = threading.Event()
    observations: list[bytes] = []

    def competitor_publish() -> None:
        if not ready.wait(timeout=5):
            return
        os.link(competitor, out)
        linked.set()

    def observe() -> None:
        while not stop.is_set():
            try:
                observations.append(out.read_bytes())
            except FileNotFoundError:
                pass

    competitor_thread = threading.Thread(target=competitor_publish)
    observer_thread = threading.Thread(target=observe)
    competitor_thread.start()
    observer_thread.start()
    try:
        try:
            helper.publish_atomic(
                out,
                tool_payload,
                operations=RacingOps(competitor, ready, linked),
            )
        except helper.PublicationError as exc:
            if exc.failure.step != "link" or "destination already exists" not in exc.failure.detail:
                raise AssertionError(exc.failure) from exc
        else:
            raise AssertionError("competing creator did not win publication")
    finally:
        stop.set()
        competitor_thread.join(timeout=5)
        observer_thread.join(timeout=5)
    if out.read_bytes() != competitor_payload:
        raise AssertionError("racing destination was not retained byte-for-byte")
    if any(item != competitor_payload for item in observations):
        raise AssertionError("observer saw partial or unexpected destination bytes")


class FailingOps(helper.PublicationOps):
    def __init__(self, step: str, *, persistent_unlink: bool = False) -> None:
        self.step = step
        self.persistent_unlink = persistent_unlink
        self.unlink_attempts = 0

    def create_temp(self, name: str, directory_fd: int) -> int:
        if self.step == "temp create":
            raise OSError(errno.EIO, "injected temp create failure")
        return super().create_temp(name, directory_fd)

    def fsync_file(self, file_fd: int) -> None:
        if self.step == "file fsync":
            raise OSError(errno.EIO, "injected file fsync failure")
        super().fsync_file(file_fd)

    def link(self, source: str, destination: str, directory_fd: int) -> None:
        if self.step == "link":
            raise OSError(errno.EIO, "injected link failure")
        super().link(source, destination, directory_fd)

    def unlink(self, name: str, directory_fd: int) -> None:
        self.unlink_attempts += 1
        if self.step == "temp unlink" and (self.persistent_unlink or self.unlink_attempts == 1):
            raise OSError(errno.EIO, "injected temp unlink failure")
        super().unlink(name, directory_fd)

    def fsync_directory(self, directory_fd: int) -> None:
        if self.step == "directory fsync":
            raise OSError(errno.EIO, "injected directory fsync failure")
        super().fsync_directory(directory_fd)


def temp_files(root: Path, destination: Path) -> list[Path]:
    return list(root.glob(f".{destination.name}.tmp-*"))


@case("04b-publication-failure-state-matrix")
def publication_failure_matrix(root: Path) -> None:
    initialize_repo(root)
    payload = b'{"complete":true}\n'
    for step in ("temp create", "file fsync", "link", "temp unlink", "directory fsync"):
        directory = root / step.replace(" ", "-")
        directory.mkdir()
        out = directory / "evidence.json"
        operations = FailingOps(step)
        try:
            helper.publish_atomic(out, payload, operations=operations)
        except helper.PublicationError as exc:
            if exc.failure.step != step:
                raise AssertionError(f"{step}: reported {exc.failure.step}") from exc
        else:
            raise AssertionError(f"{step}: injected failure did not bite")
        if step in {"temp unlink", "directory fsync"}:
            if out.read_bytes() != payload:
                raise AssertionError(f"{step}: complete destination was not retained")
        elif out.exists() or out.is_symlink():
            raise AssertionError(f"{step}: destination should remain absent")
        if temp_files(directory, out):
            raise AssertionError(f"{step}: temporary file survived")


@case("04d-temp-cleanup-retries-and-names-recovery")
def temp_cleanup_proof(root: Path) -> None:
    initialize_repo(root)
    payload = b"complete artifact"
    retry_directory = root / "retry"
    retry_directory.mkdir()
    retry_out = retry_directory / "evidence.json"
    retry_ops = FailingOps("temp unlink")
    try:
        helper.publish_atomic(retry_out, payload, operations=retry_ops)
    except helper.PublicationError as exc:
        if exc.failure.temp_path is not None:
            raise AssertionError("successful retry reported a surviving temp") from exc
    else:
        raise AssertionError("initial unlink failure was not reported")
    if retry_ops.unlink_attempts != 2 or temp_files(retry_directory, retry_out):
        raise AssertionError("best-effort unlink was not retried exactly once")
    if retry_out.read_bytes() != payload:
        raise AssertionError("committed destination was not retained after retry")

    persistent_directory = root / "persistent"
    persistent_directory.mkdir()
    persistent_out = persistent_directory / "evidence.json"
    persistent_ops = FailingOps("temp unlink", persistent_unlink=True)
    try:
        helper.publish_atomic(persistent_out, payload, operations=persistent_ops)
    except helper.PublicationError as exc:
        failure = exc.failure
    else:
        raise AssertionError("persistent unlink failure was not reported")
    survivors = temp_files(persistent_directory, persistent_out)
    if persistent_ops.unlink_attempts != 2 or len(survivors) != 1:
        raise AssertionError("persistent failure did not retain one named unique temp")
    if failure.temp_path != survivors[0] or failure.step != "temp unlink":
        raise AssertionError(failure)
    output = io.StringIO()
    with contextlib.redirect_stderr(output):
        helper.report_publication_error(helper.PublicationError(failure))
    if f"Recovery: rm -- {survivors[0]}" not in output.getvalue():
        raise AssertionError("recovery command did not name the surviving temp")
    if persistent_out.read_bytes() != payload:
        raise AssertionError("complete destination was not retained")
    survivors[0].unlink()


@case("05-nonzero-gate-runs-exactly-once-and-captures-streams")
def nonzero_exactly_once(root: Path) -> None:
    counter = root / "counter"
    script = (
        "from pathlib import Path\n"
        "import sys\n"
        f"p = Path({str(counter)!r})\n"
        "p.write_text(str(int(p.read_text()) + 1) if p.exists() else '1')\n"
        "sys.stdout.write('stdout-seven\\n')\n"
        "sys.stderr.write('stderr-seven\\n')\n"
        "raise SystemExit(7)\n"
    )
    repo, commit = initialize_repo(root, scripts={"scripts/check-once.py": script}, steps=[{"name": "once", "run": "python3 scripts/check-once.py"}])
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    if completed.returncode != 2:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    data = artifact(out)
    gate = gate_by_name(data, "once")
    if gate["status"] != "failed" or gate["exit_status"] != 7 or gate["reason_code"] != "gate-nonzero-exit":
        raise AssertionError(gate)
    if gate["stdout"] != {"encoding": "utf-8", "data": "stdout-seven\n"}:
        raise AssertionError(gate["stdout"])
    if gate["stderr"] != {"encoding": "utf-8", "data": "stderr-seven\n"}:
        raise AssertionError(gate["stderr"])
    if counter.read_text(encoding="utf-8") != "1":
        raise AssertionError("gate did not execute exactly once")


@case("06-all-interpreter-preflights-flip-from-absent-to-pass")
def interpreter_preflight_matrix(root: Path) -> None:
    forms = [
        ("python", "scripts/check-python.py", 'print("python-ok")\n', PYTHON),
        ("python3", "scripts/check-python3.py", 'print("python3-ok")\n', PYTHON),
        ("bash", "scripts/check-bash.sh", 'printf "bash-ok\\n"\n', Path("/usr/bin/bash")),
    ]
    for interpreter, script_path, content, executable in forms:
        fixture_root = root / interpreter
        fixture_root.mkdir()
        repo, commit = initialize_repo(
            fixture_root,
            scripts={script_path: content},
            steps=[{"name": interpreter, "run": f"{interpreter} {script_path}"}],
        )
        command_bin = fixture_root / "bin"
        command_bin.mkdir()
        (command_bin / "git").symlink_to(GIT)
        absent_out = fixture_root / "absent.json"
        absent = invoke(
            repo,
            commit,
            absent_out,
            env_updates={"PATH": str(command_bin)},
        )
        if absent.returncode != 2:
            raise AssertionError((interpreter, absent.returncode, stderr_text(absent)))
        absent_gate = gate_by_name(artifact(absent_out), interpreter)
        if absent_gate["status"] != "not-run" or absent_gate["reason_code"] != "interpreter-absent":
            raise AssertionError(absent_gate)
        if absent_gate["resolved_interpreter"] is not None:
            raise AssertionError("absent interpreter must be recorded as null")

        (command_bin / interpreter).symlink_to(executable)
        present_out = fixture_root / "present.json"
        present = invoke(
            repo,
            commit,
            present_out,
            env_updates={"PATH": str(command_bin)},
        )
        if present.returncode != 0:
            raise AssertionError((interpreter, present.returncode, stderr_text(present)))
        present_gate = gate_by_name(artifact(present_out), interpreter)
        if present_gate["status"] != "pass" or not present_gate["resolved_interpreter"]:
            raise AssertionError(present_gate)


@case("07-workflow-added-step-is-derived-and-executed")
def derived_step(root: Path) -> None:
    counters = [root / "first", root / "added"]
    scripts: dict[str, str] = {}
    steps: list[dict[str, str]] = []
    for index, counter in enumerate(counters):
        name = "first" if index == 0 else "added-later"
        path = f"scripts/check-{name}.py"
        scripts[path] = f"from pathlib import Path\nPath({str(counter)!r}).write_text('ran')\n"
        steps.append({"name": name, "run": f"python3 {path}"})
    repo, commit = initialize_repo(root, scripts=scripts, steps=steps)
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    if completed.returncode != 0:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    data = artifact(out)
    if [gate["step_name"] for gate in data["gates"]] != ["first", "added-later"]:
        raise AssertionError("workflow order or derived step list changed")
    if not all(counter.read_text(encoding="utf-8") == "ran" for counter in counters):
        raise AssertionError("a workflow-derived step did not execute")


@case("08-masked-failure-pipeline-is-never-executed")
def pipeline_never_executes(root: Path) -> None:
    counter = root / "pipeline-counter"
    marker = root / "pipeline-marker"
    left = (
        "from pathlib import Path\n"
        f"p=Path({str(counter)!r})\n"
        "p.write_text('left')\n"
        "raise SystemExit(9)\n"
    )
    right = f"from pathlib import Path\nPath({str(marker)!r}).write_text('right')\n"
    body = "python3 scripts/check-left.py | python3 scripts/check-right.py"
    repo, commit = initialize_repo(
        root,
        scripts={"scripts/check-left.py": left, "scripts/check-right.py": right},
        steps=[{"name": "pipeline", "run": body}],
    )
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    if completed.returncode != 2:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    gate = gate_by_name(artifact(out), "pipeline")
    if gate["status"] != "not-run" or gate["reason_code"] != "outside-grammar":
        raise AssertionError(gate)
    if counter.exists() or marker.exists():
        raise AssertionError("pipeline canary fired")
    if gate["stdout"]["data"] or gate["stderr"]["data"]:
        raise AssertionError("ineligible gate unexpectedly captured streams")


@case("09-closed-grammar-rejects-hostile-bodies-and-symlink")
def closed_grammar_negatives(root: Path) -> None:
    counter = root / "grammar-counter"
    canary = (
        "from pathlib import Path\n"
        f"p=Path({str(counter)!r})\n"
        "p.write_text(p.read_text() + 'x' if p.exists() else 'x')\n"
    )
    bodies = {
        "sudo": "sudo python3 scripts/check-canary.py",
        "heredoc": "python3 - <<'PY'\nprint('x')\nPY",
        "redirect": "python3 scripts/check-canary.py > canary",
        "comment": "python3 scripts/check-canary.py # run",
        "tilde": "python3 ~/scripts/check-canary.py",
        "cr": "python3 scripts/check-canary.py\r",
        "leading-space": " python3 scripts/check-canary.py",
        "trailing-space": "python3 scripts/check-canary.py ",
        "unicode": "python3 scripts/check-canary.py --café",
        "multiline-comment": "# comment\npython3 scripts/check-canary.py",
        "dotdot": "python3 scripts/../../etc/x.py",
        "absolute": "python3 /tmp/check-canary.py",
        "symlink": "python3 scripts/check-link.py",
    }
    scripts: dict[str, str] = {"scripts/check-canary.py": canary}
    steps = [{"name": name, "run": body} for name, body in bodies.items()]
    repo, _commit = initialize_repo(root, scripts=scripts, steps=steps)
    (repo / "scripts/check-link.py").symlink_to("check-canary.py")
    git(repo, "add", "scripts/check-link.py")
    git(repo, "commit", "-m", "add tracked symlink")
    commit = git(repo, "rev-parse", "HEAD").stdout.decode("ascii").strip()
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    if completed.returncode != 2:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    data = artifact(out)
    for name in bodies:
        gate = gate_by_name(data, name)
        expected = "path-not-tracked-regular-blob" if name == "symlink" else "outside-grammar"
        if gate["status"] != "not-run" or gate["reason_code"] != expected:
            raise AssertionError((name, gate))
    if counter.exists():
        raise AssertionError("a hostile-body canary fired")


@case("10-generated-closed-command-classifier-matrix")
def classifier_matrix(_root: Path) -> None:
    accepted = []
    for interpreter, suffix in (("python", ".py"), ("python3", ".py"), ("bash", ".sh")):
        accepted.extend(
            [
                f"{interpreter} scripts/check-a{suffix}",
                f"{interpreter} scripts/dir/check-a_1.test-{suffix.lstrip('.')}{suffix}",
                f"{interpreter} scripts/check-a{suffix} --flag --two-flags",
            ]
        )
    for body in accepted:
        if helper.parse_command_body(body) is None:
            raise AssertionError(f"valid production rejected: {body!r}")
        if helper.parse_command_body(body + "\n") is None:
            raise AssertionError(f"single trailing LF rejected: {body!r}")

    mutations: set[str] = set()
    seed = "python3 scripts/check-a.py --flag"
    mutations.update(
        {
            "" + seed + "\n\n",
            " " + seed,
            seed + " ",
            seed.replace(" ", "  ", 1),
            seed.replace("scripts/", "/scripts/"),
            seed.replace("scripts/", "scripts/../"),
            seed.replace("check-a.py", ".hidden.py"),
            seed.replace("check-a.py", "x;true.py"),
            seed.replace("--flag", "flag"),
            seed.replace("--flag", "--Flag"),
            seed.replace("--flag", "--flag=value"),
            seed.replace("--flag", "--flag#x"),
            seed.replace("--flag", "--fläg"),
            seed.replace("check-a.py", "check-a.sh"),
            "bash scripts/check-a.py",
            "python3 scripts/check-a.sh",
            "ruby scripts/check-a.py",
        }
    )
    for body in mutations:
        if helper.parse_command_body(body) is not None:
            raise AssertionError(f"invalid production accepted: {body!r}")


@case("11-requested-commit-materialization-excludes-head-and-residue")
def commit_materialization(root: Path) -> None:
    marker_a = os.urandom(12).hex()
    marker_b = os.urandom(12).hex()
    marker_dirty = os.urandom(12).hex()
    repo, commit_a = initialize_repo(
        root,
        scripts={"scripts/check-marker.py": f"print({marker_a!r})\n"},
        steps=[{"name": "marker", "run": "python3 scripts/check-marker.py"}],
    )
    write(repo / "scripts/check-marker.py", f"print({marker_b!r})\n")
    write(repo / ".gitignore", "residue\n")
    git(repo, "add", "scripts/check-marker.py", ".gitignore")
    git(repo, "commit", "-m", "different head marker")
    write(repo / "scripts/check-marker.py", f"print({marker_dirty!r})\n")
    write(repo / "residue", "ignored")
    out = root / "evidence.json"
    completed = invoke(repo, commit_a, out)
    if completed.returncode != 0:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    data = artifact(out)
    output = gate_by_name(data, "marker")["stdout"]["data"]
    if output != marker_a + "\n" or marker_b in output or marker_dirty in output:
        raise AssertionError(f"capture did not come solely from requested commit: {output!r}")
    if data["target"]["commit"] != commit_a:
        raise AssertionError("target commit provenance mismatch")


@case("12-generator-self-binding-refuses-dirty-absent-and-different")
def generator_self_binding(root: Path) -> None:
    clean_root = root / "dirty"
    clean_root.mkdir()
    repo, commit = initialize_repo(clean_root)
    dirty_tool = clean_root / "dirty-generator.py"
    dirty_tool.write_bytes(TOOL.read_bytes() + b"\n# dirty executing bytes\n")
    out = clean_root / "evidence.json"
    completed = invoke(repo, commit, out, tool=dirty_tool)
    assert_refusal(
        completed,
        out,
        "generator binding mismatch: source read at __file__ at check time does not match "
        f"{commit}:{helper.GENERATOR_PATH}",
    )

    absent_root = root / "absent"
    absent_root.mkdir()
    absent_repo, absent_commit = initialize_repo(absent_root, include_generator=False)
    absent_out = absent_root / "evidence.json"
    absent = invoke(absent_repo, absent_commit, absent_out)
    assert_refusal(absent, absent_out, "target path is absent: scripts/build-review-evidence.py")

    different_root = root / "different"
    different_root.mkdir()
    different_repo, different_commit = initialize_repo(
        different_root,
        generator_bytes=TOOL.read_bytes() + b"\n# committed mismatch\n",
    )
    different_out = different_root / "evidence.json"
    different = invoke(different_repo, different_commit, different_out)
    assert_refusal(
        different,
        different_out,
        "generator binding mismatch: source read at __file__ at check time does not match "
        f"{different_commit}:{helper.GENERATOR_PATH}",
    )


@case("13-invalid-utf8-and-nul-streams-use-base64")
def byte_preservation(root: Path) -> None:
    stdout = b"stdout\x00\xff"
    stderr = b"stderr\x00\xfe"
    script = (
        "import sys\n"
        f"sys.stdout.buffer.write({stdout!r})\n"
        f"sys.stderr.buffer.write({stderr!r})\n"
    )
    repo, commit = initialize_repo(
        root,
        scripts={"scripts/check-bytes.py": script},
        steps=[{"name": "bytes", "run": "python3 scripts/check-bytes.py"}],
    )
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    if completed.returncode != 0:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    gate = gate_by_name(artifact(out), "bytes")
    for key, expected in (("stdout", stdout), ("stderr", stderr)):
        if gate[key]["encoding"] != "base64":
            raise AssertionError(f"{key} did not use base64")
        if base64.b64decode(gate[key]["data"]) != expected:
            raise AssertionError(f"{key} bytes changed")


@case("14-timeout-reaps-the-process-group")
def timeout_process_group(root: Path) -> None:
    child_pid = root / "child.pid"
    canary = root / "timeout-canary"
    child_code = f"import time; from pathlib import Path; time.sleep(5); Path({str(canary)!r}).write_text('escaped')"
    script = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        f"Path({str(child_pid)!r}).write_text(str(child.pid))\n"
        "print('before-timeout', flush=True)\n"
        "time.sleep(10)\n"
    )
    repo, commit = initialize_repo(
        root,
        scripts={"scripts/check-timeout.py": script},
        steps=[{"name": "timeout", "run": "python3 scripts/check-timeout.py"}],
    )
    out = root / "evidence.json"
    completed = invoke(repo, commit, out, timeout=1)
    if completed.returncode != 2:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    gate = gate_by_name(artifact(out), "timeout")
    if gate["status"] != "timed-out" or gate["reason_code"] != "gate-timed-out":
        raise AssertionError(gate)
    if gate["exit_status"] is not None or gate["signal"] is not None:
        raise AssertionError("timeout null rules violated")
    if gate["stdout"]["data"] != "before-timeout\n":
        raise AssertionError("timeout output was not captured")
    pid = int(child_pid.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        raise AssertionError(f"timed-out descendant still exists: {pid}")
    if canary.exists():
        raise AssertionError("timed-out descendant escaped process-group cleanup")


@case("14b-signal-termination-has-a-distinct-status")
def signal_status(root: Path) -> None:
    script = (
        "import os, signal, sys\n"
        "sys.stdout.write('before-signal\\n')\n"
        "sys.stdout.flush()\n"
        "os.kill(os.getpid(), signal.SIGTERM)\n"
    )
    repo, commit = initialize_repo(
        root,
        scripts={"scripts/check-signal.py": script},
        steps=[{"name": "signal", "run": "python3 scripts/check-signal.py"}],
    )
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    if completed.returncode != 2:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    gate = gate_by_name(artifact(out), "signal")
    if gate["status"] != "signaled" or gate["signal"] != signal.SIGTERM:
        raise AssertionError(gate)
    if gate["exit_status"] is not None or gate["reason_code"] != "gate-signaled":
        raise AssertionError("signal null/reason rules violated")


def counter_script(path: Path, *, shell: bool = False) -> str:
    if shell:
        return f"printf x >> {path}\n"
    return (
        "from pathlib import Path\n"
        f"p=Path({str(path)!r})\n"
        "p.write_text(p.read_text() + 'x' if p.exists() else 'x')\n"
    )


@case("14c-generated-role-family-matrix-bites")
def role_family_matrix(root: Path) -> None:
    accepted_forms = [
        ("selftest", "python3 scripts/probe.selftest.py", "scripts/probe.selftest.py", False),
        ("check-python", "python scripts/check-python.py", "scripts/check-python.py", False),
        ("check-python3", "python3 scripts/check-python3.py", "scripts/check-python3.py", False),
        ("check-bash", "bash scripts/check-bash.sh", "scripts/check-bash.sh", True),
        ("renderer", "python3 scripts/render-probe.py --check", "scripts/render-probe.py", False),
        ("exception", "python3 scripts/rendered-inventory.py --all-paths", "scripts/rendered-inventory.py", False),
    ]
    rejected_forms = [
        ("nested-exception", "python3 scripts/nested/rendered-inventory.py --all-paths", "scripts/nested/rendered-inventory.py", False),
        *[
            (name, f"bash scripts/{name}.sh", f"scripts/{name}.sh", True)
            for name in ("apply", "bootstrap", "upgrade", "generate", "s3-sync", "onboard-tenant")
        ],
        ("novel", "python3 scripts/audit-probe.py", "scripts/audit-probe.py", False),
        ("renderer-write-one", "python3 scripts/render-write-one.py", "scripts/render-write-one.py", False),
        ("renderer-write-two", "python3 scripts/render-write-two.py", "scripts/render-write-two.py", False),
    ]
    scripts: dict[str, str] = {}
    steps: list[dict[str, str]] = []
    counters: dict[str, Path] = {}
    for name, body, path, is_shell in [*accepted_forms, *rejected_forms]:
        counter = root / f"counter-{name}"
        counters[name] = counter
        scripts[path] = counter_script(counter, shell=is_shell)
        steps.append({"name": name, "run": body})
    repo, commit = initialize_repo(root, scripts=scripts, steps=steps)
    command_bin = root / "bin"
    command_bin.mkdir()
    (command_bin / "git").symlink_to(GIT)
    (command_bin / "python").symlink_to(PYTHON)
    (command_bin / "python3").symlink_to(PYTHON)
    (command_bin / "bash").symlink_to("/usr/bin/bash")
    out = root / "evidence.json"
    completed = invoke(repo, commit, out, env_updates={"PATH": str(command_bin)})
    if completed.returncode != 2:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    data = artifact(out)
    for name, _body, _path, _shell in accepted_forms:
        gate = gate_by_name(data, name)
        if gate["status"] != "pass" or counters[name].read_text(encoding="utf-8") != "x":
            raise AssertionError((name, gate))
    for name, _body, _path, _shell in rejected_forms:
        gate = gate_by_name(data, name)
        if gate["status"] != "not-run" or gate["reason_code"] != "outside-guard-family":
            raise AssertionError((name, gate))
        if counters[name].exists():
            raise AssertionError(f"off-family canary fired: {name}")


@case("14d-gitlink-refusal-is-independent")
def gitlink_refusal(root: Path) -> None:
    repo, initial = initialize_repo(root)
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{initial},vendor/submodule")
    git(repo, "commit", "-m", "add gitlink")
    commit = git(repo, "rev-parse", "HEAD").stdout.decode("ascii").strip()
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    assert_refusal(completed, out, "gitlink/submodule entry is not allowed: vendor/submodule")


@case("14d-active-checkout-filter-refusal-is-independent")
def active_filter_refusal(root: Path) -> None:
    repo, _initial = initialize_repo(root)
    write(repo / ".gitattributes", "scripts/*.py filter=selftest-filter\n")
    git(repo, "add", ".gitattributes")
    git(repo, "commit", "-m", "add filter attribute")
    git(repo, "config", "filter.selftest-filter.smudge", "cat")
    commit = git(repo, "rev-parse", "HEAD").stdout.decode("ascii").strip()
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    assert_refusal(completed, out, "active checkout filter is not allowed: selftest-filter")


def workflow_with_context(
    *,
    workflow_update: Mapping[str, Any] | None = None,
    job_update: Mapping[str, Any] | None = None,
    step_update: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    step = {"name": "canary", "run": "python3 scripts/check-canary.py"}
    if step_update:
        step.update(step_update)
    document = default_workflow([step])
    if workflow_update:
        document.update(workflow_update)
    if job_update:
        document["jobs"]["fixture"].update(job_update)
    return document


def duplicate_workflow(level: str) -> str:
    ordinary_job = (
        "  fixture:\n"
        "    name: Fixture\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: canary\n"
        "        run: python3 scripts/check-canary.py\n"
    )
    if level == "workflow":
        return (
            "name: one\nname: two\non: {pull_request: null}\n"
            "permissions: {contents: read}\njobs:\n" + ordinary_job
        )
    if level == "on":
        return (
            "name: Fixture Validate\non:\n  pull_request: null\n  pull_request: null\n"
            "permissions: {contents: read}\njobs:\n" + ordinary_job
        )
    if level == "permissions":
        return (
            "name: Fixture Validate\non: {pull_request: null}\npermissions:\n"
            "  contents: read\n  contents: write\njobs:\n" + ordinary_job
        )
    if level == "jobs":
        return (
            "name: Fixture Validate\non: {pull_request: null}\npermissions: {contents: read}\n"
            "jobs:\n  fixture:\n    name: Fixture\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - name: canary\n        run: python3 scripts/check-canary.py\n"
            "  fixture:\n    name: Fixture\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - name: canary\n        run: python3 scripts/check-canary.py\n"
        )
    if level == "job":
        return (
            "name: Fixture Validate\non: {pull_request: null}\npermissions: {contents: read}\n"
            "jobs:\n  fixture:\n    name: Fixture\n    runs-on: ubuntu-latest\n"
            "    runs-on: ubuntu-22.04\n    steps:\n      - name: canary\n"
            "        run: python3 scripts/check-canary.py\n"
        )
    if level == "step":
        return (
            "name: Fixture Validate\non: {pull_request: null}\npermissions: {contents: read}\n"
            "jobs:\n  fixture:\n    name: Fixture\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - name: canary\n        name: duplicate\n"
            "        run: python3 scripts/check-canary.py\n"
        )
    raise AssertionError(f"unknown duplicate level: {level}")


@case("14e-workflow-job-and-duplicate-context-fail-closed")
def context_allowlists_and_duplicates(root: Path) -> None:
    canary = root / "context-canary"
    script = counter_script(canary)
    contexts = [
        ("workflow-env", workflow_with_context(workflow_update={"env": {"X": "Y"}}), "workflow-context-not-allowlisted"),
        ("workflow-defaults", workflow_with_context(workflow_update={"defaults": {"run": {"shell": "bash"}}}), "workflow-context-not-allowlisted"),
        ("workflow-future", workflow_with_context(workflow_update={"future-context": True}), "workflow-context-not-allowlisted"),
        ("job-if", workflow_with_context(job_update={"if": "always()"}), "job-context-not-allowlisted"),
        ("job-container", workflow_with_context(job_update={"container": "example.invalid/image"}), "job-context-not-allowlisted"),
        ("job-services", workflow_with_context(job_update={"services": {"db": {"image": "example.invalid/db"}}}), "job-context-not-allowlisted"),
        ("job-future", workflow_with_context(job_update={"future-context": True}), "job-context-not-allowlisted"),
    ]
    for name, workflow, expected_reason in contexts:
        fixture = root / name
        fixture.mkdir()
        repo, commit = initialize_repo(
            fixture,
            scripts={"scripts/check-canary.py": script},
            workflow=workflow,
        )
        out = fixture / "evidence.json"
        completed = invoke(repo, commit, out)
        if completed.returncode != 2:
            raise AssertionError((name, completed.returncode, stderr_text(completed)))
        gate = gate_by_name(artifact(out), "canary")
        if gate["status"] != "not-run" or gate["reason_code"] != expected_reason:
            raise AssertionError((name, gate))
    if canary.exists():
        raise AssertionError("context canary fired")

    for level in ("workflow", "on", "permissions", "jobs", "job", "step"):
        fixture = root / f"duplicate-{level}"
        fixture.mkdir()
        raw_workflow = duplicate_workflow(level)
        if level == "jobs":
            token_types = {type(token) for token in yaml.scan(raw_workflow, Loader=yaml.SafeLoader)}
            if yaml.tokens.AnchorToken in token_types or yaml.tokens.AliasToken in token_types:
                raise AssertionError("duplicate jobs fixture still contains an anchor or alias token")
        repo, commit = initialize_repo(
            fixture,
            scripts={"scripts/check-canary.py": script},
            raw_workflow=raw_workflow,
        )
        out = fixture / "evidence.json"
        completed = invoke(repo, commit, out)
        assert_exact_refusal(completed, out, "workflow YAML contains a duplicate mapping key")
    if canary.exists():
        raise AssertionError("duplicate-key canary fired")


@case("14f-step-key-allowlist-bites-known-and-future-keys")
def step_key_allowlist(root: Path) -> None:
    canary = root / "step-key-canary"
    script = counter_script(canary)
    steps = [
        {"name": "env", "run": "python3 scripts/check-canary.py", "env": {"X": "Y"}},
        {"name": "if", "run": "python3 scripts/check-canary.py", "if": "always()"},
        {"name": "future", "run": "python3 scripts/check-canary.py", "future-step-key": True},
    ]
    repo, commit = initialize_repo(
        root,
        scripts={"scripts/check-canary.py": script},
        steps=steps,
    )
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    if completed.returncode != 2:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    data = artifact(out)
    for name in ("env", "if", "future"):
        gate = gate_by_name(data, name)
        if gate["status"] != "not-run" or gate["reason_code"] != "step-key-not-allowlisted":
            raise AssertionError((name, gate))
    if canary.exists():
        raise AssertionError("step-key canary fired")


def near_misses(accepted: Sequence[tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
    """Mechanically derive all applicable one-token/flag-order mutations."""
    generated: dict[str, tuple[str, ...]] = {}
    interpreters = ("python", "python3", "bash")
    for form_index, argv in enumerate(accepted):
        prefix = f"form-{form_index}"
        flags = list(argv[2:])
        extra_flag = "--extra" if argv[1] == "scripts/rendered-inventory.py" else "--write"
        generated[f"{prefix}-extra-flag"] = (*argv, extra_flag)
        if flags:
            generated[f"{prefix}-missing-flag"] = tuple(argv[:2] + argv[3:])
            generated[f"{prefix}-duplicated-flag"] = (*argv, flags[0])
            generated[f"{prefix}-substituted-flag"] = (*argv[:2], "--substitute", *argv[3:])
            generated[f"{prefix}-reordered-with-extra"] = (*argv[:2], extra_flag, *flags)
        for interpreter in interpreters:
            if interpreter != argv[0]:
                generated[f"{prefix}-interpreter-{interpreter}"] = (interpreter, *argv[1:])
    return generated


@case("14g-generative-whole-argv-near-miss-matrix")
def generative_near_misses(root: Path) -> None:
    accepted = [
        ("python3", "scripts/probe.selftest.py"),
        ("python", "scripts/check-python.py"),
        ("python3", "scripts/check-python3.py"),
        ("bash", "scripts/check-bash.sh"),
        ("python3", "scripts/render-probe.py", "--check"),
        ("python3", "scripts/rendered-inventory.py", "--all-paths"),
    ]
    generated = near_misses(accepted)
    expected_verdicts: dict[str, str | tuple[str, str]] = {
        "form-0-extra-flag": ("not-run", "outside-guard-family"),  # AC-3a self-test form permits no flags.
        "form-0-interpreter-python": ("not-run", "outside-guard-family"),  # AC-3a self-test form requires python3.
        "form-0-interpreter-bash": ("not-run", "outside-grammar"),  # AC-3 clause 6 requires bash paths to end in .sh.
        "form-1-extra-flag": ("not-run", "outside-guard-family"),  # AC-3a check-guard form permits no flags.
        "form-1-interpreter-python3": "pass",  # AC-3a check-guard form admits python and python3 for .py.
        "form-1-interpreter-bash": ("not-run", "outside-grammar"),  # AC-3 clause 6 requires bash paths to end in .sh.
        "form-2-extra-flag": ("not-run", "outside-guard-family"),  # AC-3a check-guard form permits no flags.
        "form-2-interpreter-python": "pass",  # AC-3a check-guard form admits python and python3 for .py.
        "form-2-interpreter-bash": ("not-run", "outside-grammar"),  # AC-3 clause 6 requires bash paths to end in .sh.
        "form-3-extra-flag": ("not-run", "outside-guard-family"),  # AC-3a check-guard form permits no flags.
        "form-3-interpreter-python": ("not-run", "outside-grammar"),  # AC-3 clause 6 requires python paths to end in .py.
        "form-3-interpreter-python3": ("not-run", "outside-grammar"),  # AC-3 clause 6 requires python3 paths to end in .py.
        "form-4-extra-flag": ("not-run", "outside-guard-family"),  # AC-3a renderer form is exactly python3, path, and --check.
        "form-4-missing-flag": ("not-run", "outside-guard-family"),  # AC-3a renderer form requires --check.
        "form-4-duplicated-flag": ("not-run", "outside-guard-family"),  # AC-3a renderer form permits exactly one --check.
        "form-4-substituted-flag": ("not-run", "outside-guard-family"),  # AC-3a renderer form requires --check.
        "form-4-reordered-with-extra": ("not-run", "outside-guard-family"),  # AC-3a renderer form permits no extra flag or reordering.
        "form-4-interpreter-python": ("not-run", "outside-guard-family"),  # AC-3a renderer form requires python3.
        "form-4-interpreter-bash": ("not-run", "outside-grammar"),  # AC-3 clause 6 requires bash paths to end in .sh.
        "form-5-extra-flag": ("not-run", "outside-guard-family"),  # AC-3a named exception requires the exact whole argv.
        "form-5-missing-flag": ("not-run", "outside-guard-family"),  # AC-3a named exception requires --all-paths.
        "form-5-duplicated-flag": ("not-run", "outside-guard-family"),  # AC-3a named exception permits exactly one --all-paths.
        "form-5-substituted-flag": ("not-run", "outside-guard-family"),  # AC-3a named exception requires --all-paths.
        "form-5-reordered-with-extra": ("not-run", "outside-guard-family"),  # AC-3a named exception requires the exact whole argv.
        "form-5-interpreter-python": ("not-run", "outside-guard-family"),  # AC-3a named exception requires python3.
        "form-5-interpreter-bash": ("not-run", "outside-grammar"),  # AC-3 clause 6 requires bash paths to end in .sh.
    }
    if generated.keys() != expected_verdicts.keys():
        missing = sorted(generated.keys() - expected_verdicts.keys())
        unexpected = sorted(expected_verdicts.keys() - generated.keys())
        raise AssertionError(f"literal oracle differs from near_misses: missing={missing}, unexpected={unexpected}")
    if sum(verdict == "pass" for verdict in expected_verdicts.values()) != 2:
        raise AssertionError("literal oracle must contain exactly two accepted near-misses")
    if ("python3", "scripts/render-probe.py", "--check", "--write") not in generated.values():
        raise AssertionError("generator omitted renderer --check --write")
    if ("python3", "scripts/rendered-inventory.py", "--all-paths", "--extra") not in generated.values():
        raise AssertionError("generator omitted exact-exception extra flag")

    scripts: dict[str, str] = {}
    counters: dict[str, Path] = {}
    for argv in accepted:
        path = argv[1]
        if path in scripts:
            continue
        counter = root / (path.replace("/", "-") + ".counter")
        counters[path] = counter
        scripts[path] = counter_script(counter, shell=path.endswith(".sh"))
    steps = [
        {"name": name, "run": " ".join(argv)}
        for name, argv in generated.items()
    ]
    repo, commit = initialize_repo(root, scripts=scripts, steps=steps)
    command_bin = root / "bin"
    command_bin.mkdir()
    (command_bin / "git").symlink_to(GIT)
    (command_bin / "python").symlink_to(PYTHON)
    (command_bin / "python3").symlink_to(PYTHON)
    (command_bin / "bash").symlink_to("/usr/bin/bash")
    out = root / "evidence.json"
    completed = invoke(repo, commit, out, env_updates={"PATH": str(command_bin)})
    if completed.returncode != 2:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    data = artifact(out)
    expected_executions: dict[str, int] = {path: 0 for path in scripts}
    for name, expected in expected_verdicts.items():
        argv = generated[name]
        gate = gate_by_name(data, name)
        if expected == "pass":
            if gate["status"] != "pass":
                raise AssertionError((name, argv, gate))
            expected_executions[argv[1]] += 1
        else:
            expected_status, expected_reason = expected
            if gate["status"] != expected_status or gate["reason_code"] != expected_reason:
                raise AssertionError((name, argv, gate))
    for path, counter in counters.items():
        observed = len(counter.read_text(encoding="utf-8")) if counter.exists() else 0
        if observed != expected_executions[path]:
            raise AssertionError(f"near-miss canary count for {path}: {observed} != {expected_executions[path]}")


@case("14h-exit-zero-carve-out-is-exact")
def exact_help_carve_out(root: Path) -> None:
    for argv in (("-h",), ("--help",)):
        before = sorted(path.relative_to(root) for path in root.rglob("*"))
        completed = run([str(PYTHON), str(TOOL), *argv], cwd=root, check=False)
        if completed.returncode != 0 or not completed.stdout.startswith(b"usage:"):
            raise AssertionError((argv, completed.returncode, completed.stdout, completed.stderr))
        after = sorted(path.relative_to(root) for path in root.rglob("*"))
        if after != before:
            raise AssertionError(f"help invocation changed directory contents: {before!r} != {after!r}")

    explicit_destination = root / "malformed-with-out.json"
    rejected = (
        ("--h",),
        ("--he",),
        ("--hel",),
        ("--help", "--definitely-unknown"),
        ("--definitely-unknown", "--help"),
        ("--commit", "0" * 40, "--out", str(explicit_destination), "--help"),
        ("-h", "--commit", "0" * 40),
        ("--definitely-unknown",),
    )
    refusal_prefix = b"REFUSAL: argument error:"
    for argv in rejected:
        completed = run([str(PYTHON), str(TOOL), *argv], cwd=root, check=False)
        if completed.returncode != 3 or not completed.stderr.startswith(refusal_prefix):
            raise AssertionError((argv, completed.returncode, completed.stdout, completed.stderr))
    if explicit_destination.exists() or explicit_destination.is_symlink():
        raise AssertionError(f"malformed help invocation created destination: {explicit_destination}")


@case("15-worktree-cleanup-failure-refuses-with-exact-recovery")
def cleanup_failure(root: Path) -> None:
    repo, commit = initialize_repo(root)
    before = worktree_state(repo)
    out = root / "evidence.json"
    original_remove = helper.remove_materialized_worktree

    def injected_remove(_repo: Path, _worktree: Path) -> None:
        raise helper.Refusal("injected cleanup failure")

    old_argv = sys.argv
    old_cwd = Path.cwd()
    stdout = io.StringIO()
    stderr = io.StringIO()
    helper.remove_materialized_worktree = injected_remove
    sys.argv = [
        str(TOOL),
        "--commit",
        commit,
        "--out",
        str(out),
        "--timeout-seconds",
        "10",
    ]
    try:
        os.chdir(repo)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            returncode = helper.main()
    finally:
        os.chdir(old_cwd)
        sys.argv = old_argv
        helper.remove_materialized_worktree = original_remove
    if returncode != 3 or out.exists():
        raise AssertionError((returncode, stdout.getvalue(), stderr.getvalue()))
    after_failure = worktree_state(repo)
    if after_failure == before:
        raise AssertionError("injected cleanup failure did not leave a recoverable worktree")
    records = after_failure.decode("utf-8").splitlines()
    paths = [Path(line.removeprefix("worktree ")) for line in records if line.startswith("worktree ")]
    original_paths = {
        Path(line.removeprefix("worktree "))
        for line in before.decode("utf-8").splitlines()
        if line.startswith("worktree ")
    }
    leaked = [path for path in paths if path not in original_paths]
    if len(leaked) != 1:
        raise AssertionError(f"expected one recoverable worktree, got {leaked!r}")
    expected = f"Recovery: git -C {repo.resolve()} worktree remove --force {leaked[0]}"
    if expected not in stderr.getvalue():
        raise AssertionError(f"exact recovery command absent: {stderr.getvalue()!r}")
    git(repo, "worktree", "remove", "--force", str(leaked[0]))
    if worktree_state(repo) != before:
        raise AssertionError("recovery command did not restore worktree state")
    shutil.rmtree(leaked[0].parent, ignore_errors=True)


@case("16-all-gates-pass-and-schema-is-exact")
def all_gates_pass(root: Path) -> None:
    repo, commit = initialize_repo(
        root,
        steps=[
            {"uses": "actions/checkout@0123456789abcdef"},
            {"id": "without-name", "run": "python3 scripts/check-pass.py"},
        ],
    )
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    if completed.returncode != 0:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    data = artifact(out)
    gate = data["gates"][0]
    if gate["step_name"] is not None or gate["status"] != "pass":
        raise AssertionError(gate)
    if data["run"]["counts"] != {"pass": 1, "failed": 0, "signaled": 0, "not_run": 0, "timed_out": 0}:
        raise AssertionError(data["run"]["counts"])
    non_run = data["coverage_limits"]["non_run_steps"]
    if non_run != [{"job": "fixture", "step_name": None, "uses": "actions/checkout@0123456789abcdef"}]:
        raise AssertionError(non_run)
    expected_context = [
        {"kind": "permissions", "value": "contents=read"},
        {"kind": "job-order", "value": "0:fixture"},
        {"kind": "runs-on", "value": "ubuntu-latest"},
    ]
    if data["coverage_limits"]["unreproduced_context"] != expected_context:
        raise AssertionError(data["coverage_limits"]["unreproduced_context"])


def assert_exact_refusal(
    completed: subprocess.CompletedProcess[bytes],
    out: Path,
    reason: str,
) -> None:
    expected = f"REFUSAL: {reason}\n".encode("utf-8")
    if completed.returncode != 3 or completed.stdout != b"" or completed.stderr != expected:
        raise AssertionError(
            (completed.returncode, completed.stdout, completed.stderr, expected)
        )
    if out.exists() or out.is_symlink():
        raise AssertionError(f"refusal unexpectedly created {out}")


def assert_gate_outcome(
    completed: subprocess.CompletedProcess[bytes],
    out: Path,
    *,
    expected_exit: int,
    expected_status: str,
    expected_reason_code: str | None,
    expected_reason: str | None,
) -> dict[str, Any]:
    if completed.returncode != expected_exit:
        raise AssertionError((completed.returncode, stderr_text(completed)))
    data = artifact(out)
    gate = gate_by_name(data, "canary")
    actual = (gate["status"], gate["reason_code"], gate["reason"])
    expected = (expected_status, expected_reason_code, expected_reason)
    if actual != expected:
        raise AssertionError((actual, expected, gate))
    return gate


def raw_gate_workflow(
    *,
    trigger_key: str = "on",
    run_body: str = "python3 scripts/check-canary.py",
) -> str:
    return (
        "name: Fixture Validate\n"
        f"{trigger_key}: {{pull_request: null}}\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  fixture:\n"
        "    name: Fixture\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: canary\n"
        f"        run: {run_body}\n"
    )


@case("17-duplicate-jobs-erasure-refuses-before-gate-derivation")
def duplicate_jobs_erasure(root: Path) -> None:
    canary = root / "duplicate-erasure-canary"
    raw_workflow = (
        "name: Fixture Validate\n"
        "on: {pull_request: null}\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  fixture:\n"
        "    name: Fixture\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: canary\n"
        "        run: python3 scripts/check-canary.py\n"
        "jobs: {}\n"
    )
    token_types = {type(token) for token in yaml.scan(raw_workflow, Loader=yaml.SafeLoader)}
    if yaml.tokens.AnchorToken in token_types or yaml.tokens.AliasToken in token_types:
        raise AssertionError("duplicate erasure fixture contains an anchor or alias")
    repo, commit = initialize_repo(
        root,
        scripts={"scripts/check-canary.py": counter_script(canary)},
        raw_workflow=raw_workflow,
    )
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    assert_exact_refusal(completed, out, "workflow YAML contains a duplicate mapping key")
    if canary.exists():
        raise AssertionError("duplicate erasure canary fired")


@case("17b-empty-derived-gate-list-refuses-without-duplicate")
def empty_gate_list(root: Path) -> None:
    raw_workflow = (
        "name: Fixture Validate\n"
        "on: {pull_request: null}\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  fixture:\n"
        "    name: Fixture\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n"
    )
    repo, commit = initialize_repo(root, raw_workflow=raw_workflow)
    out = root / "evidence.json"
    completed = invoke(repo, commit, out)
    assert_exact_refusal(completed, out, "derived gate list is empty")


@case("17c-workflow-key-lexemes-do-not-inherit-on-semantics")
def workflow_key_lexemes(root: Path) -> None:
    for index, trigger_key in enumerate(("yes", "true", "ON", "on")):
        fixture = root / f"{index}-{trigger_key}"
        fixture.mkdir()
        canary = fixture / "canary-fired"
        repo, commit = initialize_repo(
            fixture,
            scripts={"scripts/check-canary.py": counter_script(canary)},
            raw_workflow=raw_gate_workflow(trigger_key=trigger_key),
        )
        out = fixture / "evidence.json"
        completed = invoke(repo, commit, out)
        if trigger_key == "on":
            assert_gate_outcome(
                completed,
                out,
                expected_exit=0,
                expected_status="pass",
                expected_reason_code=None,
                expected_reason=None,
            )
            if canary.read_text(encoding="utf-8") != "x":
                raise AssertionError("bare on positive did not execute exactly once")
        else:
            assert_gate_outcome(
                completed,
                out,
                expected_exit=2,
                expected_status="not-run",
                expected_reason_code="workflow-context-not-allowlisted",
                expected_reason="workflow mapping contains a non-allowlisted key",
            )
            if canary.exists():
                raise AssertionError(f"coerced workflow-key canary fired: {trigger_key}")


@case("17d-selftest-family-has-its-own-bounded-path-rule")
def bounded_selftest_family(root: Path) -> None:
    for label, script_path in (
        ("flat", "scripts/probe.selftest.py"),
        ("nested", "scripts/sub/probe.selftest.py"),
    ):
        fixture = root / label
        fixture.mkdir()
        canary = fixture / "canary-fired"
        repo, commit = initialize_repo(
            fixture,
            scripts={script_path: counter_script(canary)},
            raw_workflow=raw_gate_workflow(
                run_body=f"python3 {script_path}",
            ),
        )
        out = fixture / "evidence.json"
        completed = invoke(repo, commit, out)
        assert_gate_outcome(
            completed,
            out,
            expected_exit=0,
            expected_status="pass",
            expected_reason_code=None,
            expected_reason=None,
        )
        if canary.read_text(encoding="utf-8") != "x":
            raise AssertionError(f"{label} self-test positive did not execute exactly once")

    for path in (
        "x.selftest.py",
        "/etc/x.selftest.py",
        "scripts//x.selftest.py",
        "scripts/../x.selftest.py",
        "scripts/.hidden/x.selftest.py",
    ):
        if helper.is_guard_family(["python3", path]) is not False:
            raise AssertionError(f"self-test family admitted path outside its boundary: {path!r}")


@case("17e-merge-alias-and-anchor-controls-are-independent")
def merge_alias_anchor_controls(root: Path) -> None:
    prefix = (
        "name: Fixture Validate\n"
        "on: {pull_request: null}\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  fixture:\n"
        "    name: Fixture\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
    )
    fixtures = {
        "literal-merge": (
            prefix + "      - <<: {name: canary, run: python3 scripts/check-canary.py}\n",
            "workflow YAML contains a merge key",
        ),
        "explicit-tag-merge": (
            prefix + "      - !!merge x: {name: canary, run: python3 scripts/check-canary.py}\n",
            "workflow YAML contains a merge key",
        ),
        "alias-step": (
            prefix
            + "      - &template\n"
            + "        name: canary\n"
            + "        run: python3 scripts/check-canary.py\n"
            + "      - *template\n",
            "workflow YAML contains an alias",
        ),
        "anchor-only": (
            prefix
            + "      - &only\n"
            + "        name: canary\n"
            + "        run: python3 scripts/check-canary.py\n",
            None,
        ),
    }
    for label, (raw_workflow, refusal_reason) in fixtures.items():
        fixture = root / label
        fixture.mkdir()
        canary = fixture / "canary-fired"
        token_types = {type(token) for token in yaml.scan(raw_workflow, Loader=yaml.SafeLoader)}
        if "merge" in label and (
            yaml.tokens.AnchorToken in token_types or yaml.tokens.AliasToken in token_types
        ):
            raise AssertionError(f"{label} fixture is not alias- and anchor-free")
        repo, commit = initialize_repo(
            fixture,
            scripts={"scripts/check-canary.py": counter_script(canary)},
            raw_workflow=raw_workflow,
        )
        out = fixture / "evidence.json"
        completed = invoke(repo, commit, out)
        if refusal_reason is not None:
            assert_exact_refusal(completed, out, refusal_reason)
            if canary.exists():
                raise AssertionError(f"{label} canary fired")
        else:
            if yaml.tokens.AnchorToken not in token_types or yaml.tokens.AliasToken in token_types:
                raise AssertionError("anchor-only positive has the wrong property tokens")
            assert_gate_outcome(
                completed,
                out,
                expected_exit=0,
                expected_status="pass",
                expected_reason_code=None,
                expected_reason=None,
            )
            if canary.read_text(encoding="utf-8") != "x":
                raise AssertionError("anchor-only positive did not execute exactly once")


@dataclass(frozen=True)
class ScalarRendering:
    name: str
    mode: str
    marker: str
    expected_violations: frozenset[str]


def presentation_violations(event: yaml.events.ScalarEvent) -> frozenset[str]:
    violations: set[str] = set()
    if event.style is not None:
        violations.add("style")
    if event.anchor is not None:
        violations.add("anchor")
    if event.tag is not None:
        violations.add("explicit-tag")
    if event.start_mark.line != event.end_mark.line:
        violations.add("span")
    return frozenset(violations)


def scalar_event_for_value(source: str, value: str) -> yaml.events.ScalarEvent:
    matches = [
        event
        for event in yaml.parse(source, Loader=yaml.SafeLoader)
        if isinstance(event, yaml.events.ScalarEvent)
        and event.value.rstrip("\n") == value
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one scalar event for {value!r}, got {len(matches)}")
    return matches[0]


def body_presentation_rows() -> list[ScalarRendering]:
    rows = [ScalarRendering("plain", "inline", "plain", frozenset())]
    for name, marker in (("single-quoted", "single"), ("double-quoted", "double")):
        rows.append(ScalarRendering(name, "inline", marker, frozenset({"style"})))
    rows.extend(
        [
            ScalarRendering("double-escaped", "inline", "escaped", frozenset({"style"})),
            ScalarRendering(
                "double-multiline",
                "inline",
                "double-multiline",
                frozenset({"style", "span"}),
            ),
        ]
    )
    for style_name, style in (("literal", "|"), ("folded", ">")):
        for modifier_name, modifier in (
            ("clip", ""),
            ("strip", "-"),
            ("keep", "+"),
            ("indent", "2"),
        ):
            rows.append(
                ScalarRendering(
                    f"{style_name}-{modifier_name}",
                    "block",
                    style + modifier,
                    frozenset({"style", "span"}),
                )
            )
    for name, marker, violation in (
        ("scalar-anchor", "anchor", "anchor"),
        ("explicit-str-tag", "explicit-tag", "explicit-tag"),
        ("nonspecific-tag", "nonspecific-tag", "explicit-tag"),
        ("plain-multiline", "plain-multiline", "span"),
    ):
        rows.append(ScalarRendering(name, "inline", marker, frozenset({violation})))
    return rows


def render_body_binding(row: ScalarRendering, command: str, indent: int) -> str:
    padding = " " * indent
    continuation = " " * (indent + 2)
    if row.mode == "block":
        return f"{padding}run: {row.marker}\n{continuation}{command}\n"
    if row.marker == "plain":
        scalar = command
    elif row.marker == "single":
        scalar = f"'{command}'"
    elif row.marker == "double":
        scalar = f'"{command}"'
    elif row.marker == "escaped":
        scalar = f'"{command.replace(".py", r"\x2epy")}"'
    elif row.marker == "double-multiline":
        left, right = command.split("check-canary", 1)
        scalar = f'"{left}\\\n{continuation}check-canary{right}"'
    elif row.marker == "anchor":
        scalar = f"&body {command}"
    elif row.marker == "explicit-tag":
        scalar = f"!!str {command}"
    elif row.marker == "nonspecific-tag":
        scalar = f"! {command}"
    elif row.marker == "plain-multiline":
        interpreter, path = command.split(" ", 1)
        scalar = f"{interpreter}\n{continuation}{path}"
    else:
        raise AssertionError(f"unknown body rendering: {row}")
    return f"{padding}run: {scalar}\n"


@case("17f-generative-run-body-presentation-matrix")
def run_body_presentation_matrix(root: Path) -> None:
    command = "python3 scripts/check-canary.py"
    rows = body_presentation_rows()
    if len({row.name for row in rows}) != len(rows):
        raise AssertionError("run-body presentation generator emitted duplicate names")
    if "nonspecific-tag" not in {row.name for row in rows}:
        raise AssertionError("run-body presentation generator omitted the ! row")
    for clause in ("style", "anchor", "explicit-tag", "span"):
        if not any(row.expected_violations == frozenset({clause}) for row in rows):
            raise AssertionError(f"run-body matrix lacks a single-property {clause} witness")

    prefix = (
        "name: Fixture Validate\n"
        "on: {pull_request: null}\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  fixture:\n"
        "    name: Fixture\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: canary\n"
    )
    for row in rows:
        fixture = root / row.name
        fixture.mkdir()
        canary = fixture / "canary-fired"
        raw_workflow = prefix + render_body_binding(row, command, 8)
        event = scalar_event_for_value(raw_workflow, command)
        actual_violations = presentation_violations(event)
        if actual_violations != row.expected_violations:
            raise AssertionError(
                f"{row.name} violations {actual_violations} != {row.expected_violations}"
            )
        repo, commit = initialize_repo(
            fixture,
            scripts={"scripts/check-canary.py": counter_script(canary)},
            raw_workflow=raw_workflow,
        )
        out = fixture / "evidence.json"
        completed = invoke(repo, commit, out)
        if row.expected_violations:
            assert_gate_outcome(
                completed,
                out,
                expected_exit=2,
                expected_status="not-run",
                expected_reason_code="outside-grammar",
                expected_reason="run body is outside the closed command grammar",
            )
            if canary.exists():
                raise AssertionError(f"run-body presentation canary fired: {row.name}")
        else:
            assert_gate_outcome(
                completed,
                out,
                expected_exit=0,
                expected_status="pass",
                expected_reason_code=None,
                expected_reason=None,
            )
            if canary.read_text(encoding="utf-8") != "x":
                raise AssertionError("plain run-body positive did not execute exactly once")


def key_presentation_rows(key: str) -> list[ScalarRendering]:
    escape_indexes = {"jobs": 2, "steps": 2, "run": 1}
    escaped_index = escape_indexes[key]
    escaped = (
        key[:escaped_index]
        + f"\\x{ord(key[escaped_index]):02x}"
        + key[escaped_index + 1 :]
    )
    rows = [ScalarRendering("plain", "inline-key", key, frozenset())]
    for name, rendered in (
        ("single-quoted", f"'{key}'"),
        ("double-quoted", f'"{key}"'),
        ("double-escaped", f'"{escaped}"'),
    ):
        rows.append(ScalarRendering(name, "inline-key", rendered, frozenset({"style"})))
    rows.append(
        ScalarRendering(
            "double-multiline",
            "double-multiline-key",
            key,
            frozenset({"style", "span"}),
        )
    )
    for style_name, style in (("literal", "|"), ("folded", ">")):
        rows.append(
            ScalarRendering(
                f"{style_name}-block-strip",
                "block-key",
                style + "-",
                frozenset({"style", "span"}),
            )
        )
    for name, rendered, violation in (
        ("scalar-anchor", f"&key {key}", "anchor"),
        ("explicit-str-tag", f"!!str {key}", "explicit-tag"),
        ("nonspecific-tag", f"! {key}", "explicit-tag"),
    ):
        rows.append(ScalarRendering(name, "inline-key", rendered, frozenset({violation})))
    return rows


def indent_yaml(value: str, width: int) -> str:
    padding = " " * width
    return "".join(padding + line + "\n" for line in value.rstrip("\n").split("\n"))


def render_mapping_binding(
    row: ScalarRendering,
    key: str,
    value: str,
    indent: int,
    *,
    scalar_value: bool = False,
) -> str:
    padding = " " * indent
    continuation = " " * (indent + 2)
    if row.mode == "block-key":
        binding = f"{padding}? {row.marker}\n{continuation}{key}\n{padding}:"
    elif row.mode == "double-multiline-key":
        split_at = max(1, len(key) // 2)
        rendered_key = f'"{key[:split_at]}\\\n{continuation}{key[split_at:]}"'
        binding = f"{padding}? {rendered_key}\n{padding}:"
    else:
        binding = f"{padding}{row.marker}:"
    if scalar_value:
        return f"{binding} {value}\n"
    return binding + "\n" + indent_yaml(value, indent + 2)


def raw_workflow_with_presented_key(level: str, row: ScalarRendering) -> tuple[str, str]:
    command = "python3 scripts/check-canary.py"
    step_value = f"- name: canary\n  run: {command}\n"
    job_value = (
        "fixture:\n"
        "  name: Fixture\n"
        "  runs-on: ubuntu-latest\n"
        "  steps:\n"
        + indent_yaml(step_value, 4)
    )
    prefix = (
        "name: Fixture Validate\n"
        "on: {pull_request: null}\n"
        "permissions: {contents: read}\n"
    )
    if level == "workflow":
        return prefix + render_mapping_binding(row, "jobs", job_value, 0), "jobs"
    if level == "job":
        return (
            prefix
            + "jobs:\n"
            + "  fixture:\n"
            + "    name: Fixture\n"
            + "    runs-on: ubuntu-latest\n"
            + render_mapping_binding(row, "steps", step_value, 4)
        ), "steps"
    if level == "step":
        return (
            prefix
            + "jobs:\n"
            + "  fixture:\n"
            + "    name: Fixture\n"
            + "    runs-on: ubuntu-latest\n"
            + "    steps:\n"
            + "      - name: canary\n"
            + render_mapping_binding(row, "run", command, 8, scalar_value=True)
        ), "run"
    raise AssertionError(f"unknown key-presentation level: {level}")


@case("17g-generative-key-presentation-matrix-at-all-levels")
def key_presentation_matrix(root: Path) -> None:
    reason_by_level = {
        "workflow": (
            "workflow-context-not-allowlisted",
            "workflow mapping contains a non-allowlisted key",
        ),
        "job": (
            "job-context-not-allowlisted",
            "job mapping contains a non-allowlisted key",
        ),
        "step": (
            "step-key-not-allowlisted",
            "step mapping contains a non-allowlisted key",
        ),
    }
    for level, key in (("workflow", "jobs"), ("job", "steps"), ("step", "run")):
        rows = key_presentation_rows(key)
        if len({row.name for row in rows}) != len(rows):
            raise AssertionError(f"{level} key generator emitted duplicate row names")
        if "nonspecific-tag" not in {row.name for row in rows}:
            raise AssertionError(f"{level} key generator omitted the ! row")
        for row in rows:
            fixture = root / level / row.name
            fixture.mkdir(parents=True)
            canary = fixture / "canary-fired"
            raw_workflow, target_value = raw_workflow_with_presented_key(level, row)
            event = scalar_event_for_value(raw_workflow, target_value)
            actual_violations = presentation_violations(event)
            if actual_violations != row.expected_violations:
                raise AssertionError(
                    f"{level}/{row.name} violations {actual_violations} "
                    f"!= {row.expected_violations}"
                )
            repo, commit = initialize_repo(
                fixture,
                scripts={"scripts/check-canary.py": counter_script(canary)},
                raw_workflow=raw_workflow,
            )
            out = fixture / "evidence.json"
            completed = invoke(repo, commit, out)
            if row.expected_violations:
                reason_code, reason = reason_by_level[level]
                assert_gate_outcome(
                    completed,
                    out,
                    expected_exit=2,
                    expected_status="not-run",
                    expected_reason_code=reason_code,
                    expected_reason=reason,
                )
                if canary.exists():
                    raise AssertionError(f"key-presentation canary fired: {level}/{row.name}")
            else:
                assert_gate_outcome(
                    completed,
                    out,
                    expected_exit=0,
                    expected_status="pass",
                    expected_reason_code=None,
                    expected_reason=None,
                )
                if canary.read_text(encoding="utf-8") != "x":
                    raise AssertionError(f"plain {level} key positive did not execute exactly once")


def main() -> int:
    failures: list[tuple[str, str]] = []
    for name, function in CASES:
        with tempfile.TemporaryDirectory(prefix="build-review-evidence-selftest-") as temporary:
            try:
                function(Path(temporary))
            except Exception as exc:  # noqa: BLE001 - report every independent case
                failures.append((name, repr(exc)))
                print(f"FAIL  {name}")
            else:
                print(f"PASS  {name}")
    print()
    if failures:
        print(f"SELFTEST FAIL ({len(failures)} of {len(CASES)} cases)")
        for name, error in failures:
            print(f"  - {name}: {error}")
        return 1
    print(f"SELFTEST PASS ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
