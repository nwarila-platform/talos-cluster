#!/usr/bin/env python3
"""Hermetic failure and ordering fixtures for the etcd backup producer."""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import signal
import subprocess
import tempfile
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONFIGMAP = ROOT / "clusters/talos-cluster/apps/dr-etcd-backup/configmap-encrypt-script.yaml"
APP = ROOT / "clusters/talos-cluster/apps/dr-etcd-backup"
ADR_0014 = ROOT / "docs/decision-records/repo/0014-use-stage-1-local-backup-server-for-dr.md"
ADR_0026 = ROOT / "docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md"
DR_RUNBOOK = ROOT / "docs/runbooks/dr-stage1-backup.md"
TECH_DEBT = ROOT / "docs/tech-debt.md"
LEDGER = ROOT / "_handoff/steps/dr1-DONE.md"
FINAL_SUFFIX = ".db.sops.json"
MIN_SNAPSHOT_BYTES = 10_000_000
PINNED_SOPS_IMAGE = (
    "ghcr.io/getsops/sops@sha256:"
    "0bc8915bce25ea3bf0f3e27a74cb5ad092488e6e5245af384816d628ed7fd426"
)
AGE_RECIPIENT = "age18scjc2mepug263cnqmkxe6drne6mqs5h77y9j3fh3fuxshxesuhsyh0vhx"
PINNED_SOPS_SHA256 = "154dfe4cd70554bdd82b98e4cd4acf191d43d01ead6f00a73477aa44c4ac42ef"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def compact(path: Path) -> str:
    return " ".join(read(path).split())


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(read(path))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must parse to a YAML mapping")
    return value


def extract_encrypt_script() -> str:
    lines = CONFIGMAP.read_text(encoding="utf-8").splitlines(keepends=True)
    anchors = [index for index, line in enumerate(lines) if line == "  encrypt.sh: |\n"]
    if len(anchors) != 1:
        raise AssertionError(f"expected one encrypt.sh block, found {len(anchors)}")
    body = lines[anchors[0] + 1 :]
    if not body or any(line.strip() and not line.startswith("    ") for line in body):
        raise AssertionError("encrypt.sh must be the ConfigMap's final four-space-indented block")
    return "".join(line[4:] if line.strip() else line for line in body)


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def configured_pinned_sops() -> Path:
    configured = os.environ.get("DR1_PINNED_SOPS")
    if configured:
        binary = Path(configured).resolve()
    else:
        configured_rootfs = os.environ.get("DR1_PINNED_ROOTFS")
        if not configured_rootfs:
            raise AssertionError(
                "set DR1_PINNED_SOPS or DR1_PINNED_ROOTFS so fixtures use the pinned real SOPS binary"
            )
        binary = Path(configured_rootfs).resolve() / "usr/local/bin/sops"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise AssertionError(f"pinned SOPS binary is not executable: {binary}")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != PINNED_SOPS_SHA256:
        raise AssertionError(
            f"pinned SOPS binary digest mismatch: expected {PINNED_SOPS_SHA256}, got {digest}"
        )
    return binary


@dataclass
class Fixture:
    root: Path
    data: Path
    work: Path
    bin: Path
    script: Path
    tool_markers: dict[str, Path]
    date_output: Path

    @classmethod
    def create(cls, root: Path) -> "Fixture":
        data = root / "data"
        work = root / "work"
        bin_dir = root / "bin"
        data.mkdir()
        work.mkdir()
        bin_dir.mkdir()

        snapshot = work / "etcd.db"
        with snapshot.open("wb") as stream:
            stream.truncate(MIN_SNAPSHOT_BYTES + 1)

        source = extract_encrypt_script()
        script = root / "encrypt.sh"
        write_executable(
            script,
            source.replace("/work", str(work)).replace("/data", str(data)),
        )

        write_executable(
            bin_dir / "date",
            """#!/bin/sh
printf 'called\n' >>"${DATE_MARKER:?}"
date_output=$("${REAL_DATE:?}" "$@")
date_status=$?
[ "$date_status" -eq 0 ] || exit "$date_status"
printf '%s\n' "$date_output" >>"${DATE_OUTPUT_MARKER:?}"
if [ "${DATE_CREATE_OUT:-0}" = 1 ]; then
  printf '%s' 'existing-final' >"${FIXTURE_DATA:?}/etcd-$date_output.db.sops.json"
fi
printf '%s\n' "$date_output"
""",
        )
        write_executable(
            bin_dir / "df",
            """#!/bin/sh
printf 'called\n' >>"${DF_MARKER:?}"
if [ -n "${DF_MUTATE_ON_CALL:-}" ]; then
  calls=$(wc -l <"$DF_MARKER")
  stamp=$(tail -n 1 "${DATE_OUTPUT_MARKER:?}")
  out_path="${FIXTURE_DATA:?}/etcd-$stamp.db.sops.json"
  if [ -n "${DF_REMOVE_OUT_ON_CALL:-}" ] && [ "$calls" -eq "$DF_REMOVE_OUT_ON_CALL" ]; then
    rm -f -- "$out_path"
  fi
  if [ "$calls" -eq "$DF_MUTATE_ON_CALL" ]; then
    case "${DF_MUTATION:?}" in
      remove-out) rm -f -- "$out_path" ;;
      directory-out) rm -f -- "$out_path"; mkdir -- "$out_path" ;;
      empty-out) : >"$out_path" ;;
      small-out) printf 'x' >"$out_path" ;;
      add-finals)
        day=1
        while [ "$day" -le 14 ]; do
          printf 'late-final' >"${FIXTURE_DATA:?}/etcd-2000-01-$(printf '%02d' "$day")T030000Z.db.sops.json"
          day=$((day + 1))
        done
        ;;
      *) echo "unknown DF_MUTATION: $DF_MUTATION" >&2; exit 97 ;;
    esac
  fi
fi
if [ -z "${TEST_AVAILABLE_KIB:-}" ]; then
  exec "${REAL_DF:?}" "$@"
fi
printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'
printf 'fixture 20000000 0 %s 0%% %s\n' "$TEST_AVAILABLE_KIB" "${2:-${1:-unknown}}"
""",
        )
        write_executable(
            bin_dir / "sops",
            """#!/bin/sh
printf 'called\n' >>"${SOPS_MARKER:?}"
if [ "${SOPS_FAIL:-0}" = 1 ]; then
  echo 'injected sops failure' >&2
  exit 42
fi
if [ -z "${SOPS_SIZE_DELTA:-}" ]; then
  cd /
  exec "${REAL_SOPS:?}" "$@"
fi
input=
for argument do
  input=$argument
done
size=$(stat -c%s "$input")
output_size=$((size + SOPS_SIZE_DELTA))
python3 -c 'import os, sys; os.ftruncate(1, int(sys.argv[1]))' "$output_size"
""",
        )
        tool_markers = {name: root / f"{name}-called" for name in ("date", "df", "sops")}
        return cls(
            root=root,
            data=data,
            work=work,
            bin=bin_dir,
            script=script,
            tool_markers=tool_markers,
            date_output=root / "date-output",
        )

    def environment(self, overrides: dict[str, str] | None = None) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "AGE_RECIPIENT": AGE_RECIPIENT,
                "PATH": f"{self.bin}:{env['PATH']}",
                "DATE_MARKER": str(self.tool_markers["date"]),
                "DATE_OUTPUT_MARKER": str(self.date_output),
                "DF_MARKER": str(self.tool_markers["df"]),
                "SOPS_MARKER": str(self.tool_markers["sops"]),
                "FIXTURE_DATA": str(self.data),
                "REAL_DATE": shutil.which("date") or "/usr/bin/date",
                "REAL_DF": shutil.which("df") or "/usr/bin/df",
                "REAL_SOPS": str(configured_pinned_sops()),
            }
        )
        if overrides:
            env.update(overrides)
        return env

    def generated_out(self) -> Path:
        stamps = self.date_output.read_text(encoding="utf-8").splitlines()
        if not stamps:
            raise AssertionError("date wrapper recorded no successful output")
        return final_path(self.data, stamps[-1])

    def assert_tool_invocations(self, expected_tools: set[str]) -> None:
        actual_tools = {name for name, marker in self.tool_markers.items() if marker.is_file() and marker.stat().st_size}
        if actual_tools != expected_tools:
            raise AssertionError(
                f"stub invocation mismatch: expected {sorted(expected_tools)!r}, got {sorted(actual_tools)!r}"
            )

    def run(
        self,
        *,
        expected_tools: set[str] | None = None,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["/bin/sh", str(self.script)],
            cwd=self.root,
            env=self.environment(overrides),
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        if expected_tools is not None:
            self.assert_tool_invocations(expected_tools)
        return result


def final_path(data: Path, stamp: str) -> Path:
    return data / f"etcd-{stamp}{FINAL_SUFFIX}"


def seed_finals(data: Path, count: int) -> list[Path]:
    finals: list[Path] = []
    now = datetime.now(timezone.utc)
    for index in range(count):
        stamp = (now - timedelta(days=count - index + 1)).strftime("%Y-%m-%dT%H%M%SZ")
        path = final_path(data, stamp)
        path.write_bytes(f"final-{index + 1:02d}".encode())
        finals.append(path)
    return finals


def seed_mixed_nonfinals(data: Path) -> tuple[list[Path], Path]:
    partials = [
        data / "orphan.partial",
        data / "etcd-legacy.db.sops.partial",
        data / "etcd-2026-08-30T030000Z.db.sops.json.partial",
    ]
    for index, path in enumerate(partials, start=1):
        path.write_bytes(b"p" * index)
    legacy_final = data / "etcd-legacy.db.sops"
    legacy_final.write_bytes(b"legacy-final")
    return partials, legacy_final


@dataclass(frozen=True)
class RealToolBackend:
    """Execute the producer with no PATH stubs."""

    kind: str
    rootfs: Path | None = None
    runtime: str | None = None

    @classmethod
    def discover(cls) -> "RealToolBackend":
        configured_rootfs = os.environ.get("DR1_PINNED_ROOTFS")
        if configured_rootfs:
            rootfs = Path(configured_rootfs).resolve()
            required = (
                rootfs / "bin/dash",
                rootfs / "usr/bin/date",
                rootfs / "usr/bin/find",
                rootfs / "usr/bin/sort",
                rootfs / "usr/bin/awk",
                rootfs / "usr/bin/stat",
                rootfs / "usr/bin/df",
                rootfs / "usr/bin/mktemp",
                rootfs / "usr/bin/flock",
                rootfs / "usr/local/bin/sops",
            )
            missing = [str(path) for path in required if not path.is_file() or not os.access(path, os.X_OK)]
            if missing:
                raise AssertionError(f"DR1_PINNED_ROOTFS is incomplete: {missing!r}")
            return cls(kind="rootfs", rootfs=rootfs)

        for runtime in ("docker", "podman"):
            executable = shutil.which(runtime)
            if executable is None:
                continue
            probe = subprocess.run(
                [executable, "info"],
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
            )
            if probe.returncode == 0:
                return cls(kind="container", runtime=executable)

        if os.environ.get("DR1_PINNED_SOPS"):
            configured_pinned_sops()
            required_commands = ("date", "find", "sort", "awk", "stat", "df", "mktemp", "flock")
            missing = [command for command in required_commands if shutil.which(command) is None]
            if missing:
                raise AssertionError(f"host real-tool fallback is missing commands: {missing!r}")
            return cls(kind="host")

        raise AssertionError(
            "no real-tool backend; set DR1_PINNED_ROOTFS, set DR1_PINNED_SOPS for host coreutils, "
            "or provide a working docker/podman"
        )

    def run(self, case_root: Path, script: Path) -> subprocess.CompletedProcess[str]:
        work = case_root / "work"
        data = case_root / "data"
        if self.kind == "container":
            assert self.runtime is not None
            command = [
                self.runtime,
                "run",
                "--rm",
                "--network=none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--entrypoint=/bin/sh",
                "--env",
                f"AGE_RECIPIENT={AGE_RECIPIENT}",
                "--volume",
                f"{work}:/work:rw",
                "--volume",
                f"{data}:/data:rw",
                "--volume",
                f"{script}:/opt/etcd-backup/encrypt.sh:ro",
                PINNED_SOPS_IMAGE,
                "/opt/etcd-backup/encrypt.sh",
            ]
        else:
            source = read(script).replace("/work", str(work)).replace("/data", str(data))
            direct_script = case_root / "encrypt-direct.sh"
            write_executable(direct_script, source)
            if self.rootfs is not None:
                command = [str(self.rootfs / "bin/dash"), str(direct_script)]
            else:
                command = ["/bin/sh", str(direct_script)]

        environment = {
            "AGE_RECIPIENT": AGE_RECIPIENT,
            "HOME": str(case_root),
            "LC_ALL": "C",
        }
        if self.rootfs is not None:
            environment["PATH"] = ":".join(
                (
                    str(self.rootfs / "usr/local/bin"),
                    str(self.rootfs / "usr/bin"),
                    str(self.rootfs / "bin"),
                )
            )
        elif self.kind == "host":
            pinned_sops = configured_pinned_sops()
            pinned_bin = case_root / "pinned-bin"
            pinned_bin.mkdir()
            (pinned_bin / "sops").symlink_to(pinned_sops)
            environment["PATH"] = f"{pinned_bin}:{os.defpath}"
        return subprocess.run(
            command,
            cwd=work,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )

    def sops_binary(self, destination: Path) -> Path:
        if self.rootfs is not None:
            binary = self.rootfs / "usr/local/bin/sops"
        elif self.kind == "host":
            binary = configured_pinned_sops()
        else:
            assert self.runtime is not None
            created = subprocess.run(
                [self.runtime, "create", PINNED_SOPS_IMAGE],
                text=True,
                capture_output=True,
                check=False,
                timeout=60,
            )
            if created.returncode != 0:
                raise AssertionError(f"could not create pinned SOPS container: {created.stderr}")
            container_id = created.stdout.strip()
            try:
                copied = subprocess.run(
                    [self.runtime, "cp", f"{container_id}:/usr/local/bin/sops", str(destination)],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=60,
                )
                if copied.returncode != 0:
                    raise AssertionError(f"could not copy pinned SOPS binary: {copied.stderr}")
            finally:
                subprocess.run(
                    [self.runtime, "rm", "-f", container_id],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=30,
                )
            destination.chmod(0o755)
            binary = destination
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest != PINNED_SOPS_SHA256:
            raise AssertionError(f"pinned SOPS binary digest mismatch: expected {PINNED_SOPS_SHA256}, got {digest}")
        return binary


def case_real_tools_end_to_end() -> None:
    """The extracted producer must finish with the pinned image's real tools."""

    backend = RealToolBackend.discover()
    configured_tmpdir = os.environ.get("DR1_REAL_TMPDIR")
    temp_parent = Path(configured_tmpdir) if configured_tmpdir else None
    with tempfile.TemporaryDirectory(prefix="dr-etcd-real-tools-", dir=temp_parent) as tmp:
        fixture_root = Path(tmp)
        source_script = fixture_root / "encrypt.sh"
        write_executable(source_script, extract_encrypt_script())

        for count in (0, 1, 14, 15):
            case_root = fixture_root / f"finals-{count}"
            data = case_root / "data"
            work = case_root / "work"
            data.mkdir(parents=True)
            work.mkdir()
            snapshot = work / "etcd.db"
            with snapshot.open("wb") as stream:
                stream.truncate(MIN_SNAPSHOT_BYTES + 1)

            now = datetime.now(timezone.utc)
            existing: set[str] = set()
            for age_days in range(count, 0, -1):
                stamp = (now - timedelta(days=age_days + 1)).strftime("%Y-%m-%dT%H%M%SZ")
                path = final_path(data, stamp)
                path.write_bytes(f"pre-existing-{age_days:02d}".encode())
                existing.add(path.name)

            result = backend.run(case_root, source_script)
            assert result.returncode == 0, (
                f"real-tool run with {count} pre-existing finals returned {result.returncode}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
            retained = sorted(data.glob(f"etcd-*{FINAL_SUFFIX}"))
            new_artifacts = [path for path in retained if path.name not in existing]
            assert len(new_artifacts) == 1, (
                f"real-tool run with {count} finals retained new artifacts {new_artifacts!r}"
            )
            assert new_artifacts[0].stat().st_size >= MIN_SNAPSHOT_BYTES
            assert len(retained) == min(count + 1, 14)
            assert f"terminal artifact assertion passed: {new_artifacts[0]}" in result.stdout


def case_date_stub_matches_real_tool() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-date-fidelity-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        arguments = ("-u", "+%Y-%m-%dT%H%M%SZ")
        before = subprocess.run(
            [shutil.which("date") or "/usr/bin/date", *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        stub = subprocess.run(
            [str(fixture.bin / "date"), *arguments],
            env=fixture.environment(),
            text=True,
            capture_output=True,
            check=False,
        )
        after = subprocess.run(
            [shutil.which("date") or "/usr/bin/date", *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        assert before.returncode == stub.returncode == after.returncode == 0
        assert stub.stderr == before.stderr == after.stderr
        assert stub.stdout in {before.stdout, after.stdout}


def case_df_stub_matches_real_tool() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-df-fidelity-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        arguments = ("-Pk", str(fixture.data))
        stub = subprocess.run(
            [str(fixture.bin / "df"), *arguments],
            env=fixture.environment(),
            text=True,
            capture_output=True,
            check=False,
        )
        real = subprocess.run(
            [shutil.which("df") or "/usr/bin/df", *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        assert (stub.returncode, stub.stdout, stub.stderr) == (real.returncode, real.stdout, real.stderr)


def case_find_wrapper_matches_real_tool() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-find-fidelity-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        seed_finals(fixture.data, 1)
        install_find_stub(fixture)
        arguments = (
            str(fixture.data),
            "-maxdepth",
            "1",
            "-type",
            "f",
            "-name",
            "etcd-*.db.sops.json",
            "-print",
        )
        stub = subprocess.run(
            [str(fixture.bin / "find"), *arguments],
            env=fixture.environment(),
            text=True,
            capture_output=True,
            check=False,
        )
        real = subprocess.run(
            [shutil.which("find") or "/usr/bin/find", *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        assert (stub.returncode, stub.stdout, stub.stderr) == (real.returncode, real.stdout, real.stderr)


def sops_output_shape(output: bytes) -> object:
    def shape(value: object) -> object:
        if isinstance(value, dict):
            return {key: shape(item) for key, item in sorted(value.items())}
        if isinstance(value, list):
            return [shape(item) for item in value]
        return type(value).__name__

    return shape(json.loads(output))


def case_sops_stub_matches_real_tool() -> None:
    backend = RealToolBackend.discover()
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-sops-fidelity-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        real_sops = backend.sops_binary(fixture.root / "pinned-sops")
        arguments = (
            "--encrypt",
            "--age",
            AGE_RECIPIENT,
            "--input-type",
            "binary",
            "--output-type",
            "json",
            str(fixture.work / "etcd.db"),
        )
        stub = subprocess.run(
            [str(fixture.bin / "sops"), *arguments],
            cwd="/",
            env=fixture.environment(),
            capture_output=True,
            check=False,
            timeout=30,
        )
        real = subprocess.run(
            [str(real_sops), *arguments],
            cwd="/",
            env={"HOME": str(fixture.root), "PATH": os.environ["PATH"]},
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert stub.returncode == real.returncode == 0, (stub.stderr, real.stderr)
        assert sops_output_shape(stub.stdout) == sops_output_shape(real.stdout)
        for name, output in (("stub", stub.stdout), ("real", real.stdout)):
            ciphertext = fixture.root / f"{name}.json"
            ciphertext.write_bytes(output)
            status = subprocess.run(
                [str(real_sops), "filestatus", "--input-type", "json", str(ciphertext)],
                cwd="/",
                env={"HOME": str(fixture.root), "PATH": os.environ["PATH"]},
                text=True,
                capture_output=True,
                check=False,
                timeout=15,
            )
            assert status.returncode == 0, status.stderr
            assert json.loads(status.stdout) == {"encrypted": True}


def install_find_stub(
    fixture: Fixture,
    fail_on_call: int | None = None,
    *,
    omit_out_on_call: int | None = None,
) -> None:
    real_find = shutil.which("find")
    if real_find is None:
        raise AssertionError("find is required by the fixture")
    marker = fixture.root / "find-calls"
    capture = fixture.root / "find-capture"
    fail_condition = "false" if fail_on_call is None else f'[ "$calls" -eq {fail_on_call} ]'
    omit_condition = "false" if omit_out_on_call is None else f'[ "$calls" -eq {omit_out_on_call} ]'
    write_executable(
        fixture.bin / "find",
        f"""#!/bin/sh
printf 'called\\n' >>"{marker}"
calls=$(wc -l <"{marker}")
if {fail_condition}; then
  echo 'injected find I/O failure' >&2
  exit 42
fi
if {omit_condition}; then
  "{real_find}" "$@" >"{capture}" || exit $?
  while IFS= read -r found; do
    stamp=$(tail -n 1 "${{DATE_OUTPUT_MARKER:?}}")
    out_path="${{FIXTURE_DATA:?}}/etcd-$stamp.db.sops.json"
    [ "$found" = "$out_path" ] || printf '%s\\n' "$found"
  done <"{capture}"
  exit 0
fi
exec "{real_find}" "$@"
""",
    )


def assert_source_contract() -> None:
    source = extract_encrypt_script()
    cronjob = load_yaml(APP / "cronjob.yaml")
    containers = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"]
    encrypt_container = next(container for container in containers if container.get("name") == "encrypt")
    assert encrypt_container["image"] == PINNED_SOPS_IMAGE
    recipient_env = next(item for item in encrypt_container["env"] if item.get("name") == "AGE_RECIPIENT")
    assert recipient_env["value"] == AGE_RECIPIENT
    required = (
        "exec 9</data",
        'flock -n 9 || { echo "FATAL: another backup run holds /data" >&2; exit 1; }',
        'RETAINED_LIMIT=14',
        "FINAL_NAME_PATTERN='etcd-[0-9]",
        'TMP=$(mktemp "$OUT.XXXXXX.partial")',
        "--input-type binary --output-type json",
        'OUT="/data/etcd-$STAMP.db.sops.json"',
        'terminal_failure "$OUT does not exist"',
        'terminal_failure "$OUT is not a regular file"',
        'terminal_failure "$OUT is empty"',
        'terminal_failure "$OUT is absent from the retained finalized set"',
        'terminal_failure "retained finalized count $FINAL_COUNT exceeds $RETAINED_LIMIT"',
        'valid_final_stamp "$candidate_stamp"',
        '[ "$month_value" -ge 1 ] && [ "$month_value" -le 12 ]',
        '[ "$day_value" -ge 1 ] && [ "$day_value" -le "$maximum_day" ]',
        '[ "$hour_value" -le 23 ]',
        '[ "$minute_value" -le 59 ]',
        '[ "$second_value" -le 59 ]',
    )
    for fragment in required:
        if fragment not in source:
            raise AssertionError(f"missing producer contract: {fragment}")
    if 'echo "pruning final: $old ($old_size bytes)"\n  rm -- "$old"' not in source:
        raise AssertionError("final path and measured size must be logged immediately before rm")
    lock_index = source.index("flock -n 9")
    temp_index = source.index('TMP=$(mktemp "$OUT.XXXXXX.partial")')
    trap_index = source.index("trap cleanup EXIT")
    if not lock_index < temp_index < trap_index:
        raise AssertionError("lock must precede unique TMP creation and EXIT trap installation")
    forbidden = (
        ".backup.lock",
        "-mmin",
        "find -newer",
        "db.sops\"",
        'TMP="$OUT.$$.partial"',
        "date -u -d",
    )
    for fragment in forbidden:
        if fragment in source:
            raise AssertionError(f"forbidden producer contract: {fragment}")


def check_r1_ledger_claims() -> None:
    ledger = read(LEDGER)
    normalized_ledger = compact(LEDGER)
    assert "PID-scoped" not in ledger
    assert "before deriving any artifact path or installing a cleanup trap" in normalized_ledger
    assert "atomically created, run-unique temporary path" in normalized_ledger


def check_r4_threshold_annotation() -> None:
    adr_0014 = read(ADR_0014)
    normalized_adr_0014 = compact(ADR_0014)
    assert "| etcd snapshot | Every 6 hours plus before risky platform changes |" in adr_0014
    assert "SUPERSEDED pending dr2" in normalized_adr_0014
    assert "implemented daily CronJob uses a 26-hour threshold" in normalized_adr_0014


def check_r6_capacity_horizon() -> None:
    pvc = load_yaml(APP / "pvc.yaml")
    assert pvc["spec"]["resources"]["requests"]["storage"] == "32Gi"
    margin_adjusted_limit = (32 * 1024**3 - 128 * 1024**2) // 15
    assert margin_adjusted_limit == 2_281_701_376
    horizon_days = math.log(margin_adjusted_limit / 927_695_901, 1.112) * 40
    assert round(horizon_days) == 339
    for document in (compact(APP / "pvc.yaml"), compact(LEDGER)):
        assert "2,281,701,376 bytes (2,176 MiB)" in document
        assert "approximately 339 days" in document
        assert "96 GiB nominal" in document


def check_r8_work_volume_headroom() -> None:
    cronjob = load_yaml(APP / "cronjob.yaml")
    volumes = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]["volumes"]
    work = next(volume for volume in volumes if volume.get("name") == "work")
    assert work["emptyDir"]["sizeLimit"] == "2Gi"
    assert "695,771,168-byte measured raw snapshot uses 32.4% of 2 GiB" in read(APP / "cronjob.yaml")


def check_r11_dr2_technical_debt() -> None:
    register = read(TECH_DEBT)
    assert "| TD-0023 | Reconcile etcd snapshot cadence, retention, and staleness threshold | Open | **High** |" in register
    td_0023 = register.split("## TD-0023", 1)[1]
    assert "dr2" in td_0023
    assert "6-hour cadence" in td_0023
    assert "daily/14-artifact" in td_0023
    assert "8-hour" in td_0023 and "26-hour" in td_0023
    assert "48.4 GiB" in td_0023


def check_r12_evidence_honesty() -> None:
    ledger = read(LEDGER)
    assert "/home/hellbomb" not in ledger
    assert "Final-commit and live-cluster gate attestation remains owner-run" in ledger


def check_r13_precision_corrections() -> None:
    normalized_adr_0026 = compact(ADR_0026)
    assert "14 local artifacts and 14 Synology copies are retained" in normalized_adr_0026
    assert "The local set uses 12.096 GiB on the PVC" in normalized_adr_0026
    assert "The Synology set adds approximately 12.096 GiB" in normalized_adr_0026
    assert "observes CronJob success status, not the snapshot artifact" in normalized_adr_0026
    assert "cannot prove that the PVC contains a decryptable snapshot" in normalized_adr_0026
    assert "109 MB snapshot" not in read(APP / "talosconfig.sops.yaml")


def check_remediation_evidence_claims() -> None:
    ledger = compact(LEDGER)
    assert "pinned-image real-tool producer fixture" in ledger
    assert "Differential checks compare every normal `date`, `df`, `find`, and SOPS wrapper path" in ledger
    assert "prove rc=0, retention of the new artifact, and write-then-prune behavior" in ledger
    assert "0, 1, 14, and 15 canonical pre-existing finals" in ledger
    assert "hermetic producer fixtures" not in ledger


def check_operator_wedge_recovery() -> None:
    runbook = compact(DR_RUNBOOK)
    assert "FATAL: invalid finalized snapshot name" in runbook
    assert "FATAL: future finalized snapshot ... sorts after current output" in runbook
    assert "copy the file to approved offline quarantine" in runbook
    assert "first verify node UTC time is correct" in runbook
    assert "quarantine or remove the future artifact" in runbook
    assert "terminal artifact assertion passed" in runbook
    assert "lastSuccessfulTime" in runbook


def check_exit_gate_commands_are_named() -> None:
    ledger = compact(LEDGER)
    required_commands = (
        "kubectl kustomize clusters/talos-cluster",
        "python3 scripts/test-dr-etcd-backup.py",
        "python3 scripts/test-talos-drift-readonly.py",
        "python3 scripts/render-dr-schedule-values.py --check",
        "python3 scripts/render-talos-drift-expected.py --check",
        "python3 scripts/render-scripts-readme-counts.py --check",
        "python3 scripts/check-text-encoding.py",
        "python3 scripts/check-doc-links.py",
        "python3 scripts/check-sops-encrypted.py",
    )
    for command in required_commands:
        assert command in ledger


def case_lock_held_touches_nothing() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-lock-held-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        existing = seed_finals(fixture.data, 1)[0]
        partials, _legacy = seed_mixed_nonfinals(fixture.data)
        before = {path.name: path.read_bytes() for path in fixture.data.iterdir()}
        descriptor = os.open(fixture.data, os.O_RDONLY | os.O_DIRECTORY)
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = fixture.run(expected_tools=set())
        finally:
            os.close(descriptor)
        after = {path.name: path.read_bytes() for path in fixture.data.iterdir()}
        assert result.returncode != 0
        assert f"FATAL: another backup run holds {fixture.data}" in result.stderr
        assert before == after
        assert existing.exists()
        assert all(path.exists() for path in partials)


def case_lock_refusal_cannot_unlink_colliding_partial() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-lock-collision-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        ready = fixture.root / "flock-ready"
        release = fixture.root / "flock-release"
        write_executable(
            fixture.bin / "flock",
            """#!/bin/sh
: >"${FLOCK_READY:?}"
while [ ! -e "${FLOCK_RELEASE:?}" ]; do
  sleep 0.01
done
exit 1
""",
        )
        process = subprocess.Popen(
            ["/bin/sh", str(fixture.script)],
            cwd=fixture.root,
            env=fixture.environment({"FLOCK_READY": str(ready), "FLOCK_RELEASE": str(release)}),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 5
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists(), "contender did not reach flock"
        collided = fixture.data / f"winner.{process.pid}.partial"
        collided.write_bytes(b"winner-in-flight-ciphertext")
        release.touch()
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode != 0, stdout
        assert f"FATAL: another backup run holds {fixture.data}" in stderr
        assert collided.read_bytes() == b"winner-in-flight-ciphertext"
        fixture.assert_tool_invocations(set())


def case_lock_released_after_process_death() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-lock-death-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        holder = subprocess.Popen(
            [
                "/bin/sh",
                "-c",
                'exec 9<"$1"; flock -n 9; echo READY; while :; do sleep 1; done',
                "holder",
                str(fixture.data),
            ],
            text=True,
            stdout=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            assert holder.stdout is not None
            assert holder.stdout.readline().strip() == "READY"
            os.killpg(holder.pid, signal.SIGKILL)
            holder.wait(timeout=5)
            result = fixture.run(expected_tools={"date", "df", "sops"})
        finally:
            if holder.poll() is None:
                os.killpg(holder.pid, signal.SIGKILL)
                holder.wait(timeout=5)
        assert result.returncode == 0, result.stderr
        assert fixture.generated_out().is_file()


def case_same_second_out_is_not_clobbered() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-no-clobber-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        partials, _legacy = seed_mixed_nonfinals(fixture.data)
        result = fixture.run(expected_tools={"date"}, DATE_CREATE_OUT="1")
        out = fixture.generated_out()
        assert result.returncode != 0
        assert f"FATAL: refusing to overwrite existing finalized snapshot: {out}" in result.stderr
        assert out.read_bytes() == b"existing-final"
        assert all(not path.exists() for path in partials)
        assert not list(fixture.data.glob("*.partial"))


def case_capacity_failure_preserves_finals() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-capacity-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        existing = seed_finals(fixture.data, 1)[0]
        original = existing.read_bytes()
        partials, _legacy = seed_mixed_nonfinals(fixture.data)
        marker = fixture.tool_markers["sops"]
        result = fixture.run(expected_tools={"date", "df"}, TEST_AVAILABLE_KIB="1")
        assert result.returncode != 0
        size = MIN_SNAPSHOT_BYTES + 1
        projected = ((size + 2) // 3) * 4 + 1009
        required = projected + 134_217_728
        diagnostic = (
            f"FATAL: insufficient free space on {fixture.data}: available 1024 bytes; "
            f"require {required} bytes (projected SOPS {projected} + margin 134217728)"
        )
        assert diagnostic in result.stderr.splitlines()
        assert existing.read_bytes() == original
        assert all(not path.exists() for path in partials)
        assert not marker.exists()
        assert not fixture.generated_out().exists()


def case_sops_failure_preserves_finals_and_cleans_tmp() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-sops-failure-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        existing = seed_finals(fixture.data, 1)[0]
        original = existing.read_bytes()
        partials, _legacy = seed_mixed_nonfinals(fixture.data)
        result = fixture.run(expected_tools={"date", "df", "sops"}, SOPS_FAIL="1")
        assert result.returncode != 0
        assert f"FATAL: sops encryption failed for {fixture.work / 'etcd.db'}" in result.stderr.splitlines()
        assert existing.read_bytes() == original
        assert all(not path.exists() for path in partials)
        assert not list(fixture.data.glob("*.partial"))
        assert not fixture.generated_out().exists()


def case_implausibly_small_ciphertext_is_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-small-output-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        existing = seed_finals(fixture.data, 1)[0]
        original = existing.read_bytes()
        result = fixture.run(
            expected_tools={"date", "df", "sops"},
            SOPS_SIZE_DELTA=f"-{MIN_SNAPSHOT_BYTES}",
        )
        assert result.returncode != 0
        assert "FATAL: encrypted output is implausibly small" in result.stderr
        assert existing.read_bytes() == original
        assert not list(fixture.data.glob("*.partial"))
        assert not fixture.generated_out().exists()


def case_terminal_assertion_rejects_missing_own_out() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-terminal-assert-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        result = fixture.run(
            expected_tools={"date", "df", "sops"},
            DF_MUTATE_ON_CALL="3",
            DF_MUTATION="remove-out",
        )
        out = fixture.generated_out()
        assert result.returncode != 0
        assert "FATAL: terminal artifact assertion failed" in result.stderr
        assert not out.exists()


def case_terminal_assertion_rejects_bad_own_out(mutation: str, diagnostic: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f".dr-etcd-terminal-{mutation}-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        result = fixture.run(
            expected_tools={"date", "df", "sops"},
            DF_MUTATE_ON_CALL="3",
            DF_MUTATION=mutation,
        )
        assert result.returncode != 0
        assert "FATAL: terminal artifact assertion failed" in result.stderr
        assert diagnostic in result.stderr


def case_terminal_assertion_rejects_retained_count_over_limit() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-terminal-count-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        result = fixture.run(
            expected_tools={"date", "df", "sops"},
            DF_MUTATE_ON_CALL="3",
            DF_MUTATION="add-finals",
        )
        assert result.returncode != 0
        assert "FATAL: terminal artifact assertion failed: retained finalized count 15 exceeds 14" in result.stderr


def case_terminal_assertion_requires_own_out_in_inventory() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-terminal-membership-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        install_find_stub(fixture, omit_out_on_call=6)
        result = fixture.run(expected_tools={"date", "df", "sops"})
        out = fixture.generated_out()
        assert result.returncode != 0
        assert f"FATAL: terminal artifact assertion failed: {out} is absent from the retained finalized set" in result.stderr
        assert out.is_file() and out.stat().st_size >= MIN_SNAPSHOT_BYTES


def case_find_failure_fails_closed(fail_on_call: int) -> None:
    with tempfile.TemporaryDirectory(prefix=f".dr-etcd-find-{fail_on_call}-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        originals = seed_finals(fixture.data, 14)
        before = {path.name: path.read_bytes() for path in originals}
        install_find_stub(fixture, fail_on_call)
        result = fixture.run(expected_tools=None)
        assert result.returncode != 0
        assert "FATAL: could not inventory finalized snapshots" in result.stderr
        surviving = {path.name: path.read_bytes() for path in originals if path.exists()}
        expected_survivors = 14 if fail_on_call <= 4 else 13
        assert len(surviving) == expected_survivors
        assert all(before[name] == content for name, content in surviving.items())
        assert fixture.generated_out().exists() is (fail_on_call >= 3)


def case_future_final_is_rejected_before_publication() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-future-final-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        now = datetime.now(timezone.utc)
        future_finals = [
            final_path(fixture.data, (now + timedelta(days=day + 1)).strftime("%Y-%m-%dT%H%M%SZ"))
            for day in range(1, 15)
        ]
        for path in future_finals:
            path.write_bytes(b"future-final")
        before = {path.name: path.read_bytes() for path in future_finals}
        result = fixture.run(expected_tools={"date"})
        assert result.returncode != 0
        assert "FATAL: future finalized snapshot" in result.stderr
        assert {path.name: path.read_bytes() for path in future_finals} == before
        assert not fixture.generated_out().exists()


def case_newline_final_name_is_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-newline-final-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        ordinary = seed_finals(fixture.data, 14)
        malformed = fixture.data / "etcd-2026-08-15T030000Z\nextra.db.sops.json"
        malformed.write_bytes(b"newline-final")
        before = {path.name: path.read_bytes() for path in (*ordinary, malformed)}
        result = fixture.run(expected_tools={"date"})
        assert result.returncode != 0
        assert "FATAL: invalid finalized snapshot name" in result.stderr
        assert {path.name: path.read_bytes() for path in (*ordinary, malformed)} == before
        assert not fixture.generated_out().exists()


def case_impossible_calendar_final_name_is_rejected() -> None:
    invalid_stamps = (
        "0000-01-01T000000Z",
        "2026-00-01T000000Z",
        "2026-13-01T000000Z",
        "2026-01-00T000000Z",
        "2026-02-29T000000Z",
        "2026-02-30T030000Z",
        "2026-04-31T000000Z",
        "2026-01-01T240000Z",
        "2026-01-01T006000Z",
        "2026-01-01T000060Z",
    )
    for invalid_stamp in invalid_stamps:
        with tempfile.TemporaryDirectory(prefix=".dr-etcd-calendar-final-", dir=ROOT) as tmp:
            fixture = Fixture.create(Path(tmp))
            malformed = final_path(fixture.data, invalid_stamp)
            malformed.write_bytes(b"impossible-calendar-final")
            result = fixture.run(expected_tools={"date"})
            assert result.returncode != 0
            assert f"FATAL: invalid finalized snapshot name: {malformed}" in result.stderr
            assert malformed.read_bytes() == b"impossible-calendar-final"
            assert not fixture.generated_out().exists()


def case_leap_day_final_name_is_accepted() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-leap-final-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        leap_final = final_path(fixture.data, "2024-02-29T235959Z")
        leap_final.write_bytes(b"leap-day-final")
        result = fixture.run(expected_tools={"date", "df", "sops"})
        assert result.returncode == 0, result.stderr
        assert leap_final.read_bytes() == b"leap-day-final"
        assert fixture.generated_out().is_file()


def case_non_executable_stub_is_rejected(tool: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f".dr-etcd-stub-{tool}-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        (fixture.bin / tool).chmod(0o644)
        try:
            fixture.run(expected_tools={"date", "df", "sops"})
        except AssertionError as exc:
            assert "stub invocation mismatch" in str(exc)
            assert tool not in {
                name
                for name, marker in fixture.tool_markers.items()
                if marker.is_file() and marker.stat().st_size
            }
        else:
            raise AssertionError(f"non-executable {tool} stub was not detected")


def case_final_count(count: int) -> None:
    with tempfile.TemporaryDirectory(prefix=f".dr-etcd-finals-{count}-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        originals = seed_finals(fixture.data, count)
        partials, legacy_final = seed_mixed_nonfinals(fixture.data)
        partial_sizes = {path: path.stat().st_size for path in partials}
        original_sizes = {path: path.stat().st_size for path in originals}
        result = fixture.run(expected_tools={"date", "df", "sops"})
        assert result.returncode == 0, result.stderr
        assert all(not path.exists() for path in partials)
        for path, size in partial_sizes.items():
            assert f"removing partial: {path} ({size} bytes)" in result.stdout
        assert legacy_final.read_bytes() == b"legacy-final"

        finals = sorted(fixture.data.glob(f"etcd-*{FINAL_SUFFIX}"))
        assert len(finals) == min(count + 1, 14)
        newest = fixture.generated_out()
        assert newest in finals
        assert f"newest finalized snapshot: {newest}" in result.stdout
        assert f"finalized snapshots: {len(finals)}" in result.stdout

        pruned = originals[: max(0, count + 1 - 14)]
        retained = originals[max(0, count + 1 - 14) :]
        for path in pruned:
            assert not path.exists()
            assert f"pruning final: {path} ({original_sizes[path]} bytes)" in result.stdout
        for path in retained:
            assert path.exists()


def main() -> int:
    cases: list[tuple[str, Callable[[], None]]] = [
        ("real-tool end-to-end with 0/1/14/15 finals", case_real_tools_end_to_end),
        ("date stub matches real tool", case_date_stub_matches_real_tool),
        ("df stub matches real tool", case_df_stub_matches_real_tool),
        ("find wrapper matches real tool", case_find_wrapper_matches_real_tool),
        ("SOPS stub matches real pinned tool", case_sops_stub_matches_real_tool),
        ("source contract", assert_source_contract),
        ("R1 ledger claims", check_r1_ledger_claims),
        ("R4 threshold annotation", check_r4_threshold_annotation),
        ("R6 capacity horizon", check_r6_capacity_horizon),
        ("R8 work-volume headroom", check_r8_work_volume_headroom),
        ("R11 dr2 technical debt", check_r11_dr2_technical_debt),
        ("R12 evidence honesty", check_r12_evidence_honesty),
        ("R13 precision corrections", check_r13_precision_corrections),
        ("remediation evidence claims", check_remediation_evidence_claims),
        ("operator wedge recovery", check_operator_wedge_recovery),
        ("exit-gate commands are named", check_exit_gate_commands_are_named),
        ("lock held touches nothing", case_lock_held_touches_nothing),
        ("lock refusal preserves colliding winner partial", case_lock_refusal_cannot_unlink_colliding_partial),
        ("lock released after process death", case_lock_released_after_process_death),
        ("same-second OUT no-clobber", case_same_second_out_is_not_clobbered),
        ("capacity failure preserves finals", case_capacity_failure_preserves_finals),
        ("SOPS failure preserves finals", case_sops_failure_preserves_finals_and_cleans_tmp),
        ("implausibly small ciphertext", case_implausibly_small_ciphertext_is_rejected),
        ("terminal assertion rejects missing own OUT", case_terminal_assertion_rejects_missing_own_out),
        (
            "terminal assertion rejects directory OUT",
            lambda: case_terminal_assertion_rejects_bad_own_out(
                "directory-out", "is not a regular file"
            ),
        ),
        (
            "terminal assertion rejects empty OUT",
            lambda: case_terminal_assertion_rejects_bad_own_out(
                "empty-out", "is empty"
            ),
        ),
        (
            "terminal assertion rejects implausibly small OUT",
            lambda: case_terminal_assertion_rejects_bad_own_out(
                "small-out", "is implausibly small"
            ),
        ),
        ("terminal assertion enforces retained limit", case_terminal_assertion_rejects_retained_count_over_limit),
        ("terminal assertion requires own OUT in retained inventory", case_terminal_assertion_requires_own_out_in_inventory),
        *((f"find failure call {call}", lambda call=call: case_find_failure_fails_closed(call)) for call in range(1, 7)),
        ("future finalized names fail closed", case_future_final_is_rejected_before_publication),
        ("newline finalized name fails closed", case_newline_final_name_is_rejected),
        ("impossible calendar finalized name fails closed", case_impossible_calendar_final_name_is_rejected),
        ("valid leap-day finalized name is accepted", case_leap_day_final_name_is_accepted),
        *((f"non-executable {tool} stub is rejected", lambda tool=tool: case_non_executable_stub_is_rejected(tool)) for tool in ("date", "df", "sops")),
        *((f"write-then-prune with {count} finals", lambda count=count: case_final_count(count)) for count in (0, 1, 14, 15)),
    ]
    failed = False
    for name, case in cases:
        try:
            case()
        except Exception:  # noqa: BLE001 - retain every independent fixture result.
            failed = True
            print(f"FAIL: {name}")
            traceback.print_exc()
        else:
            print(f"PASS: {name}")
    if failed:
        print("etcd backup producer tests failed")
        return 1
    print("etcd backup producer tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
