#!/usr/bin/env python3
"""Hermetic failure and ordering fixtures for the etcd backup producer."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIGMAP = ROOT / "clusters/talos-cluster/apps/dr-etcd-backup/configmap-encrypt-script.yaml"
STAMP = "2026-08-31T030000Z"
FINAL_SUFFIX = ".db.sops.json"
MIN_SNAPSHOT_BYTES = 10_000_000


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


@dataclass
class Fixture:
    root: Path
    data: Path
    work: Path
    bin: Path
    script: Path

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
            "#!/bin/sh\nprintf '%s\\n' \"${TEST_STAMP:?}\"\n",
        )
        write_executable(
            bin_dir / "df",
            """#!/bin/sh
printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'
printf 'fixture 20000000 0 %s 0%% %s\n' "${TEST_AVAILABLE_KIB:-20000000}" "${2:-${1:-unknown}}"
""",
        )
        write_executable(
            bin_dir / "sops",
            """#!/bin/sh
if [ -n "${SOPS_MARKER:-}" ]; then
  : >"$SOPS_MARKER"
fi
if [ "${SOPS_FAIL:-0}" = 1 ]; then
  echo 'injected sops failure' >&2
  exit 42
fi
input=
for argument do
  input=$argument
done
size=$(stat -c%s "$input")
output_size=$((size + ${SOPS_SIZE_DELTA:-1009}))
python3 -c 'import os, sys; os.ftruncate(1, int(sys.argv[1]))' "$output_size"
""",
        )
        return cls(root=root, data=data, work=work, bin=bin_dir, script=script)

    def run(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "AGE_RECIPIENT": "age1fixture",
                "PATH": f"{self.bin}:{env['PATH']}",
                "TEST_STAMP": STAMP,
            }
        )
        env.update(overrides)
        return subprocess.run(
            ["/bin/sh", str(self.script)],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )


def final_path(data: Path, stamp: str) -> Path:
    return data / f"etcd-{stamp}{FINAL_SUFFIX}"


def seed_finals(data: Path, count: int) -> list[Path]:
    finals: list[Path] = []
    for day in range(1, count + 1):
        path = final_path(data, f"2026-08-{day:02d}T030000Z")
        path.write_bytes(f"final-{day:02d}".encode())
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


def assert_source_contract() -> None:
    source = extract_encrypt_script()
    required = (
        "exec 9</data",
        'flock -n 9 || { echo "FATAL: another backup run holds /data" >&2; exit 1; }',
        "--input-type binary --output-type json",
        'OUT="/data/etcd-$STAMP.db.sops.json"',
    )
    for fragment in required:
        if fragment not in source:
            raise AssertionError(f"missing producer contract: {fragment}")
    if 'echo "pruning final: $old ($old_size bytes)"\n  rm -- "$old"' not in source:
        raise AssertionError("final path and measured size must be logged immediately before rm")
    forbidden = (".backup.lock", "-mmin", "find -newer", "db.sops\"")
    for fragment in forbidden:
        if fragment in source:
            raise AssertionError(f"forbidden producer contract: {fragment}")


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
            result = fixture.run()
        finally:
            os.close(descriptor)
        after = {path.name: path.read_bytes() for path in fixture.data.iterdir()}
        assert result.returncode != 0
        assert f"FATAL: another backup run holds {fixture.data}" in result.stderr
        assert before == after
        assert existing.exists()
        assert all(path.exists() for path in partials)


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
            result = fixture.run()
        finally:
            if holder.poll() is None:
                os.killpg(holder.pid, signal.SIGKILL)
                holder.wait(timeout=5)
        assert result.returncode == 0, result.stderr
        assert final_path(fixture.data, STAMP).is_file()


def case_same_second_out_is_not_clobbered() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-no-clobber-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        out = final_path(fixture.data, STAMP)
        out.write_bytes(b"existing-final")
        result = fixture.run()
        assert result.returncode != 0
        assert f"FATAL: refusing to overwrite existing finalized snapshot: {out}" in result.stderr
        assert out.read_bytes() == b"existing-final"
        assert not list(fixture.data.glob("*.partial"))


def case_capacity_failure_preserves_finals() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-capacity-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        existing = seed_finals(fixture.data, 1)[0]
        original = existing.read_bytes()
        partials, _legacy = seed_mixed_nonfinals(fixture.data)
        marker = fixture.root / "sops-called"
        result = fixture.run(TEST_AVAILABLE_KIB="1", SOPS_MARKER=str(marker))
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
        assert not final_path(fixture.data, STAMP).exists()


def case_sops_failure_preserves_finals_and_cleans_tmp() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-sops-failure-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        existing = seed_finals(fixture.data, 1)[0]
        original = existing.read_bytes()
        partials, _legacy = seed_mixed_nonfinals(fixture.data)
        result = fixture.run(SOPS_FAIL="1")
        assert result.returncode != 0
        assert f"FATAL: sops encryption failed for {fixture.work / 'etcd.db'}" in result.stderr.splitlines()
        assert existing.read_bytes() == original
        assert all(not path.exists() for path in partials)
        assert not list(fixture.data.glob("*.partial"))
        assert not final_path(fixture.data, STAMP).exists()


def case_implausibly_small_ciphertext_is_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix=".dr-etcd-small-output-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        existing = seed_finals(fixture.data, 1)[0]
        original = existing.read_bytes()
        result = fixture.run(SOPS_SIZE_DELTA=f"-{MIN_SNAPSHOT_BYTES}")
        assert result.returncode != 0
        assert "FATAL: encrypted output is implausibly small" in result.stderr
        assert existing.read_bytes() == original
        assert not list(fixture.data.glob("*.partial"))
        assert not final_path(fixture.data, STAMP).exists()


def case_final_count(count: int) -> None:
    with tempfile.TemporaryDirectory(prefix=f".dr-etcd-finals-{count}-", dir=ROOT) as tmp:
        fixture = Fixture.create(Path(tmp))
        originals = seed_finals(fixture.data, count)
        partials, legacy_final = seed_mixed_nonfinals(fixture.data)
        partial_sizes = {path: path.stat().st_size for path in partials}
        original_sizes = {path: path.stat().st_size for path in originals}
        result = fixture.run()
        assert result.returncode == 0, result.stderr
        assert all(not path.exists() for path in partials)
        for path, size in partial_sizes.items():
            assert f"removing partial: {path} ({size} bytes)" in result.stdout
        assert legacy_final.read_bytes() == b"legacy-final"

        finals = sorted(fixture.data.glob(f"etcd-*{FINAL_SUFFIX}"))
        assert len(finals) == min(count + 1, 14)
        newest = final_path(fixture.data, STAMP)
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
        ("source contract", assert_source_contract),
        ("lock held touches nothing", case_lock_held_touches_nothing),
        ("lock released after process death", case_lock_released_after_process_death),
        ("same-second OUT no-clobber", case_same_second_out_is_not_clobbered),
        ("capacity failure preserves finals", case_capacity_failure_preserves_finals),
        ("SOPS failure preserves finals", case_sops_failure_preserves_finals_and_cleans_tmp),
        ("implausibly small ciphertext", case_implausibly_small_ciphertext_is_rejected),
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
