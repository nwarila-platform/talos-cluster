#!/usr/bin/env python3
"""Regression self-test for the Flux CRD served/storage version guard."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[1]
GUARD = Path(
    os.environ.get(
        "FLUX_CRD_GUARD",
        str(ROOT / "scripts/check-flux-crd-served-versions.py"),
    )
)
GOTK_COMPONENTS = ROOT / "clusters/talos-cluster/flux-system/gotk-components.yaml"
ALERTS_CRD = "alerts.notification.toolkit.fluxcd.io"


@dataclass(frozen=True)
class GuardRun:
    rc: int
    stdout: str
    stderr: str

    @property
    def combined_output(self) -> str:
        return self.stdout + self.stderr


@dataclass(frozen=True)
class CaseFixture:
    guard: Path
    path: Path | None = None


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected_rc: int
    actual_rc: int
    output_check: str
    passed: bool
    stdout: str
    stderr: str


def run_guard(fixture: CaseFixture) -> GuardRun:
    cmd = [sys.executable, str(fixture.guard)]
    if fixture.path is not None:
        cmd.append(str(fixture.path))

    result = subprocess.run(
        cmd,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return GuardRun(result.returncode, result.stdout, result.stderr)


def load_current_documents() -> list[object]:
    with GOTK_COMPONENTS.open(encoding="utf-8") as handle:
        return list(yaml.safe_load_all(handle))


def write_documents(path: Path, documents: Sequence[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump_all(
            documents,
            handle,
            explicit_start=True,
            sort_keys=False,
        )


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def current_fixture(_root: Path) -> CaseFixture:
    return CaseFixture(guard=GUARD)


def find_crd(documents: Sequence[object], name: str) -> dict[object, object]:
    for document in documents:
        if not isinstance(document, dict):
            continue
        metadata = document.get("metadata")
        if (
            document.get("kind") == "CustomResourceDefinition"
            and isinstance(metadata, dict)
            and metadata.get("name") == name
        ):
            return document
    raise AssertionError(f"fixture CRD not found: {name}")


def current_copy_path(root: Path) -> tuple[Path, list[object]]:
    path = root / "gotk-components.yaml"
    documents = load_current_documents()
    return path, documents


def patched_removal_guard(root: Path) -> Path:
    source = GUARD.read_text(encoding="utf-8")
    old = (
        '    "alerts.notification.toolkit.fluxcd.io": {\n'
        '        "served": ["v1beta3"],\n'
        '        "storage": "v1beta3",\n'
        "    },"
    )
    new = (
        '    "alerts.notification.toolkit.fluxcd.io": {\n'
        '        "served": ["v1beta2", "v1beta3"],\n'
        '        "storage": "v1beta3",\n'
        "    },"
    )
    if old not in source:
        raise AssertionError("could not patch expected Flux CRD version map")

    guard = root / "check-flux-crd-served-versions.expected-removal.py"
    guard.write_text(source.replace(old, new, 1), encoding="utf-8")
    return guard


def removal_fixture(root: Path) -> CaseFixture:
    return CaseFixture(guard=patched_removal_guard(root), path=GOTK_COMPONENTS)


def addition_fixture(root: Path) -> CaseFixture:
    path, documents = current_copy_path(root)
    versions = find_crd(documents, ALERTS_CRD)["spec"]["versions"]
    versions.append({"name": "v1beta4", "served": True, "storage": False})
    write_documents(path, documents)
    return CaseFixture(guard=GUARD, path=path)


def storage_change_fixture(root: Path) -> CaseFixture:
    path, documents = current_copy_path(root)
    versions = find_crd(documents, ALERTS_CRD)["spec"]["versions"]
    for version in versions:
        if version["name"] == "v1beta3":
            version["storage"] = False
    versions.append({"name": "v1beta4", "served": False, "storage": True})
    write_documents(path, documents)
    return CaseFixture(guard=GUARD, path=path)


def crd_added_fixture(root: Path) -> CaseFixture:
    path, documents = current_copy_path(root)
    documents.append(
        {
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "widgets.example.com"},
            "spec": {
                "versions": [
                    {"name": "v1", "served": True, "storage": True},
                ],
            },
        }
    )
    write_documents(path, documents)
    return CaseFixture(guard=GUARD, path=path)


def crd_missing_fixture(root: Path) -> CaseFixture:
    path, documents = current_copy_path(root)
    filtered = [
        document
        for document in documents
        if not (
            isinstance(document, dict)
            and document.get("kind") == "CustomResourceDefinition"
            and isinstance(document.get("metadata"), dict)
            and document["metadata"].get("name") == ALERTS_CRD
        )
    ]
    write_documents(path, filtered)
    return CaseFixture(guard=GUARD, path=path)


def no_served_fixture(root: Path) -> CaseFixture:
    path, documents = current_copy_path(root)
    versions = find_crd(documents, ALERTS_CRD)["spec"]["versions"]
    for version in versions:
        version["served"] = False
    write_documents(path, documents)
    return CaseFixture(guard=GUARD, path=path)


def unparseable_fixture(root: Path) -> CaseFixture:
    path = root / "broken.yaml"
    write_text(
        path,
        """
        apiVersion: [
        """,
    )
    return CaseFixture(guard=GUARD, path=path)


def missing_file_fixture(root: Path) -> CaseFixture:
    return CaseFixture(guard=GUARD, path=root / "missing.yaml")


def output_tail(text: str, line_count: int = 16) -> str:
    lines = text.splitlines()
    if len(lines) > line_count:
        lines = ["..."] + lines[-line_count:]
    return "\n".join(lines)


def run_case(
    name: str,
    expected_rc: int,
    fixture_factory: Callable[[Path], CaseFixture],
    required_output: Sequence[str],
) -> CaseResult:
    with tempfile.TemporaryDirectory(prefix="flux-crd-served-guard-") as tmpdir:
        fixture = fixture_factory(Path(tmpdir))
        run = run_guard(fixture)

    missing_output = [
        required for required in required_output if required not in run.combined_output
    ]
    if not required_output:
        output_check = "not-required"
    elif missing_output:
        output_check = "missing:" + ",".join(missing_output)
    else:
        output_check = "present"

    return CaseResult(
        name=name,
        expected_rc=expected_rc,
        actual_rc=run.rc,
        output_check=output_check,
        passed=run.rc == expected_rc and not missing_output,
        stdout=run.stdout,
        stderr=run.stderr,
    )


def print_table(results: list[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected  actual  output-check  result")
    print(f"{'-' * name_width}  --------  ------  ------------  ------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.name:<{name_width}}  "
            f"{result.expected_rc:^8}  {result.actual_rc:^6}  "
            f"{result.output_check:<12}  {status}"
        )


def main() -> int:
    results = [
        run_case(
            "current-shape-pass",
            0,
            current_fixture,
            ("PASS:", "11 CRDs", ALERTS_CRD),
        ),
        run_case(
            "served-removal-bites",
            1,
            removal_fixture,
            (
                ALERTS_CRD,
                "v1beta2",
                "a served version was removed",
                "status.storedVersions",
            ),
        ),
        run_case(
            "served-addition-bites",
            1,
            addition_fixture,
            (ALERTS_CRD, "served versions added", "deliberate map update"),
        ),
        run_case(
            "storage-change-bites",
            1,
            storage_change_fixture,
            (ALERTS_CRD, "storage version changed", "deliberate map update"),
        ),
        run_case(
            "crd-added-bites",
            1,
            crd_added_fixture,
            ("widgets.example.com", "missing from EXPECTED_FLUX_CRD_VERSIONS"),
        ),
        run_case(
            "crd-missing-bites",
            1,
            crd_missing_fixture,
            (
                ALERTS_CRD,
                "missing from gotk-components.yaml",
                "deliberate map update",
            ),
        ),
        run_case(
            "no-served-fails-closed",
            2,
            no_served_fixture,
            ("GuardUsageError", "has no served versions"),
        ),
        run_case(
            "unparseable-fails-closed",
            2,
            unparseable_fixture,
            ("GuardUsageError", "YAML parse error"),
        ),
        run_case(
            "missing-file-fails-closed",
            2,
            missing_file_fixture,
            ("GuardUsageError", "missing file"),
        ),
    ]

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for result in failures:
            print(
                f"\n[{result.name}] expected rc {result.expected_rc}, "
                f"got rc {result.actual_rc}; output-check={result.output_check}",
                file=sys.stderr,
            )
            stderr_tail = output_tail(result.stderr)
            stdout_tail = output_tail(result.stdout)
            if stderr_tail:
                print("stderr tail:", file=sys.stderr)
                print(stderr_tail, file=sys.stderr)
            if stdout_tail:
                print("stdout tail:", file=sys.stderr)
                print(stdout_tail, file=sys.stderr)
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
