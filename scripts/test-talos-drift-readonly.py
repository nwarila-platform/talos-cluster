#!/usr/bin/env python3
"""Unit tests for the reduced read-only talos-drift checker."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "clusters/talos-cluster/apps/talos-drift/check.py"
RENDERER = ROOT / "scripts/render-talos-drift-expected.py"


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def matching_inputs(checker: ModuleType) -> tuple[dict[str, str], str, dict, dict, dict, dict]:
    expected_nodes = checker.parse_expected_nodes("cp1=10.69.112.63,w1=10.69.112.68")
    talos_log = """Client:
Talos v1.13.2
Server:
    NODE:        10.69.112.63
    Tag:         v1.13.2
    NODE:        10.69.112.68
    Tag:         v1.13.2
"""
    version_payload = {"gitVersion": "v1.36.0"}
    nodes_payload = {
        "items": [
            {
                "metadata": {"name": "cp1"},
                "status": {
                    "nodeInfo": {"kubeletVersion": "v1.36.0"},
                    "addresses": [{"type": "InternalIP", "address": "10.69.112.63"}],
                },
            },
            {
                "metadata": {"name": "w1"},
                "status": {
                    "nodeInfo": {"kubeletVersion": "v1.36.0"},
                    "addresses": [{"type": "InternalIP", "address": "10.69.112.68"}],
                },
            },
        ]
    }
    flux_payload = {
        "items": [
            {
                "metadata": {"namespace": "flux-system", "name": "cluster"},
                "spec": {"suspend": False},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            }
        ]
    }
    return expected_nodes, talos_log, version_payload, nodes_payload, flux_payload, flux_payload


def test_matching_fixture() -> None:
    checker = load_module(CHECKER, "talos_drift_checker")
    expected_nodes, talos_log, version_payload, nodes_payload, kustomizations, helmreleases = matching_inputs(checker)
    problems: list[str] = []
    problems.extend(checker.check_talos_versions("v1.13.2", expected_nodes, talos_log))
    problems.extend(checker.check_kubernetes_version("v1.36.0", expected_nodes, version_payload, nodes_payload))
    problems.extend(checker.check_flux_resources("Kustomization", kustomizations))
    problems.extend(checker.check_flux_resources("HelmRelease", helmreleases))
    assert problems == []


def test_injected_drift_fixture() -> None:
    checker = load_module(CHECKER, "talos_drift_checker_drift")
    expected_nodes, talos_log, version_payload, nodes_payload, kustomizations, _ = matching_inputs(checker)
    talos_log = talos_log.replace("10.69.112.68\n    Tag:         v1.13.2", "10.69.112.68\n    Tag:         v1.13.1")
    version_payload["gitVersion"] = "v1.36.1"
    nodes_payload["items"][0]["status"]["addresses"][0]["address"] = "10.69.112.99"
    kustomizations["items"][0]["spec"]["suspend"] = True
    kustomizations["items"][0]["status"]["conditions"][0] = {
        "type": "Ready",
        "status": "False",
        "reason": "ReconciliationFailed",
        "message": "drift detected",
    }

    problems: list[str] = []
    problems.extend(checker.check_talos_versions("v1.13.2", expected_nodes, talos_log))
    problems.extend(checker.check_kubernetes_version("v1.36.0", expected_nodes, version_payload, nodes_payload))
    problems.extend(checker.check_flux_resources("Kustomization", kustomizations))

    assert any("Talos node w1" in problem for problem in problems)
    assert any("Kubernetes API server" in problem for problem in problems)
    assert any("InternalIP" in problem for problem in problems)
    assert any("suspended" in problem for problem in problems)
    assert any("drift detected" in problem for problem in problems)


def test_expected_env_is_fresh() -> None:
    renderer = load_module(RENDERER, "talos_drift_expected_renderer")
    rendered = renderer.render(renderer.parse_config_env((ROOT / "cluster/config.env").read_text(encoding="utf-8")))
    expected = (ROOT / "clusters/talos-cluster/apps/talos-drift/expected.env").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert rendered == expected


def main() -> int:
    test_matching_fixture()
    test_injected_drift_fixture()
    test_expected_env_is_fresh()
    print("talos-drift read-only tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
