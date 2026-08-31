#!/usr/bin/env python3
"""Hermetic tests for the reduced read-only talos-drift checker."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "clusters/talos-cluster/apps/talos-drift/check.py"
RENDERER = ROOT / "scripts/render-talos-drift-expected.py"
NOW = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
ABSENT = object()


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


def rfc3339(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class FakeClient:
    def __init__(
        self,
        checker: ModuleType,
        timestamp: object,
        *,
        unrelated_drift: bool = False,
        cronjob_error: Exception | None = None,
        event_error: Exception | None = None,
    ) -> None:
        _, talos_log, version_payload, nodes_payload, kustomizations, helmreleases = matching_inputs(checker)
        if unrelated_drift:
            version_payload = {"gitVersion": "v1.35.9"}
        status = {} if timestamp is ABSENT else {"lastSuccessfulTime": timestamp}
        self.talos_log = talos_log
        self.payloads = {
            "/version": version_payload,
            "/api/v1/nodes": nodes_payload,
            "/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations": kustomizations,
            "/apis/helm.toolkit.fluxcd.io/v2/helmreleases": helmreleases,
            checker.ETCD_SNAPSHOT_CRONJOB_PATH: {"status": status},
        }
        self.cronjob_error = cronjob_error
        self.event_error = event_error
        self.events: list[dict[str, Any]] = []

    def get_text(self, _path: str) -> str:
        return self.talos_log

    def get_json(self, path: str) -> dict[str, Any]:
        if path.endswith("/cronjobs/etcd-snapshot") and self.cronjob_error is not None:
            raise self.cronjob_error
        return self.payloads[path]

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> None:
        assert method == "POST"
        assert path == "/apis/events.k8s.io/v1/namespaces/talos-drift/events"
        if self.event_error is not None:
            raise self.event_error
        assert body is not None
        self.events.append(body)


def run_main(checker: ModuleType, client: FakeClient) -> tuple[int, str, str]:
    env = {
        "EXPECTED_NODES": "cp1=10.69.112.63,w1=10.69.112.68",
        "TALOS_VERSION": "v1.13.2",
        "KUBERNETES_VERSION": "v1.36.0",
        "POD_NAME": "talos-drift-fixture",
        "POD_NAMESPACE": "talos-drift",
        "POD_UID": "fixture-uid",
    }
    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        mock.patch.dict(os.environ, env, clear=False),
        mock.patch.object(checker.KubernetesClient, "in_cluster", return_value=client),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        rc = checker.main(now=NOW)
    return rc, stdout.getvalue(), stderr.getvalue()


def reasons(client: FakeClient) -> list[str]:
    return [event["reason"] for event in client.events]


def test_matching_fixture(checker: ModuleType) -> None:
    expected_nodes, talos_log, version_payload, nodes_payload, kustomizations, helmreleases = matching_inputs(checker)
    problems: list[str] = []
    problems.extend(checker.check_talos_versions("v1.13.2", expected_nodes, talos_log))
    problems.extend(checker.check_kubernetes_version("v1.36.0", expected_nodes, version_payload, nodes_payload))
    problems.extend(checker.check_flux_resources("Kustomization", kustomizations))
    problems.extend(checker.check_flux_resources("HelmRelease", helmreleases))
    assert problems == []


def test_injected_drift_fixture(checker: ModuleType) -> None:
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


def test_fresh_timestamp(checker: ModuleType) -> None:
    client = FakeClient(checker, rfc3339(NOW - timedelta(hours=1)))
    rc, stdout, stderr = run_main(checker, client)
    assert rc == 0
    assert reasons(client) == []
    assert "No drift detected" in stdout
    assert stderr == ""


def test_absent_timestamp_fails_closed(checker: ModuleType) -> None:
    client = FakeClient(checker, ABSENT)
    rc, stdout, _stderr = run_main(checker, client)
    assert rc != 0
    assert reasons(client) == ["EtcdSnapshotStale"]
    assert "lastSuccessfulTime is absent" in stdout


def test_26_hour_boundary_is_fresh(checker: ModuleType) -> None:
    client = FakeClient(checker, rfc3339(NOW - timedelta(hours=26)))
    rc, _stdout, _stderr = run_main(checker, client)
    assert rc == 0
    assert reasons(client) == []


def test_stale_timestamp_fails_closed(checker: ModuleType) -> None:
    client = FakeClient(checker, rfc3339(NOW - timedelta(hours=26, seconds=1)))
    rc, stdout, _stderr = run_main(checker, client)
    assert rc != 0
    assert reasons(client) == ["EtcdSnapshotStale"]
    assert "older than 26 hours" in stdout


def test_malformed_timestamp_fails_closed(checker: ModuleType) -> None:
    client = FakeClient(checker, "not-an-rfc3339-timestamp")
    rc, stdout, _stderr = run_main(checker, client)
    assert rc != 0
    assert reasons(client) == ["EtcdSnapshotStale"]
    assert "malformed status.lastSuccessfulTime" in stdout


def test_api_read_failure_fails_closed(checker: ModuleType) -> None:
    client = FakeClient(checker, ABSENT, cronjob_error=RuntimeError("injected CronJob read failure"))
    rc, stdout, _stderr = run_main(checker, client)
    assert rc != 0
    assert reasons(client) == ["EtcdSnapshotStale"]
    assert "injected CronJob read failure" in stdout


def test_unrelated_drift_only_stays_distinct(checker: ModuleType) -> None:
    client = FakeClient(checker, rfc3339(NOW - timedelta(hours=1)), unrelated_drift=True)
    rc, stdout, _stderr = run_main(checker, client)
    assert rc != 0
    assert reasons(client) == ["DriftDetected"]
    assert "Kubernetes API server" in stdout
    assert "ETCD SNAPSHOT STALE" not in stdout


def test_combined_stale_and_unrelated_drift_emits_two_events(checker: ModuleType) -> None:
    client = FakeClient(checker, rfc3339(NOW - timedelta(days=2)), unrelated_drift=True)
    rc, stdout, _stderr = run_main(checker, client)
    assert rc != 0
    assert reasons(client) == ["EtcdSnapshotStale", "DriftDetected"]
    assert "ETCD SNAPSHOT STALE" in stdout
    assert "DRIFT DETECTED" in stdout


def test_future_timestamp_fails_closed(checker: ModuleType) -> None:
    client = FakeClient(checker, rfc3339(NOW + timedelta(seconds=1)))
    rc, stdout, _stderr = run_main(checker, client)
    assert rc != 0
    assert reasons(client) == ["EtcdSnapshotStale"]
    assert "is in the future" in stdout


def test_event_post_failure_cannot_change_nonzero_result(checker: ModuleType) -> None:
    client = FakeClient(
        checker,
        rfc3339(NOW - timedelta(days=2)),
        event_error=RuntimeError("injected Event POST failure"),
    )
    rc, stdout, stderr = run_main(checker, client)
    assert rc != 0
    assert reasons(client) == []
    assert "ETCD SNAPSHOT STALE" in stdout
    assert "WARNING: failed to emit Kubernetes Event: injected Event POST failure" in stderr


def test_expected_env_is_fresh() -> None:
    renderer = load_module(RENDERER, "talos_drift_expected_renderer")
    rendered = renderer.render(renderer.parse_config_env((ROOT / "cluster/config.env").read_text(encoding="utf-8")))
    expected = (ROOT / "clusters/talos-cluster/apps/talos-drift/expected.env").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert rendered == expected


def main() -> int:
    checker = load_module(CHECKER, "talos_drift_checker")
    cases = (
        ("matching drift fixture", lambda: test_matching_fixture(checker)),
        ("injected drift fixture", lambda: test_injected_drift_fixture(checker)),
        ("fresh etcd timestamp", lambda: test_fresh_timestamp(checker)),
        ("absent etcd timestamp", lambda: test_absent_timestamp_fails_closed(checker)),
        ("26-hour boundary", lambda: test_26_hour_boundary_is_fresh(checker)),
        ("stale etcd timestamp", lambda: test_stale_timestamp_fails_closed(checker)),
        ("malformed etcd timestamp", lambda: test_malformed_timestamp_fails_closed(checker)),
        ("CronJob API read failure", lambda: test_api_read_failure_fails_closed(checker)),
        ("unrelated drift only", lambda: test_unrelated_drift_only_stays_distinct(checker)),
        ("combined stale and unrelated drift", lambda: test_combined_stale_and_unrelated_drift_emits_two_events(checker)),
        ("future etcd timestamp", lambda: test_future_timestamp_fails_closed(checker)),
        ("Event POST failure", lambda: test_event_post_failure_cannot_change_nonzero_result(checker)),
        ("expected.env freshness", test_expected_env_is_fresh),
    )
    for name, case in cases:
        case()
        print(f"PASS: {name}")
    print("talos-drift read-only tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
