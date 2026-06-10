#!/usr/bin/env python3
"""Reduced, read-only drift checks for the Talos cluster."""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SERVICEACCOUNT_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
TALOS_LOG_CONTAINER = "talos-version"


def parse_expected_nodes(value: str) -> dict[str, str]:
    nodes: dict[str, str] = {}
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"invalid EXPECTED_NODES entry {part!r}")
        name, ip = part.split("=", 1)
        nodes[name] = ip
    if not nodes:
        raise ValueError("EXPECTED_NODES is empty")
    return nodes


def parse_talos_versions(log: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    current_node: str | None = None
    for raw_line in log.splitlines():
        line = raw_line.strip()
        node_match = re.match(r"NODE:\s+(\S+)", line)
        if node_match:
            current_node = node_match.group(1)
            continue

        tag_match = re.match(r"Tag:\s+(\S+)", line)
        if tag_match and current_node:
            versions[current_node] = tag_match.group(1)
            current_node = None
    return versions


def check_talos_versions(expected_version: str, expected_nodes: dict[str, str], log: str) -> list[str]:
    problems: list[str] = []
    versions = parse_talos_versions(log)
    expected_ips = set(expected_nodes.values())

    for name, ip in expected_nodes.items():
        actual = versions.get(ip)
        if actual is None:
            problems.append(f"Talos node {name} ({ip}) did not report a version")
        elif actual != expected_version:
            problems.append(f"Talos node {name} ({ip}) is {actual}, expected {expected_version}")

    for ip, version in sorted(versions.items()):
        if ip not in expected_ips:
            problems.append(f"Talos returned unexpected node {ip} at {version}")

    return problems


def check_kubernetes_version(
    expected_version: str,
    expected_nodes: dict[str, str],
    version_payload: dict[str, Any],
    nodes_payload: dict[str, Any],
) -> list[str]:
    problems: list[str] = []
    server_version = version_payload.get("gitVersion")
    if server_version != expected_version:
        problems.append(f"Kubernetes API server is {server_version!r}, expected {expected_version}")

    live_nodes = {
        item.get("metadata", {}).get("name"): item
        for item in nodes_payload.get("items", [])
        if item.get("metadata", {}).get("name")
    }

    for name, expected_ip in expected_nodes.items():
        node = live_nodes.get(name)
        if node is None:
            problems.append(f"Kubernetes node {name} is missing")
            continue

        kubelet_version = node.get("status", {}).get("nodeInfo", {}).get("kubeletVersion")
        if kubelet_version != expected_version:
            problems.append(f"Kubernetes node {name} kubelet is {kubelet_version!r}, expected {expected_version}")

        internal_ips = {
            address.get("address")
            for address in node.get("status", {}).get("addresses", [])
            if address.get("type") == "InternalIP"
        }
        if expected_ip not in internal_ips:
            problems.append(f"Kubernetes node {name} InternalIP is {sorted(internal_ips)!r}, expected {expected_ip}")

    for name in sorted(set(live_nodes) - set(expected_nodes)):
        problems.append(f"Kubernetes returned unexpected node {name}")

    return problems


def ready_condition(item: dict[str, Any]) -> dict[str, Any] | None:
    for condition in item.get("status", {}).get("conditions", []):
        if condition.get("type") == "Ready":
            return condition
    return None


def object_name(item: dict[str, Any]) -> str:
    metadata = item.get("metadata", {})
    namespace = metadata.get("namespace")
    name = metadata.get("name", "<unknown>")
    return f"{namespace}/{name}" if namespace else name


def check_flux_resources(kind: str, payload: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for item in payload.get("items", []):
        ref = object_name(item)
        if item.get("spec", {}).get("suspend") is True:
            problems.append(f"{kind} {ref} is suspended")

        condition = ready_condition(item)
        if condition is None:
            problems.append(f"{kind} {ref} has no Ready condition")
        elif condition.get("status") != "True":
            reason = condition.get("reason", "<no reason>")
            message = condition.get("message", "")
            problems.append(f"{kind} {ref} Ready={condition.get('status')} reason={reason}: {message}")

        for condition in item.get("status", {}).get("conditions", []):
            status = condition.get("status")
            cond_type = str(condition.get("type", ""))
            reason = str(condition.get("reason", ""))
            message = str(condition.get("message", ""))
            if cond_type == "Stalled" and status == "True":
                problems.append(f"{kind} {ref} is stalled: {reason} {message}".strip())
            if status == "True" and "drift" in f"{reason} {message}".lower():
                problems.append(f"{kind} {ref} reports drift: {reason} {message}".strip())

    return problems


class KubernetesClient:
    def __init__(self, api_server: str, token: str, ca_path: Path) -> None:
        self.api_server = api_server.rstrip("/")
        self.token = token
        self.context = ssl.create_default_context(cafile=str(ca_path))

    @classmethod
    def in_cluster(cls) -> "KubernetesClient":
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not host:
            raise RuntimeError("KUBERNETES_SERVICE_HOST is not set")
        token = (SERVICEACCOUNT_DIR / "token").read_text(encoding="utf-8")
        return cls(f"https://{host}:{port}", token, SERVICEACCOUNT_DIR / "ca.crt")

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = None
        headers = {"Authorization": f"Bearer {self.token}"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.api_server}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=20) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} failed with HTTP {exc.code}: {detail}") from exc
        if not payload:
            return None
        return json.loads(payload)

    def get_json(self, path: str) -> dict[str, Any]:
        payload = self.request("GET", path)
        if not isinstance(payload, dict):
            raise RuntimeError(f"GET {path} returned non-object JSON")
        return payload

    def get_text(self, path: str) -> str:
        request = urllib.request.Request(
            f"{self.api_server}{path}",
            headers={"Authorization": f"Bearer {self.token}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=20) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GET {path} failed with HTTP {exc.code}: {detail}") from exc


def emit_event(client: KubernetesClient, namespace: str, pod_name: str, pod_uid: str, reason: str, note: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    body = {
        "apiVersion": "events.k8s.io/v1",
        "kind": "Event",
        "metadata": {
            "generateName": "talos-drift-",
            "namespace": namespace,
        },
        "eventTime": timestamp,
        "reportingController": "talos-drift.nwarila.io",
        "reportingInstance": pod_name,
        "action": "DriftCheck",
        "reason": reason,
        "type": "Warning",
        "note": note[:1000],
        "regarding": {
            "apiVersion": "v1",
            "kind": "Pod",
            "namespace": namespace,
            "name": pod_name,
            "uid": pod_uid,
        },
    }
    try:
        client.request("POST", f"/apis/events.k8s.io/v1/namespaces/{urllib.parse.quote(namespace)}/events", body)
    except Exception as exc:  # noqa: BLE001 - failed event reporting must not hide the drift result.
        print(f"WARNING: failed to emit Kubernetes Event: {exc}", file=sys.stderr)


def collect_problems(client: KubernetesClient, namespace: str, pod_name: str) -> list[str]:
    expected_nodes = parse_expected_nodes(os.environ["EXPECTED_NODES"])
    expected_talos = os.environ["TALOS_VERSION"]
    expected_kubernetes = os.environ["KUBERNETES_VERSION"]
    quoted_namespace = urllib.parse.quote(namespace)
    quoted_pod = urllib.parse.quote(pod_name)
    log_path = f"/api/v1/namespaces/{quoted_namespace}/pods/{quoted_pod}/log?container={TALOS_LOG_CONTAINER}"

    talos_log = client.get_text(log_path)
    version_payload = client.get_json("/version")
    nodes_payload = client.get_json("/api/v1/nodes")
    kustomizations = client.get_json("/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations")
    helmreleases = client.get_json("/apis/helm.toolkit.fluxcd.io/v2/helmreleases")

    problems: list[str] = []
    problems.extend(check_talos_versions(expected_talos, expected_nodes, talos_log))
    problems.extend(check_kubernetes_version(expected_kubernetes, expected_nodes, version_payload, nodes_payload))
    problems.extend(check_flux_resources("Kustomization", kustomizations))
    problems.extend(check_flux_resources("HelmRelease", helmreleases))
    return problems


def main() -> int:
    namespace = os.environ.get("POD_NAMESPACE", "talos-drift")
    pod_name = os.environ.get("POD_NAME")
    pod_uid = os.environ.get("POD_UID", "")
    if not pod_name:
        print("DRIFT CHECK ERROR: POD_NAME is not set", file=sys.stderr)
        return 2

    client = KubernetesClient.in_cluster()
    try:
        problems = collect_problems(client, namespace, pod_name)
        reason = "DriftDetected"
    except Exception as exc:  # noqa: BLE001 - an unreadable signal is an actionable check failure.
        problems = [f"drift checker could not complete: {exc}"]
        reason = "DriftCheckError"

    if problems:
        header = "DRIFT DETECTED:" if reason == "DriftDetected" else "DRIFT CHECK ERROR:"
        print(header)
        for problem in problems:
            print(f"- {problem}")
        emit_event(client, namespace, pod_name, pod_uid, reason, "; ".join(problems))
        return 1

    print("No drift detected across read-only coverage: Kubernetes/Talos version pins, node InternalIPs, and Flux Ready state.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
