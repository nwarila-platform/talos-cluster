#!/usr/bin/env python3
"""Assert the rendered gitlab-runner chart matches platform/gitlab-runner/values.yaml.

Usage: check-runner-render.py <rendered-manifest.yaml> <chart-directory>

The expected image tag is derived from the chart's appVersion so that a chart
bump through Renovate does not rot this check.
"""
import sys

import yaml

EXPECTED_RULES = [
    {"apiGroups": [""], "resources": ["events"], "verbs": ["list", "watch"]},
    {"apiGroups": [""], "resources": ["pods"], "verbs": ["create", "delete", "get", "list", "watch"]},
    {"apiGroups": [""], "resources": ["pods/attach", "pods/exec"], "verbs": ["get", "create", "patch", "delete"]},
    {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get", "list"]},
    {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create", "delete", "get", "update"]},
    {"apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["get"]},
    {"apiGroups": [""], "resources": ["services"], "verbs": ["create", "get"]},
]


def main(rendered_path, chart_dir):
    with open(rendered_path, encoding="utf-8") as stream:
        docs = [doc for doc in yaml.safe_load_all(stream) if doc]
    with open(f"{chart_dir}/Chart.yaml", encoding="utf-8") as stream:
        app_version = yaml.safe_load(stream)["appVersion"]

    by_kind = {}
    for doc in docs:
        by_kind.setdefault(doc["kind"], []).append(doc)
    failures = []

    roles = by_kind.get("Role", [])
    if len(roles) != 1:
        failures.append(f"expected exactly one Role, found {len(roles)}")
    elif roles[0]["rules"] != EXPECTED_RULES:
        failures.append(f"Role rules differ: {roles[0]['rules']}")
    if by_kind.get("ClusterRole"):
        failures.append("chart rendered a ClusterRole; runner access must stay namespaced")

    secrets = by_kind.get("Secret", [])
    if len(secrets) != 1 or sorted(secrets[0].get("data", {})) != ["runner-registration-token", "runner-token"]:
        failures.append(f"expected one Secret with runner-token data, found {[sorted(s.get('data', {})) for s in secrets]}")

    deployments = by_kind.get("Deployment", [])
    if len(deployments) != 1:
        failures.append(f"expected exactly one Deployment, found {len(deployments)}")
    else:
        pod = deployments[0]["spec"]["template"]["spec"]
        container = pod["containers"][0]
        expected_image = f"registry.gitlab.com/gitlab-org/gitlab-runner:alpine-v{app_version}"
        if container["image"] != expected_image:
            failures.append(f"image {container['image']} != {expected_image}")
        volumes = {volume["name"]: volume for volume in pod.get("volumes", [])}
        if volumes.get("custom-certs", {}).get("secret", {}).get("secretName") != "gitlab-ca":
            failures.append(f"custom-certs volume is not backed by secret gitlab-ca: {volumes.get('custom-certs')}")
        mounts = {mount["name"]: mount for mount in container.get("volumeMounts", [])}
        if mounts.get("custom-certs") != {"name": "custom-certs", "mountPath": "/home/gitlab-runner/.gitlab-runner/certs/", "readOnly": True}:
            failures.append(f"custom-certs mount missing or wrong: {mounts.get('custom-certs')}")
        if pod.get("securityContext", {}).get("runAsUser") != 100 or not container.get("securityContext", {}).get("runAsNonRoot"):
            failures.append("runner pod is not pinned to runAsUser 100 / runAsNonRoot")

    for failure in failures:
        print(f"ERROR: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"Rendered gitlab-runner chart conforms (appVersion {app_version}).")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
