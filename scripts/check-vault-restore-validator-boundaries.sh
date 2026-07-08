#!/usr/bin/env bash
# =============================================================================
# check-vault-restore-validator-boundaries.sh - Guard ADR-0020 boundary slice.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="clusters/talos-cluster/apps/vault-restore-validator"
PARENT_KUSTOMIZATION="clusters/talos-cluster/apps/kustomization.yaml"

cd "${ROOT_DIR}"

rendered="$(mktemp)"
trap 'rm -f "${rendered}"' EXIT

kubectl kustomize "${APP_DIR}" >"${rendered}"

python3 - "${rendered}" "${PARENT_KUSTOMIZATION}" <<'PY'
import sys

import yaml

rendered_path = sys.argv[1]
parent_kustomization = sys.argv[2]

with open(rendered_path, encoding="utf-8") as handle:
    rendered_text = handle.read()

with open(parent_kustomization, encoding="utf-8") as handle:
    parent_text = handle.read()

documents = [
    document
    for document in yaml.safe_load_all(rendered_text)
    if isinstance(document, dict)
]

errors = []


def metadata(document):
    return document.get("metadata") or {}


def name(document):
    return metadata(document).get("name", "")


def namespace(document):
    return metadata(document).get("namespace", "")


def labels(document):
    return metadata(document).get("labels") or {}


def add_error(message):
    errors.append(message)


if "vault-restore-validator" in parent_text:
    add_error("vault-restore-validator must not be Flux-reconciled while ADR-0020 is Proposed")

for forbidden in (
    "deploy-vault",
    "data-vault",
    "vault-internal",
    "vault-client",
    "nwarila.io/tenant",
    "enable_unauthenticated_access",
):
    if forbidden in rendered_text:
        add_error(f"rendered validator boundary contains forbidden live/recovery token: {forbidden}")

expected_kinds = {
    ("Namespace", "dr-validate"),
    ("ServiceAccount", "dr-orchestrator"),
    ("ServiceAccount", "dr-generate-root"),
    ("Role", "vault-restore-validator-noop"),
    ("RoleBinding", "dr-orchestrator-noop"),
    ("RoleBinding", "dr-generate-root-noop"),
    ("NetworkPolicy", "vault-restore-validator-default-deny"),
}
actual_kinds = {(document.get("kind", ""), name(document)) for document in documents}
missing = sorted(expected_kinds - actual_kinds)
unexpected = sorted(actual_kinds - expected_kinds)
if missing:
    add_error("missing expected resources: " + ", ".join(f"{kind}/{resource}" for kind, resource in missing))
if unexpected:
    add_error("unexpected resources: " + ", ".join(f"{kind}/{resource}" for kind, resource in unexpected))

for document in documents:
    kind = document.get("kind", "")
    resource_name = name(document)

    if kind != "Namespace" and namespace(document) != "dr-validate":
        add_error(f"{kind}/{resource_name} must stay in dr-validate namespace")

    if kind in {"ClusterRole", "ClusterRoleBinding"}:
        add_error(f"{kind}/{resource_name} is cluster-scoped RBAC; validator boundary must stay namespace-local")

    if kind in {"Pod", "Job", "CronJob", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
        add_error(f"{kind}/{resource_name} is runnable workload; this slice must remain inert")

namespace_docs = [document for document in documents if document.get("kind") == "Namespace"]
if len(namespace_docs) != 1:
    add_error(f"expected exactly one Namespace, found {len(namespace_docs)}")
else:
    ns_labels = labels(namespace_docs[0])
    for key in (
        "pod-security.kubernetes.io/enforce",
        "pod-security.kubernetes.io/audit",
        "pod-security.kubernetes.io/warn",
    ):
        if ns_labels.get(key) != "restricted":
            add_error(f"Namespace/dr-validate must set {key}=restricted")

for service_account in (document for document in documents if document.get("kind") == "ServiceAccount"):
    if service_account.get("automountServiceAccountToken") is not False:
        add_error(f"ServiceAccount/{name(service_account)} must set automountServiceAccountToken: false")

for role in (document for document in documents if document.get("kind") == "Role"):
    if role.get("rules") not in (None, []):
        add_error(f"Role/{name(role)} must remain permissionless in this boundary slice")

expected_subjects = {"dr-orchestrator", "dr-generate-root"}
for binding in (document for document in documents if document.get("kind") == "RoleBinding"):
    role_ref = binding.get("roleRef") or {}
    if role_ref.get("kind") != "Role" or role_ref.get("name") != "vault-restore-validator-noop":
        add_error(f"RoleBinding/{name(binding)} must bind only vault-restore-validator-noop")
    for subject in binding.get("subjects") or []:
        if subject.get("kind") != "ServiceAccount":
            add_error(f"RoleBinding/{name(binding)} has non-ServiceAccount subject")
        if subject.get("namespace") != "dr-validate":
            add_error(f"RoleBinding/{name(binding)} subject must stay in dr-validate")
        if subject.get("name") not in expected_subjects:
            add_error(f"RoleBinding/{name(binding)} has unexpected subject {subject.get('name')}")

network_policies = [
    document
    for document in documents
    if document.get("kind") == "NetworkPolicy"
    and name(document) == "vault-restore-validator-default-deny"
]
if len(network_policies) != 1:
    add_error("expected exactly one vault-restore-validator-default-deny NetworkPolicy")
else:
    spec = network_policies[0].get("spec") or {}
    if spec.get("podSelector") != {}:
        add_error("default-deny NetworkPolicy must select all pods")
    if sorted(spec.get("policyTypes") or []) != ["Egress", "Ingress"]:
        add_error("default-deny NetworkPolicy must deny both ingress and egress")
    if "ingress" in spec or "egress" in spec:
        add_error("default-deny NetworkPolicy must not include allow rules")

if errors:
    print("Vault restore-validator boundary guard failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

print("OK: Vault restore-validator boundary is inert, namespace-local, and not wired into Flux")
PY
