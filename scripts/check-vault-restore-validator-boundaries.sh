#!/usr/bin/env bash
# =============================================================================
# check-vault-restore-validator-boundaries.sh - Guard ADR-0020 restore driver.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT_DIR="clusters/talos-cluster"
APP_DIR="${ROOT_DIR}/apps/vault-restore-validator"
APPS_DIR="${ROOT_DIR}/apps"
PARENT_KUSTOMIZATION="${ROOT_DIR}/apps/kustomization.yaml"

cd "${REPO_ROOT}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

root_rendered="${tmpdir}/root.yaml"
root_render_error="${tmpdir}/root-kustomize.err"
app_rendered="${tmpdir}/validator.yaml"

if kubectl kustomize "${ROOT_DIR}" >"${root_rendered}" 2>"${root_render_error}"; then
    root_render_status=0
else
    root_render_status=$?
fi

if [[ "${root_render_status}" -ne 0 && "${GUARD_OFFLINE:-}" == "1" ]]; then
    kubectl kustomize "${APP_DIR}" >"${app_rendered}"
else
    : >"${app_rendered}"
fi

python3 - "${root_rendered}" "${root_render_status}" "${app_rendered}" "${PARENT_KUSTOMIZATION}" "${APPS_DIR}" "${ROOT_DIR}" <<'PY'
import json
import os
import re
import subprocess
import sys

import yaml

root_rendered_path = sys.argv[1]
root_render_status = int(sys.argv[2])
app_rendered_path = sys.argv[3]
parent_kustomization = sys.argv[4]
apps_dir = sys.argv[5]
flux_root_dir = sys.argv[6]

SCRATCH = "dr-validate-vault-restore"
DR_VALIDATE_NS = "dr-validate"
LONGHORN_NS = "longhorn-system"
DR_ORCHESTRATOR = "dr-orchestrator"
DR_GENERATE_ROOT = "dr-generate-root"
DR_ORCHESTRATOR_USER = "system:serviceaccount:dr-validate:dr-orchestrator"
DR_GENERATE_ROOT_USER = "system:serviceaccount:dr-validate:dr-generate-root"
GUARDED_REACHING_GROUPS = {
    "system:authenticated",
    "system:serviceaccounts",
    "system:serviceaccounts:dr-validate",
}
VAP_NAME = "dr-orchestrator-longhorn-volume-allowlist"
APPROVED_RESTORE_DRIVER_IMAGE = (
    "docker.io/bitnami/kubectl@"
    "sha256:558420daf32bbc382e3e9af4537f4073085b336ddd47399a3b70e70087115978"
)
RESTORE_DRIVER_COMMAND = ["/bin/bash", "/opt/vault-restore-validator/restore-driver.sh"]
RESTORE_DRIVER_SCRIPT_VOLUME = "dr-restore-driver-script"
DRIVER_SELECTOR_LABELS = {
    "app.kubernetes.io/name": "vault-restore-validator",
    "app.kubernetes.io/component": "restore-driver",
    "io.kubernetes.pod.namespace": DR_VALIDATE_NS,
}
DESTRUCTIVE_LONGHORN_VERBS = {
    "create",
    "update",
    "patch",
    "delete",
    "deletecollection",
}
APPROVED_GUARDED_BINDINGS = {
    ("RoleBinding", LONGHORN_NS, "dr-orchestrator-longhorn-restore"): {
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "dr-orchestrator-longhorn-restore",
        },
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": DR_ORCHESTRATOR,
                "namespace": DR_VALIDATE_NS,
            }
        ],
    },
    ("RoleBinding", DR_VALIDATE_NS, "dr-orchestrator-result-writer"): {
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "dr-orchestrator-result-writer",
        },
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": DR_ORCHESTRATOR,
                "namespace": DR_VALIDATE_NS,
            }
        ],
    },
    ("RoleBinding", DR_VALIDATE_NS, "dr-generate-root-noop"): {
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "vault-restore-validator-noop",
        },
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": DR_GENERATE_ROOT,
                "namespace": DR_VALIDATE_NS,
            }
        ],
    },
}
POD_TEMPLATE_KINDS = {
    "Pod",
    "Deployment",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "StatefulSet",
    "Job",
    "CronJob",
}
APPROVED_GUARDED_WORKLOADS = {
    ("CronJob", DR_VALIDATE_NS, "dr-restore-driver"),
}
APPROVED_LONGHORN_RULES = {
    (
        ("longhorn.io",),
        ("backups", "backuptargets", "backupvolumes"),
        ("get", "list", "watch"),
        (),
        (),
    ),
    (
        ("longhorn.io",),
        ("volumes",),
        ("create", "get", "list", "watch"),
        (),
        (),
    ),
    (
        ("longhorn.io",),
        ("volumes",),
        ("delete", "patch", "update"),
        (SCRATCH,),
        (),
    ),
}
EXPECTED_VAP_RESOURCE_RULES = [
    {
        "apiGroups": ["longhorn.io"],
        "apiVersions": ["*"],
        "operations": ["CREATE"],
        "resources": ["volumes"],
    }
]
EXPECTED_POD_SECURITY_CONTEXT = {
    "runAsNonRoot": True,
    "runAsUser": 65532,
    "runAsGroup": 65532,
    "fsGroup": 65532,
    "fsGroupChangePolicy": "OnRootMismatch",
    "seccompProfile": {"type": "RuntimeDefault"},
}
EXPECTED_RESTORE_DRIVER_VOLUMES = [
    {
        "name": "restore-driver-script",
        "configMap": {
            "name": RESTORE_DRIVER_SCRIPT_VOLUME,
            "defaultMode": 0o555,
        },
    },
    {"name": "tmp", "emptyDir": {}},
]
EXPECTED_RESTORE_DRIVER_MOUNTS = [
    {
        "name": "restore-driver-script",
        "mountPath": "/opt/vault-restore-validator/restore-driver.sh",
        "subPath": "restore-driver.sh",
        "readOnly": True,
    },
    {"name": "tmp", "mountPath": "/tmp"},
]
EXPECTED_CONTAINER_ENV = [
    {"name": "HOME", "value": "/tmp"},
    {"name": "GIT_SHA", "value": "unknown"},
    {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
    {
        "name": "POD_NAMESPACE",
        "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}},
    },
    {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
]
CLUSTER_SCOPED_KINDS = {
    "Namespace",
    "ValidatingAdmissionPolicy",
    "ValidatingAdmissionPolicyBinding",
    "ClusterRole",
    "ClusterRoleBinding",
}
MUTATING_ADMISSION_KINDS = {
    "MutatingWebhookConfiguration",
    "MutatingAdmissionPolicy",
    "MutatingAdmissionPolicyBinding",
}


def load_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def documents_from_text(text):
    return [
        document
        for document in yaml.safe_load_all(text)
        if isinstance(document, dict)
    ]


def load_documents(path):
    return documents_from_text(load_text(path))


with open(parent_kustomization, encoding="utf-8") as handle:
    parent = yaml.safe_load(handle)

app_text = ""
app_documents = []
root_documents = []
binding_scan_documents = []
binding_scan_source = ""
errors = []
warnings = []


def add_error(message):
    errors.append(message)


def add_warning(message):
    warnings.append(message)


def exit_if_errors():
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if errors:
        print("Vault restore-validator restore-driver guard failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        sys.exit(1)


def metadata(document):
    return document.get("metadata") or {}


def name(document):
    return metadata(document).get("name", "")


def namespace(document):
    return metadata(document).get("namespace", "")


def in_validator_footprint(document):
    document_metadata = metadata(document)
    document_name = name(document)
    return (
        document_metadata.get("namespace") == DR_VALIDATE_NS
        or (document.get("kind") == "Namespace" and document_name == DR_VALIDATE_NS)
        or (
            document_name == VAP_NAME
            and document.get("kind") in {
                "ValidatingAdmissionPolicy",
                "ValidatingAdmissionPolicyBinding",
            }
        )
        or (
            document_metadata.get("namespace") == LONGHORN_NS
            and document_name.startswith("dr-orchestrator-longhorn-restore")
        )
    )


def docs(kind=None, resource_name=None, resource_namespace=None):
    selected = app_documents
    if kind is not None:
        selected = [document for document in selected if document.get("kind") == kind]
    if resource_name is not None:
        selected = [document for document in selected if name(document) == resource_name]
    if resource_namespace is not None:
        selected = [
            document for document in selected if namespace(document) == resource_namespace
        ]
    return selected


def rules_for(role):
    return role.get("rules") or []


def list_value(value):
    return value if isinstance(value, list) else []


def normalized_list(value):
    return tuple(sorted(str(item) for item in list_value(value)))


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def canonical_object_set(values):
    return {canonical_json(value) for value in values}


def verbs(rule):
    return set(list_value(rule.get("verbs")))


def resource_names(rule):
    return list_value(rule.get("resourceNames"))


def values_match(values, expected):
    value_set = set(list_value(values))
    return "*" in value_set or expected in value_set


def rule_targets_driver_surface(api_groups, resources):
    api_group_set = set(list_value(api_groups))
    resource_set = set(list_value(resources))

    return any(
        group in api_group_set or "*" in api_group_set
        for group, target_resources in {
            "": {"pods"},
            "longhorn.io": {"volumes"},
            "admissionregistration.k8s.io": {
                "validatingadmissionpolicies",
                "validatingadmissionpolicybindings",
                "validatingwebhookconfigurations",
            },
        }.items()
        if "*" in resource_set or resource_set & target_resources
    )


def rule_matches_longhorn_api_group(rule):
    return values_match(rule.get("apiGroups"), "longhorn.io")


def normalized_rbac_rule(rule):
    return (
        normalized_list(rule.get("apiGroups")),
        normalized_list(rule.get("resources")),
        normalized_list(rule.get("verbs")),
        normalized_list(rule.get("resourceNames")),
        normalized_list(rule.get("nonResourceURLs")),
    )


def matched_destructive_verbs(rule):
    rule_verbs = verbs(rule)
    if "*" in rule_verbs:
        return set(DESTRUCTIVE_LONGHORN_VERBS)
    return rule_verbs & DESTRUCTIVE_LONGHORN_VERBS


def has_unapproved_longhorn_destructive(rule):
    return (
        rule_matches_longhorn_api_group(rule)
        and bool(matched_destructive_verbs(rule))
        and normalized_rbac_rule(rule) not in APPROVED_LONGHORN_RULES
    )


def role_grants_unapproved_longhorn_destructive(role):
    return any(has_unapproved_longhorn_destructive(rule) for rule in rules_for(role))


def role_is_approved_longhorn_identity(role):
    return (
        role.get("kind") == "Role"
        and namespace(role) == LONGHORN_NS
        and name(role) == "dr-orchestrator-longhorn-restore"
    )


def role_grants_any_longhorn_destructive(role):
    return any(
        rule_matches_longhorn_api_group(rule)
        and bool(matched_destructive_verbs(rule))
        for rule in rules_for(role)
    )


def source_documents_under(path):
    documents = []
    for root, _, files in os.walk(path):
        for file_name in files:
            if not file_name.endswith((".yaml", ".yml")):
                continue
            file_path = os.path.join(root, file_name)
            try:
                for document in load_documents(file_path):
                    document["_guard_source_path"] = file_path
                    documents.append(document)
            except yaml.YAMLError as exc:
                add_error(f"failed to parse YAML source {file_path}: {exc}")
    return documents


def normalize_flux_path(path):
    if not isinstance(path, str) or not path:
        return ""
    return os.path.normpath(path[2:] if path.startswith("./") else path)


def is_flux_kustomization(document):
    return (
        document.get("kind") == "Kustomization"
        and "kustomize.toolkit.fluxcd.io" in str(document.get("apiVersion", ""))
    )


def flux_kustomization_id(item):
    namespace_text = f"{item['namespace']}/" if item["namespace"] else ""
    return (
        f"{namespace_text}{item['name']} "
        f"(sourceRef.name={item['source_ref_name']}, path={item['path']}, "
        f"source={item['source_path']})"
    )


def discover_flux_child_paths(path):
    child_paths = []
    seen_paths = set()
    external_kustomizations = []
    flux_root_path = os.path.normpath(flux_root_dir)

    for root, dirs, files in os.walk(path):
        dirs.sort()
        for file_name in sorted(files):
            if not file_name.endswith((".yaml", ".yml")):
                continue
            file_path = os.path.join(root, file_name)
            try:
                documents = load_documents(file_path)
            except yaml.YAMLError as exc:
                add_error(f"failed to parse YAML source {file_path}: {exc}")
                continue

            for document in documents:
                if not is_flux_kustomization(document):
                    continue

                document_metadata = metadata(document)
                spec = document.get("spec") or {}
                source_ref = spec.get("sourceRef") or {}
                source_ref_name = source_ref.get("name", "")
                document_path = spec.get("path", "")
                normalized_path = normalize_flux_path(document_path)
                item = {
                    "name": document_metadata.get("name", ""),
                    "namespace": document_metadata.get("namespace", ""),
                    "path": document_path,
                    "source_path": file_path,
                    "source_ref_name": source_ref_name,
                }

                if source_ref_name != "flux-system":
                    external_kustomizations.append(item)
                    continue

                if (
                    normalized_path
                    and normalized_path != flux_root_path
                    and os.path.isdir(normalized_path)
                    and normalized_path not in seen_paths
                ):
                    seen_paths.add(normalized_path)
                    child_paths.append(normalized_path)

    return child_paths, external_kustomizations


def render_child_flux_documents(child_paths, failures_are_warnings=False):
    documents = []
    failed_paths = []

    for child_path in child_paths:
        result = subprocess.run(
            ["kubectl", "kustomize", child_path],
            check=False,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            stderr = " ".join(result.stderr.split()) or "<no stderr>"
            message = (
                f"cannot render child Flux Kustomization path {child_path}; "
                f"kubectl kustomize exited {result.returncode}: {stderr}"
            )
            if failures_are_warnings:
                add_warning(f"GUARD_OFFLINE — {message}")
            else:
                add_error(message)
            failed_paths.append(child_path)
            continue

        try:
            rendered_documents = documents_from_text(result.stdout)
        except yaml.YAMLError as exc:
            message = (
                f"failed to parse rendered child Flux Kustomization path "
                f"{child_path}: {exc}"
            )
            if failures_are_warnings:
                add_warning(f"GUARD_OFFLINE — {message}")
            else:
                add_error(message)
            failed_paths.append(child_path)
            continue

        for document in rendered_documents:
            document["_guard_source_path"] = child_path
            documents.append(document)

    return documents, failed_paths


def dedup_documents(documents):
    deduped = []
    seen = set()
    for document in documents:
        key = (document.get("kind", ""), namespace(document), name(document))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(document)
    return deduped


def assert_exactly_one(kind, resource_name, resource_namespace=None):
    matches = docs(kind, resource_name, resource_namespace)
    if len(matches) != 1:
        ns_text = f" in namespace {resource_namespace}" if resource_namespace else ""
        add_error(f"expected exactly one {kind}/{resource_name}{ns_text}, found {len(matches)}")
        return None
    return matches[0]


def role_key(role):
    kind = role.get("kind")
    if kind == "ClusterRole":
        return (kind, "", name(role))
    return (kind, namespace(role), name(role))


def role_location(role):
    kind = role.get("kind", "<unknown>")
    if kind == "ClusterRole":
        role_id = f"{kind}/{name(role)}"
    else:
        role_id = f"{kind}/{namespace(role)}/{name(role)}"
    source_path = role.get("_guard_source_path")
    if source_path:
        return f"{role_id} ({source_path})"
    return role_id


def role_ref_key(binding):
    role_ref = binding.get("roleRef") or {}
    role_ref_kind = role_ref.get("kind")
    role_ref_name = role_ref.get("name")
    if role_ref_kind == "ClusterRole":
        return ("ClusterRole", "", role_ref_name)
    if role_ref_kind == "Role":
        return ("Role", namespace(binding), role_ref_name)
    return (role_ref_kind or "", namespace(binding), role_ref_name or "")


def binding_key(binding):
    kind = binding.get("kind", "")
    if kind == "ClusterRoleBinding":
        return (kind, "", name(binding))
    return (kind, namespace(binding), name(binding))


def subject_reaches_guarded_sa(subject):
    subject_kind = subject.get("kind")
    subject_name = subject.get("name")
    if subject_kind == "ServiceAccount":
        return subject_name in {DR_ORCHESTRATOR, DR_GENERATE_ROOT}
    if subject_kind == "User":
        return subject_name in {DR_ORCHESTRATOR_USER, DR_GENERATE_ROOT_USER}
    if subject_kind == "Group":
        return subject_name in GUARDED_REACHING_GROUPS
    return False


def subject_label(subject):
    return f"{subject.get('kind', '<unknown>')} {subject.get('name', '<unnamed>')}"


def binding_location(binding):
    source_path = binding.get("_guard_source_path")
    if source_path:
        return source_path
    ns = namespace(binding)
    ns_text = f"{ns}/" if ns else ""
    return f"{binding.get('kind', '<unknown>')}/{ns_text}{name(binding)}"


def workload_id(workload):
    ns = namespace(workload)
    ns_text = f"{ns}/" if ns else ""
    return f"{workload.get('kind', '<unknown>')}/{ns_text}{name(workload)}"


def workload_location(workload):
    source_path = workload.get("_guard_source_path")
    if source_path:
        return f"{workload_id(workload)} ({source_path})"
    return workload_id(workload)


def assert_guarded_service_account_bindings(binding_documents, source_label):
    for binding in binding_documents:
        if binding.get("kind") not in {"RoleBinding", "ClusterRoleBinding"}:
            continue
        guarded_subjects = [
            subject
            for subject in binding.get("subjects") or []
            if subject_reaches_guarded_sa(subject)
        ]
        if not guarded_subjects:
            continue

        key = binding_key(binding)
        expected = APPROVED_GUARDED_BINDINGS.get(key)
        guarded_labels = ", ".join(sorted({subject_label(subject) for subject in guarded_subjects}))
        if expected is None:
            add_error(
                f"{source_label} {binding_location(binding)} must not bind guarded subject(s) "
                f"{guarded_labels}; only the approved restore-validator bindings may name them"
            )
            continue

        if (binding.get("roleRef") or {}) != expected["roleRef"]:
            add_error(
                f"{source_label} {binding_location(binding)} must keep the approved roleRef "
                f"for guarded ServiceAccount binding {name(binding)}"
            )
        if (binding.get("subjects") or []) != expected["subjects"]:
            add_error(
                f"{source_label} {binding_location(binding)} must bind only the approved guarded "
                f"ServiceAccount subject; found guarded subject(s) {guarded_labels}"
            )


def pod_spec_of(document):
    kind = document.get("kind")
    spec = document.get("spec")
    if not isinstance(spec, dict):
        return None
    if kind == "Pod":
        return spec
    if kind in {
        "Deployment",
        "DaemonSet",
        "ReplicaSet",
        "ReplicationController",
        "StatefulSet",
        "Job",
    }:
        template = spec.get("template")
        if not isinstance(template, dict):
            return None
        pod_spec = template.get("spec")
        return pod_spec if isinstance(pod_spec, dict) else None
    if kind == "CronJob":
        job_template = spec.get("jobTemplate")
        if not isinstance(job_template, dict):
            return None
        job_spec = job_template.get("spec")
        if not isinstance(job_spec, dict):
            return None
        template = job_spec.get("template")
        if not isinstance(template, dict):
            return None
        pod_spec = template.get("spec")
        return pod_spec if isinstance(pod_spec, dict) else None
    return None


def assert_guarded_service_account_workloads(workload_documents, source_label):
    guarded_service_accounts = {DR_ORCHESTRATOR, DR_GENERATE_ROOT}
    for workload in workload_documents:
        kind = workload.get("kind")
        if kind not in POD_TEMPLATE_KINDS:
            continue
        pod_spec = pod_spec_of(workload)
        if pod_spec is None:
            continue

        workload_namespace = namespace(workload)
        sa = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
        if workload_namespace != DR_VALIDATE_NS or sa not in guarded_service_accounts:
            continue
        if (kind, workload_namespace, name(workload)) in APPROVED_GUARDED_WORKLOADS:
            continue

        add_error(
            f"{source_label} {workload_location(workload)} runs as guarded "
            f"restore-driver ServiceAccount {sa}; only the approved suspended "
            "CronJob may run as a guarded restore-driver ServiceAccount"
        )


def assert_no_unapproved_destructive_longhorn_roles(role_documents, source_label):
    for role in role_documents:
        if role.get("kind") not in {"Role", "ClusterRole"}:
            continue
        if not role_grants_any_longhorn_destructive(role):
            continue
        if role_is_approved_longhorn_identity(role):
            continue

        role_id = (
            f"ClusterRole/{name(role)}"
            if role.get("kind") == "ClusterRole"
            else f"Role/{namespace(role)}/{name(role)}"
        )
        add_error(
            f"{source_label} {role_location(role)}: only the approved "
            "dr-orchestrator-longhorn-restore Role in longhorn-system may carry "
            f"create/destructive longhorn.io access; {role_id} must not"
        )


def normalize_cilium_selector_key(key):
    return key.removeprefix("k8s:") if isinstance(key, str) else key


def could_select_driver(endpoint_selector):
    if not isinstance(endpoint_selector, dict):
        return True

    match_labels = endpoint_selector.get("matchLabels") or {}
    if not isinstance(match_labels, dict):
        return True

    match_expressions = endpoint_selector.get("matchExpressions")
    if not match_labels and not match_expressions:
        return True
    if match_expressions is not None:
        return True

    return all(
        DRIVER_SELECTOR_LABELS.get(normalize_cilium_selector_key(key)) == value
        for key, value in match_labels.items()
    )


def assert_no_ccnp_egress_selects_driver(documents, source_label):
    for document in documents:
        if document.get("kind") != "CiliumClusterwideNetworkPolicy":
            continue

        for rule in [document.get("spec") or {}] + list_value(document.get("specs")):
            if not isinstance(rule, dict):
                continue
            if not rule.get("egress"):
                continue
            if not could_select_driver(rule.get("endpointSelector") or {}):
                continue

            add_error(
                f"{source_label} CiliumClusterwideNetworkPolicy {name(document) or '<unnamed>'} "
                "must not grant egress to the restore-driver pods "
                "(only the approved kube-apiserver CNP may)"
            )


def assert_no_mutating_admission_targets_driver(documents, source_label):
    for document in documents:
        kind = document.get("kind")
        if kind not in MUTATING_ADMISSION_KINDS:
            continue

        document_name = name(document) or "<unnamed>"
        if kind == "MutatingWebhookConfiguration":
            for webhook in document.get("webhooks") or []:
                for rule in webhook.get("rules") or []:
                    if rule_targets_driver_surface(
                        rule.get("apiGroups"), rule.get("resources")
                    ):
                        add_error(
                            f"{source_label} MutatingWebhookConfiguration {document_name} "
                            "may rewrite the restore-driver pod / Longhorn volume / VAP"
                        )

        if kind == "MutatingAdmissionPolicy":
            resource_rules = (
                ((document.get("spec") or {}).get("matchConstraints") or {})
                .get("resourceRules")
                or []
            )
            for rule in resource_rules:
                if rule_targets_driver_surface(
                    rule.get("apiGroups"), rule.get("resources")
                ):
                    add_error(
                        f"{source_label} MutatingAdmissionPolicy {document_name} "
                        "may rewrite the restore-driver pod / Longhorn volume / VAP"
                    )

        if kind == "MutatingAdmissionPolicyBinding":
            add_error(
                f"{source_label} MutatingAdmissionPolicyBinding {document_name} "
                "is forbidden; the restore-driver design uses no mutating admission"
            )


def normalize_shell_continuations(script):
    logical_lines = []
    current = ""
    start_line = 1
    for line_number, line in enumerate(script.splitlines(), start=1):
        stripped = line.rstrip()
        if not current:
            start_line = line_number
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        current += stripped
        logical_lines.append((start_line, current))
        current = ""
    if current:
        logical_lines.append((start_line, current))
    return logical_lines


resources = parent.get("resources") or []
if "vault-restore-validator" not in resources:
    add_error("parent apps kustomization must reference vault-restore-validator")

guard_offline = os.environ.get("GUARD_OFFLINE") == "1"
child_flux_paths, external_flux_kustomizations = discover_flux_child_paths(flux_root_dir)
if external_flux_kustomizations:
    add_warning(
        "external-source Flux Kustomizations are out of scope for local rendering "
        "and are governed by their source repositories: "
        + "; ".join(
            flux_kustomization_id(item) for item in external_flux_kustomizations
        )
    )

if root_render_status == 0:
    root_documents = load_documents(root_rendered_path)
    app_documents = [
        document for document in root_documents if in_validator_footprint(document)
    ]
    app_text = yaml.safe_dump_all(app_documents, sort_keys=True)
    child_documents, failed_child_paths = render_child_flux_documents(
        child_flux_paths,
        failures_are_warnings=guard_offline,
    )
    if failed_child_paths and guard_offline:
        add_warning(
            "GUARD_OFFLINE — one or more child Flux Kustomization renders failed; "
            "falling back to a whole Flux source-tree scan; this run is NOT authoritative"
        )
        binding_scan_documents = source_documents_under(flux_root_dir)
        binding_scan_source = "Flux source tree"
    else:
        binding_scan_documents = dedup_documents(root_documents + child_documents)
        binding_scan_source = "Flux root render plus child Flux Kustomization renders"
elif guard_offline:
    add_warning(
        "GUARD_OFFLINE — Flux-root render skipped; kustomize transforms/top-level "
        "patches NOT verified; this run is NOT authoritative"
    )
    app_text = load_text(app_rendered_path)
    app_documents = load_documents(app_rendered_path)
    binding_scan_documents = source_documents_under(flux_root_dir)
    binding_scan_source = "Flux source tree"
else:
    add_error(
        f"cannot render the Flux root {flux_root_dir} (CI must verify the deployed state); "
        "set GUARD_OFFLINE=1 only for local non-authoritative checks"
    )
    exit_if_errors()

if "enable_unauthenticated_access" in app_text:
    add_error("validator render must not include enable_unauthenticated_access")

if "vault-drill" in app_text or "scratch-vault" in app_text:
    add_error("validator render must not include scratch Vault resources")

for document in app_documents:
    kind = document.get("kind", "")
    resource_name = name(document)

    if kind in {"ClusterRole", "ClusterRoleBinding"}:
        add_error(f"{kind}/{resource_name} is forbidden; Longhorn access must use a namespaced Role")

    if kind == "Job":
        add_error(f"Job/{resource_name} is forbidden; only the suspended CronJob may exist")

    if kind == "StatefulSet":
        add_error(f"StatefulSet/{resource_name} is forbidden; scratch Vault is out of scope")

    if kind not in CLUSTER_SCOPED_KINDS and not namespace(document):
        add_error(f"{kind}/{resource_name} must have an explicit namespace")

    rendered_doc = yaml.safe_dump(document, sort_keys=True)
    if "data-vault" in rendered_doc and not (
        kind == "ConfigMap" and resource_name == RESTORE_DRIVER_SCRIPT_VOLUME
    ):
        add_error(f"{kind}/{resource_name} contains data-vault outside the restore-driver script")

dr_namespace = assert_exactly_one("Namespace", DR_VALIDATE_NS)
if dr_namespace is not None:
    labels = metadata(dr_namespace).get("labels") or {}
    for psa_mode in ("enforce", "audit", "warn"):
        label = f"pod-security.kubernetes.io/{psa_mode}"
        if labels.get(label) != "restricted":
            add_error(f"Namespace/{DR_VALIDATE_NS} must set {label}: restricted")
    if not labels.get("pod-security.kubernetes.io/enforce-version"):
        add_error(f"Namespace/{DR_VALIDATE_NS} must set pod-security.kubernetes.io/enforce-version")

vap = assert_exactly_one("ValidatingAdmissionPolicy", VAP_NAME)
if vap is not None:
    spec = vap.get("spec") or {}
    if spec.get("failurePolicy") != "Fail":
        add_error(f"ValidatingAdmissionPolicy/{VAP_NAME} must set failurePolicy: Fail")

    match_constraints = spec.get("matchConstraints") or {}
    resource_rules = match_constraints.get("resourceRules") or []
    if resource_rules != EXPECTED_VAP_RESOURCE_RULES:
        add_error(
            f"ValidatingAdmissionPolicy/{VAP_NAME} must match exactly longhorn.io */volumes CREATE"
        )
    if "excludeResourceRules" in match_constraints:
        add_error(f"ValidatingAdmissionPolicy/{VAP_NAME} must not define excludeResourceRules")
    for selector_field in ("namespaceSelector", "objectSelector"):
        selector = match_constraints.get(selector_field)
        if selector not in (None, {}):
            add_error(f"ValidatingAdmissionPolicy/{VAP_NAME} must not define matchConstraints.{selector_field}")
    match_policy = spec.get("matchPolicy")
    if match_policy is not None and match_policy != "Equivalent":
        add_error(f"ValidatingAdmissionPolicy/{VAP_NAME} spec.matchPolicy must be Equivalent when present")
    match_constraints_policy = match_constraints.get("matchPolicy")
    if match_constraints_policy is not None and match_constraints_policy != "Equivalent":
        add_error(
            f"ValidatingAdmissionPolicy/{VAP_NAME} matchConstraints.matchPolicy must be Equivalent when present"
        )

    match_conditions = spec.get("matchConditions") or []
    expected_match_expression = f"request.userInfo.username == '{DR_ORCHESTRATOR_USER}'"
    if len(match_conditions) != 1 or match_conditions[0].get("expression") != expected_match_expression:
        add_error(
            f"ValidatingAdmissionPolicy/{VAP_NAME} must have exactly one matchCondition for {DR_ORCHESTRATOR_USER}"
        )

    validations = spec.get("validations") or []
    validation_expressions = {validation.get("expression") for validation in validations}
    if f"object.metadata.name == '{SCRATCH}'" not in validation_expressions:
        add_error(
            f"ValidatingAdmissionPolicy/{VAP_NAME} must allowlist only {SCRATCH}"
        )
    if "object.spec.numberOfReplicas <= 1" not in validation_expressions:
        add_error(
            f"ValidatingAdmissionPolicy/{VAP_NAME} must cap scratch Longhorn replicas at one"
        )

vap_binding = assert_exactly_one("ValidatingAdmissionPolicyBinding", VAP_NAME)
if vap_binding is not None:
    spec = vap_binding.get("spec") or {}
    if spec.get("policyName") != VAP_NAME:
        add_error(f"ValidatingAdmissionPolicyBinding/{VAP_NAME} must bind {VAP_NAME}")
    if spec.get("validationActions") != ["Deny"]:
        add_error(f"ValidatingAdmissionPolicyBinding/{VAP_NAME} validationActions must be exactly [Deny]")
    if "matchResources" in spec:
        add_error(f"ValidatingAdmissionPolicyBinding/{VAP_NAME} must not define matchResources")
    if "paramRef" in spec:
        add_error(f"ValidatingAdmissionPolicyBinding/{VAP_NAME} must not define paramRef")

for service_account in docs("ServiceAccount"):
    if service_account.get("automountServiceAccountToken") is not False:
        add_error(f"ServiceAccount/{name(service_account)} must set automountServiceAccountToken: false")

roles = docs("Role") + docs("ClusterRole")
bindings = docs("RoleBinding") + docs("ClusterRoleBinding")
roles_by_key = {role_key(role): role for role in roles}

for binding in bindings:
    binding_name = name(binding)
    for subject in binding.get("subjects") or []:
        if not subject_reaches_guarded_sa(subject):
            continue
        subject_name = subject.get("name")
        if binding_key(binding) not in APPROVED_GUARDED_BINDINGS:
            add_error(
                f"{binding.get('kind')}/{binding_name} must not bind {subject_label(subject)}; "
                "only approved restore-validator bindings may name guarded subjects"
            )
        role = roles_by_key.get(role_ref_key(binding))
        if role is None:
            add_error(f"{binding.get('kind')}/{binding_name} references a missing role")
            continue
        if (
            subject_name == DR_ORCHESTRATOR
            and name(role) != "dr-orchestrator-longhorn-restore"
            and role_grants_unapproved_longhorn_destructive(role)
        ):
            add_error(
                f"{binding.get('kind')}/{binding_name} grants dr-orchestrator "
                f"unapproved destructive Longhorn access through {role.get('kind')}/{name(role)}"
            )

for role in roles:
    if name(role) != "dr-orchestrator-longhorn-restore" and role_grants_unapproved_longhorn_destructive(role):
        add_error(
            f"{role.get('kind')}/{name(role)} must not grant unapproved destructive Longhorn access"
        )

assert_guarded_service_account_bindings(binding_scan_documents, binding_scan_source)
assert_guarded_service_account_workloads(binding_scan_documents, binding_scan_source)
assert_no_unapproved_destructive_longhorn_roles(binding_scan_documents, binding_scan_source)
assert_no_ccnp_egress_selects_driver(binding_scan_documents, binding_scan_source)
assert_no_mutating_admission_targets_driver(binding_scan_documents, binding_scan_source)

noop_role = assert_exactly_one("Role", "vault-restore-validator-noop", DR_VALIDATE_NS)
if noop_role is not None and rules_for(noop_role) != []:
    add_error("Role/vault-restore-validator-noop must remain permissionless")

generate_root_binding = assert_exactly_one("RoleBinding", "dr-generate-root-noop", DR_VALIDATE_NS)
if generate_root_binding is not None:
    role_ref = generate_root_binding.get("roleRef") or {}
    if role_ref.get("kind") != "Role" or role_ref.get("name") != "vault-restore-validator-noop":
        add_error("RoleBinding/dr-generate-root-noop must bind the permissionless noop Role")
    subjects = generate_root_binding.get("subjects") or []
    if subjects != [{"kind": "ServiceAccount", "name": DR_GENERATE_ROOT, "namespace": DR_VALIDATE_NS}]:
        add_error("RoleBinding/dr-generate-root-noop must bind only dr-generate-root in dr-validate")

result_role = assert_exactly_one("Role", "dr-orchestrator-result-writer", DR_VALIDATE_NS)
if result_role is not None:
    expected_result_rules = [
        {
            "apiGroups": [""],
            "resources": ["configmaps"],
            "resourceNames": ["dr-restore-driver-result"],
            "verbs": ["get", "create", "update"],
        }
    ]
    if rules_for(result_role) != expected_result_rules:
        add_error(
            "Role/dr-orchestrator-result-writer rules must be exactly "
            "configmaps [get,create,update] scoped to dr-restore-driver-result"
        )

result_binding = assert_exactly_one("RoleBinding", "dr-orchestrator-result-writer", DR_VALIDATE_NS)
if result_binding is not None:
    role_ref = result_binding.get("roleRef") or {}
    if role_ref.get("kind") != "Role" or role_ref.get("name") != "dr-orchestrator-result-writer":
        add_error("RoleBinding/dr-orchestrator-result-writer must bind the result writer Role")
    subjects = result_binding.get("subjects") or []
    if subjects != [{"kind": "ServiceAccount", "name": DR_ORCHESTRATOR, "namespace": DR_VALIDATE_NS}]:
        add_error("RoleBinding/dr-orchestrator-result-writer must bind only dr-orchestrator in dr-validate")

longhorn_role = assert_exactly_one("Role", "dr-orchestrator-longhorn-restore", LONGHORN_NS)
if longhorn_role is not None:
    normalized_rules = {normalized_rbac_rule(rule) for rule in rules_for(longhorn_role)}
    if normalized_rules != APPROVED_LONGHORN_RULES:
        add_error(
            "Role/dr-orchestrator-longhorn-restore rules must be exactly the approved "
            "Longhorn backup read, scratch volume create/read, and scratch-scoped "
            "update/patch/delete rules"
        )

    for rule in rules_for(longhorn_role):
        if any(resource_name.startswith("data-vault") for resource_name in resource_names(rule)):
            add_error("Longhorn Role resourceNames must never include data-vault*")
        if has_unapproved_longhorn_destructive(rule):
            add_error(
                "Role/dr-orchestrator-longhorn-restore must not grant destructive verbs "
                "on any unapproved longhorn.io resource or wildcard"
            )

longhorn_binding = assert_exactly_one("RoleBinding", "dr-orchestrator-longhorn-restore", LONGHORN_NS)
if longhorn_binding is not None:
    role_ref = longhorn_binding.get("roleRef") or {}
    if role_ref.get("kind") != "Role" or role_ref.get("name") != "dr-orchestrator-longhorn-restore":
        add_error("RoleBinding/dr-orchestrator-longhorn-restore must bind the Longhorn restore Role")
    subjects = longhorn_binding.get("subjects") or []
    if subjects != [{"kind": "ServiceAccount", "name": DR_ORCHESTRATOR, "namespace": DR_VALIDATE_NS}]:
        add_error("Longhorn RoleBinding must bind only dr-orchestrator in dr-validate")

script_configmap = assert_exactly_one("ConfigMap", RESTORE_DRIVER_SCRIPT_VOLUME, DR_VALIDATE_NS)
if script_configmap is not None:
    script = ((script_configmap.get("data") or {}).get("restore-driver.sh")) or ""
    if 'readonly SCRATCH="dr-validate-vault-restore"' not in script:
        add_error("restore-driver.sh must hard-code the fixed scratch volume name")
    if '[[ "${SCRATCH}" == data-vault* ]]' not in script:
        add_error("restore-driver.sh must explicitly reject protected data-vault scratch names")
    if 'delete_scratch_volume "${SCRATCH}"' not in script:
        add_error("restore-driver.sh must delete only the fixed scratch volume")
    if "trap finish EXIT" not in script:
        add_error("restore-driver.sh must trap EXIT for fail-closed cleanup/result emission")
    if "fromBackup:" not in script:
        add_error("restore-driver.sh must create the scratch Longhorn Volume from a backup URL")

    create_restore_match = re.search(
        r"create_restore_volume\(\) \{(?P<body>.*?)\n\}",
        script,
        re.DOTALL,
    )
    if create_restore_match is None:
        add_error("restore-driver.sh must define create_restore_volume")
    else:
        create_restore_body = create_restore_match.group("body")
        if "kind: Volume" not in create_restore_body:
            add_error("restore-driver.sh create manifest must create a Longhorn Volume")
        if f"\n  name: {SCRATCH}\n" not in create_restore_body:
            add_error(
                f"restore-driver.sh create manifest must set metadata.name to {SCRATCH}"
            )
        if "kubectl create -f -" not in create_restore_body:
            add_error("restore-driver.sh must use kubectl create for the scratch Volume manifest")

    destructive_target = re.compile(
        r"\bkubectl\b.*\b(create|delete|deletecollection|patch|replace|apply)\b.*data-vault"
    )
    for line_number, logical_line in normalize_shell_continuations(script):
        if "kubectl" not in logical_line:
            continue
        if "data-vault" in logical_line:
            add_error(
                f"restore-driver.sh logical line starting {line_number} has data-vault in a kubectl invocation"
            )
        if destructive_target.search(logical_line):
            add_error(
                f"restore-driver.sh logical line starting {line_number} has destructive data-vault target"
            )

network_policies = docs("NetworkPolicy")
if len(network_policies) != 1:
    add_error(f"expected exactly one NetworkPolicy default deny, found {len(network_policies)}")
network_policy = assert_exactly_one("NetworkPolicy", "vault-restore-validator-default-deny", DR_VALIDATE_NS)
if network_policy is not None:
    spec = network_policy.get("spec") or {}
    if spec.get("podSelector") != {}:
        add_error("default-deny NetworkPolicy must select all pods")
    if sorted(spec.get("policyTypes") or []) != ["Egress", "Ingress"]:
        add_error("default-deny NetworkPolicy must deny both ingress and egress")
    if "ingress" in spec or "egress" in spec:
        add_error("default-deny NetworkPolicy must not include allow rules")

cnps = docs("CiliumNetworkPolicy")
if len(cnps) != 1:
    add_error(f"expected exactly one CiliumNetworkPolicy egress allow, found {len(cnps)}")
cnp = assert_exactly_one("CiliumNetworkPolicy", "dr-orchestrator-egress", DR_VALIDATE_NS)
if cnp is not None:
    spec = cnp.get("spec") or {}
    if "specs" in cnp:
        add_error("approved egress CNP must not use specs; egress must be declared only in spec")
    endpoint_selector = spec.get("endpointSelector") or {}
    if (endpoint_selector.get("matchLabels") or {}) != {
        "app.kubernetes.io/name": "vault-restore-validator",
        "app.kubernetes.io/component": "restore-driver",
    }:
        add_error("CiliumNetworkPolicy must select only restore-driver pods")
    if "ingress" in spec:
        add_error("CiliumNetworkPolicy must not include ingress allow rules")
    if spec.get("egress") != [{"toEntities": ["kube-apiserver"]}]:
        add_error("CiliumNetworkPolicy egress must allow only toEntities: [kube-apiserver]")

cronjob = assert_exactly_one("CronJob", "dr-restore-driver", DR_VALIDATE_NS)
if cronjob is not None:
    spec = cronjob.get("spec") or {}
    if spec.get("suspend") is not True:
        add_error("CronJob/dr-restore-driver must ship spec.suspend: true")
    if spec.get("schedule") != "0 6 31 2 *":
        add_error("CronJob/dr-restore-driver must use the inert Feb-31 schedule placeholder")
    pod_spec = (
        ((spec.get("jobTemplate") or {}).get("spec") or {})
        .get("template", {})
        .get("spec", {})
    )
    if pod_spec.get("serviceAccountName") != DR_ORCHESTRATOR:
        add_error("CronJob/dr-restore-driver must run as dr-orchestrator")
    if pod_spec.get("automountServiceAccountToken") is not True:
        add_error("CronJob/dr-restore-driver pod must explicitly opt in to service account token automount")
    for host_flag in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(host_flag) not in (None, False):
            add_error(f"CronJob/dr-restore-driver pod must not set {host_flag}: true")
    if (pod_spec.get("securityContext") or {}) != EXPECTED_POD_SECURITY_CONTEXT:
        add_error("CronJob/dr-restore-driver pod securityContext must match the approved restricted context")
    if pod_spec.get("initContainers"):
        add_error("CronJob/dr-restore-driver must not define initContainers")
    if pod_spec.get("ephemeralContainers"):
        add_error("CronJob/dr-restore-driver must not define ephemeralContainers")

    containers = pod_spec.get("containers") or []
    if len(containers) != 1:
        add_error(f"CronJob/dr-restore-driver must define exactly one container, found {len(containers)}")
    else:
        container = containers[0]
        if container.get("command") != RESTORE_DRIVER_COMMAND:
            add_error("CronJob/dr-restore-driver command must execute the mounted restore-driver.sh with /bin/bash")
        if container.get("image") != APPROVED_RESTORE_DRIVER_IMAGE:
            add_error("CronJob/dr-restore-driver image must match the approved digest exactly")
        container_env = container.get("env") or []
        if (
            len(container_env) != len(EXPECTED_CONTAINER_ENV)
            or canonical_object_set(container_env) != canonical_object_set(
                EXPECTED_CONTAINER_ENV
            )
        ):
            add_error(
                "CronJob/dr-restore-driver container env must be exactly the approved "
                "provenance vars — no secretKeyRef or extra vars"
            )
        if container.get("envFrom"):
            add_error("CronJob/dr-restore-driver container must not use envFrom")
        if container.get("lifecycle"):
            add_error("CronJob/dr-restore-driver container must not define lifecycle hooks")
        for probe_name in ("livenessProbe", "readinessProbe", "startupProbe"):
            if probe_name in container:
                add_error(
                    "CronJob/dr-restore-driver container must not define probes — "
                    f"{probe_name} is an arbitrary-command surface"
                )
        if container.get("args"):
            add_error("CronJob/dr-restore-driver command is pinned; args are forbidden")

        container_security = container.get("securityContext") or {}
        if container_security.get("allowPrivilegeEscalation") is not False:
            add_error("CronJob/dr-restore-driver container must disable privilege escalation")
        if container_security.get("capabilities") != {"drop": ["ALL"]}:
            add_error("CronJob/dr-restore-driver container must drop exactly capability ALL")
        if container_security.get("readOnlyRootFilesystem") is not True:
            add_error("CronJob/dr-restore-driver container must use a read-only root filesystem")
        if container_security.get("runAsNonRoot") is False:
            add_error("CronJob/dr-restore-driver container must not override runAsNonRoot to false")
        if container_security.get("privileged") is True:
            add_error("CronJob/dr-restore-driver container must not be privileged")

        if canonical_object_set(container.get("volumeMounts") or []) != canonical_object_set(
            EXPECTED_RESTORE_DRIVER_MOUNTS
        ):
            add_error("CronJob/dr-restore-driver volumeMounts must be exactly the approved script and /tmp mounts")

    volumes = pod_spec.get("volumes") or []
    if canonical_object_set(volumes) != canonical_object_set(EXPECTED_RESTORE_DRIVER_VOLUMES):
        add_error("CronJob/dr-restore-driver volumes must be exactly the approved script ConfigMap and tmp emptyDir")

if "enable_unauthenticated_access" in app_text:
    add_error("rendered validator app must not contain generate-root recovery config")

exit_if_errors()

print("OK: Vault restore-validator restore-driver safety invariants hold")
PY
