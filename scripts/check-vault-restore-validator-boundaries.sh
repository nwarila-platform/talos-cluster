#!/usr/bin/env bash
# =============================================================================
# check-vault-restore-validator-boundaries.sh - Guard ADR-0020 restore driver.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="clusters/talos-cluster/apps/vault-restore-validator"
KYVERNO_POLICY_DIR="clusters/talos-cluster/apps/kyverno/policies"
PARENT_KUSTOMIZATION="clusters/talos-cluster/apps/kustomization.yaml"

cd "${ROOT_DIR}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

app_rendered="${tmpdir}/validator.yaml"
kyverno_rendered="${tmpdir}/kyverno.yaml"

kubectl kustomize "${APP_DIR}" >"${app_rendered}"
kubectl kustomize "${KYVERNO_POLICY_DIR}" >"${kyverno_rendered}"

python3 - "${app_rendered}" "${kyverno_rendered}" "${PARENT_KUSTOMIZATION}" <<'PY'
import re
import sys

import yaml

app_rendered_path = sys.argv[1]
kyverno_rendered_path = sys.argv[2]
parent_kustomization = sys.argv[3]

SCRATCH = "dr-validate-vault-restore"
DR_ORCHESTRATOR_USER = "system:serviceaccount:dr-validate:dr-orchestrator"


def load_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def load_documents(path):
    return [
        document
        for document in yaml.safe_load_all(load_text(path))
        if isinstance(document, dict)
    ]


app_text = load_text(app_rendered_path)
kyverno_text = load_text(kyverno_rendered_path)
app_documents = load_documents(app_rendered_path)
kyverno_documents = load_documents(kyverno_rendered_path)

with open(parent_kustomization, encoding="utf-8") as handle:
    parent = yaml.safe_load(handle)

errors = []


def add_error(message):
    errors.append(message)


def metadata(document):
    return document.get("metadata") or {}


def name(document):
    return metadata(document).get("name", "")


def namespace(document):
    return metadata(document).get("namespace", "")


def labels(document):
    return metadata(document).get("labels") or {}


def docs(kind=None, resource_name=None, resource_namespace=None, source=None):
    haystack = app_documents if source is None else source
    selected = haystack
    if kind is not None:
        selected = [document for document in selected if document.get("kind") == kind]
    if resource_name is not None:
        selected = [document for document in selected if name(document) == resource_name]
    if resource_namespace is not None:
        selected = [document for document in selected if namespace(document) == resource_namespace]
    return selected


def rules_for(role):
    return role.get("rules") or []


def list_value(value):
    return value if isinstance(value, list) else []


def has_resource(rule, resource):
    return resource in list_value(rule.get("resources"))


def has_api_group(rule, api_group):
    return api_group in list_value(rule.get("apiGroups"))


def verbs(rule):
    return set(list_value(rule.get("verbs")))


def resource_names(rule):
    return list_value(rule.get("resourceNames"))


def assert_exactly_one(kind, resource_name, resource_namespace=None, source=None):
    matches = docs(kind, resource_name, resource_namespace, source)
    if len(matches) != 1:
        ns_text = f" in namespace {resource_namespace}" if resource_namespace else ""
        add_error(f"expected exactly one {kind}/{resource_name}{ns_text}, found {len(matches)}")
        return None
    return matches[0]


resources = parent.get("resources") or []
if "vault-restore-validator" not in resources:
    add_error("parent apps kustomization must reference vault-restore-validator")

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

    if kind not in {"Namespace"} and not namespace(document):
        add_error(f"{kind}/{resource_name} must have an explicit namespace")

    rendered_doc = yaml.safe_dump(document, sort_keys=True)
    if "data-vault" in rendered_doc and not (
        kind == "ConfigMap" and resource_name == "dr-restore-driver-script"
    ):
        add_error(f"{kind}/{resource_name} contains data-vault outside the restore-driver script")

for service_account in docs("ServiceAccount"):
    if service_account.get("automountServiceAccountToken") is not False:
        add_error(f"ServiceAccount/{name(service_account)} must set automountServiceAccountToken: false")

noop_role = assert_exactly_one("Role", "vault-restore-validator-noop", "dr-validate")
if noop_role is not None and rules_for(noop_role) not in (None, []):
    add_error("Role/vault-restore-validator-noop must remain permissionless")

generate_root_binding = assert_exactly_one("RoleBinding", "dr-generate-root-noop", "dr-validate")
if generate_root_binding is not None:
    role_ref = generate_root_binding.get("roleRef") or {}
    if role_ref.get("kind") != "Role" or role_ref.get("name") != "vault-restore-validator-noop":
        add_error("RoleBinding/dr-generate-root-noop must bind the permissionless noop Role")
    subjects = generate_root_binding.get("subjects") or []
    if subjects != [{"kind": "ServiceAccount", "name": "dr-generate-root", "namespace": "dr-validate"}]:
        add_error("RoleBinding/dr-generate-root-noop must bind only dr-generate-root in dr-validate")

longhorn_role = assert_exactly_one("Role", "dr-orchestrator-longhorn-restore", "longhorn-system")
if longhorn_role is not None:
    exact_destructive_rule_seen = False
    for rule in rules_for(longhorn_role):
        if any(resource_name.startswith("data-vault") for resource_name in resource_names(rule)):
            add_error("Longhorn Role resourceNames must never include data-vault*")

        if has_api_group(rule, "longhorn.io") and has_resource(rule, "volumes"):
            destructive = verbs(rule) & {"delete", "patch", "update"}
            if destructive:
                if resource_names(rule) != [SCRATCH]:
                    add_error(
                        "Longhorn volume delete/patch/update verbs must be resourceNames-scoped "
                        f"exactly to [{SCRATCH}]"
                    )
                else:
                    exact_destructive_rule_seen = True
            if "create" in verbs(rule) and resource_names(rule):
                add_error("Longhorn volume create must not use resourceNames; Kubernetes cannot scope create by name")

    if not exact_destructive_rule_seen:
        add_error("missing Longhorn volumes delete/patch/update rule scoped exactly to the scratch name")

    expected_read_rule = False
    expected_create_rule = False
    for rule in rules_for(longhorn_role):
        if (
            has_api_group(rule, "longhorn.io")
            and set(rule.get("resources") or []) == {"backups", "backupvolumes", "backuptargets"}
            and verbs(rule) == {"get", "list", "watch"}
            and not resource_names(rule)
        ):
            expected_read_rule = True
        if (
            has_api_group(rule, "longhorn.io")
            and set(rule.get("resources") or []) == {"volumes"}
            and verbs(rule) == {"get", "list", "watch", "create"}
            and not resource_names(rule)
        ):
            expected_create_rule = True
    if not expected_read_rule:
        add_error("Longhorn Role must read backups, backupvolumes, and backuptargets with get/list/watch only")
    if not expected_create_rule:
        add_error("Longhorn Role must grant volumes get/list/watch/create without destructive verbs")

longhorn_binding = assert_exactly_one("RoleBinding", "dr-orchestrator-longhorn-restore", "longhorn-system")
if longhorn_binding is not None:
    role_ref = longhorn_binding.get("roleRef") or {}
    if role_ref.get("kind") != "Role" or role_ref.get("name") != "dr-orchestrator-longhorn-restore":
        add_error("RoleBinding/dr-orchestrator-longhorn-restore must bind the Longhorn restore Role")
    subjects = longhorn_binding.get("subjects") or []
    if subjects != [{"kind": "ServiceAccount", "name": "dr-orchestrator", "namespace": "dr-validate"}]:
        add_error("Longhorn RoleBinding must bind only dr-orchestrator in dr-validate")

script_configmap = assert_exactly_one("ConfigMap", "dr-restore-driver-script", "dr-validate")
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
    destructive_target = re.compile(r"\bkubectl\b.*\b(delete|patch|replace|apply)\b.*data-vault")
    for line_number, line in enumerate(script.splitlines(), start=1):
        if destructive_target.search(line):
            add_error(f"restore-driver.sh line {line_number} has destructive data-vault target")
    if "fromBackup:" not in script:
        add_error("restore-driver.sh must create the scratch Longhorn Volume from a backup URL")

network_policy = assert_exactly_one("NetworkPolicy", "vault-restore-validator-default-deny", "dr-validate")
if network_policy is not None:
    spec = network_policy.get("spec") or {}
    if spec.get("podSelector") != {}:
        add_error("default-deny NetworkPolicy must select all pods")
    if sorted(spec.get("policyTypes") or []) != ["Egress", "Ingress"]:
        add_error("default-deny NetworkPolicy must deny both ingress and egress")
    if "ingress" in spec or "egress" in spec:
        add_error("default-deny NetworkPolicy must not include allow rules")

cnp = assert_exactly_one("CiliumNetworkPolicy", "dr-orchestrator-egress", "dr-validate")
if cnp is not None:
    spec = cnp.get("spec") or {}
    endpoint_selector = spec.get("endpointSelector") or {}
    if (endpoint_selector.get("matchLabels") or {}) != {
        "app.kubernetes.io/name": "vault-restore-validator",
        "app.kubernetes.io/component": "restore-driver",
    }:
        add_error("CiliumNetworkPolicy must select only restore-driver pods")
    egress = spec.get("egress") or []
    if egress != [{"toEntities": ["kube-apiserver"]}]:
        add_error("CiliumNetworkPolicy egress must allow only toEntities: [kube-apiserver]")

cronjobs = docs("CronJob")
if not cronjobs:
    add_error("expected the suspended dr-restore-driver CronJob")
for cronjob in cronjobs:
    spec = cronjob.get("spec") or {}
    resource_name = name(cronjob)
    if spec.get("suspend") is not True:
        add_error(f"CronJob/{resource_name} must ship spec.suspend: true")
    if spec.get("schedule") != "0 6 31 2 *":
        add_error(f"CronJob/{resource_name} must use the inert Feb-31 schedule placeholder")
    pod_spec = (
        ((spec.get("jobTemplate") or {}).get("spec") or {})
        .get("template", {})
        .get("spec", {})
    )
    if pod_spec.get("serviceAccountName") != "dr-orchestrator":
        add_error(f"CronJob/{resource_name} must run as dr-orchestrator")
    if pod_spec.get("automountServiceAccountToken") is not True:
        add_error(f"CronJob/{resource_name} pod must explicitly opt in to service account token automount")
    for container in pod_spec.get("containers") or []:
        image = container.get("image") or ""
        if "@sha256:" not in image:
            add_error(f"CronJob/{resource_name} container {container.get('name')} image must be digest-pinned")

kyverno_policy = assert_exactly_one(
    "ClusterPolicy",
    "protect-live-vault-longhorn-volume",
    source=kyverno_documents,
)
if kyverno_policy is not None:
    spec = kyverno_policy.get("spec") or {}
    if spec.get("validationFailureAction") != "Enforce":
        add_error("protect-live-vault-longhorn-volume must enforce admission denial")
    policy_text = yaml.safe_dump(kyverno_policy, sort_keys=True)
    for required in (
        "longhorn.io/v1beta2/Volume",
        "CREATE",
        "UPDATE",
        "DELETE",
        DR_ORCHESTRATOR_USER,
        "^data-vault",
    ):
        if required not in policy_text:
            add_error(f"protect-live-vault-longhorn-volume missing required guard token: {required}")

if "enable_unauthenticated_access" in app_text:
    add_error("rendered validator app must not contain generate-root recovery config")

if errors:
    print("Vault restore-validator restore-driver guard failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

print("OK: Vault restore-validator restore-driver safety invariants hold")
PY
