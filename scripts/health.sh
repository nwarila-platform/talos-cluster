#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"
STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
TALOSCONFIG="${STATE_ROOT}/configs/talosconfig"
KUBECONFIG="${KUBECONFIG:-${STATE_ROOT}/configs/kubeconfig}"
export KUBECONFIG

CP_IPS=""
WORKER_IPS=""
for entry in ${CP_NODES}; do CP_IPS="${CP_IPS:+${CP_IPS},}${entry##*:}"; done
for entry in ${WORKER_NODES}; do WORKER_IPS="${WORKER_IPS:+${WORKER_IPS},}${entry##*:}"; done

for command in talosctl kubectl helm jq; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done

talosctl health --talosconfig "${TALOSCONFIG}" --nodes "${BOOTSTRAP_NODE##*:}" \
    --control-plane-nodes "${CP_IPS}" --worker-nodes "${WORKER_IPS}" --wait-timeout 5m

failed=false
nodes_json="$(kubectl get nodes -o json)"
expected_node_count=0
for entry in ${CP_NODES} ${WORKER_NODES}; do
    ((expected_node_count += 1))
done
actual_node_count="$(jq '.items | length' <<<"${nodes_json}")"
if (( actual_node_count != expected_node_count )); then
    echo "ERROR: expected ${expected_node_count} nodes, found ${actual_node_count}" >&2
    failed=true
fi
node_failures="$(jq -r '
    .items[]
    | [.status.conditions[]? | select(.type == "Ready") | .status] as $ready
    | select(($ready | length) == 0 or any($ready[]; . != "True"))
    | "ERROR: node \(.metadata.name) Ready=\($ready | if length == 0 then "missing" else join(",") end)"
' <<<"${nodes_json}")"
if [[ -n "${node_failures}" ]]; then
    printf '%s\n' "${node_failures}" >&2
    failed=true
fi

pods_json="$(kubectl get pods -A -o json)"
pod_failures="$(jq -r '
    .items[]
    | (.status.phase // "Unknown") as $phase
    | [.status.containerStatuses[]? | select(.ready != true) | .name] as $not_ready
    | [.status.conditions[]? | select(.type == "Ready")] as $ready
    | select(
        $phase != "Succeeded"
        and (
          $phase != "Running"
          or ((.status.containerStatuses // []) | length) == 0
          or $not_ready != []
          or ($ready | length) != 1
          or $ready[0].status != "True"
        )
      )
    | ($ready
       | if length == 0 then "missing"
         elif length == 1 then (.[0].status // "missing")
         else (map(.status // "missing") | join(","))
         end) as $ready_status
    | ($ready
       | if length == 0 then "missing"
         elif length == 1 then (.[0].reason // "none")
         else (map(.reason // "none") | join(","))
         end) as $ready_reason
    | "ERROR: pod \(.metadata.namespace)/\(.metadata.name) phase=\($phase) "
      + "Ready=\($ready_status) reason=\($ready_reason) "
      + "not-ready-app-containers=\($not_ready | if length == 0 then "none" else join(",") end)"
' <<<"${pods_json}")"
if [[ -n "${pod_failures}" ]]; then
    printf '%s\n' "${pod_failures}" >&2
    failed=true
fi

releases='[]'
offset=0
while true; do
    page="$(helm list -A --all --max 256 --offset "${offset}" -o json)"
    page_count="$(jq 'length' <<<"${page}")"
    releases="$(jq -s 'add' <(printf '%s\n' "${releases}") <(printf '%s\n' "${page}"))"
    (( page_count < 256 )) && break
    ((offset += 256))
done
release_failures="$(jq -r '
    .[]
    | select(.status != "deployed" and .status != "uninstalled" and .status != "superseded")
    | "ERROR: release \(.namespace)/\(.name) status=\(.status)"
' <<<"${releases}")"
if [[ -n "${release_failures}" ]]; then
    printf '%s\n' "${release_failures}" >&2
    failed=true
fi
while read -r namespace name; do
    release_count="$(jq --arg namespace "${namespace}" --arg name "${name}" '
        [.[] | select(.namespace == $namespace and .name == $name and .status == "deployed")] | length
    ' <<<"${releases}")"
    if (( release_count != 1 )); then
        echo "ERROR: expected deployed release ${namespace}/${name} exactly once, found ${release_count}" >&2
        failed=true
    fi
done <<'EOF'
tigera-operator calico
longhorn-system longhorn
argocd argocd
vault vault
cert-manager cert-manager
keycloak cnpg
EOF

# The Keycloak platform is healthy only when its operands are: the operator Deployments available,
# the issuer and certificate Ready, the database cluster healthy with both instances, the server
# Ready, the realm imported without errors, the tunnel connector rolled out. Each read must succeed
# (a failed read is an error, never "absent and fine"); a missing object is an error too — this gate
# is meaningful only after the full rebuild order, which is when it runs.
operand() {  # operand DESCRIPTION KUBECTL-ARGS... : the value must be non-empty and equal to the last argument
    local description="$1" want="${*: -1}" got; shift
    set -- "${@:1:$#-1}"
    if ! got="$(kubectl "$@" 2>&1)"; then echo "ERROR: ${description}: cannot read (${got})" >&2; failed=true; return 0; fi
    [[ "${got}" == "${want}" ]] || { echo "ERROR: ${description}: ${got:-missing} (want ${want})" >&2; failed=true; }
}
operand "keycloak-operator Deployment available" -n keycloak get deployment keycloak-operator -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' True
operand "cnpg operator Deployment available" -n keycloak get deployment cnpg-cloudnative-pg -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' True
operand "ClusterIssuer vault-tcn-server Ready" get clusterissuer vault-tcn-server -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' True
operand "Certificate keycloak-tls Ready" -n keycloak get certificate keycloak-tls -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' True
operand "database cluster keycloak-db healthy" -n keycloak get cluster keycloak-db -o jsonpath='{.status.phase}' "Cluster in healthy state"
operand "database cluster keycloak-db instances ready" -n keycloak get cluster keycloak-db -o jsonpath='{.status.readyInstances}' 2
operand "Keycloak keycloak Ready" -n keycloak get keycloak keycloak -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' True
operand "realm import tcn Done" -n keycloak get keycloakrealmimport tcn -o jsonpath='{.status.conditions[?(@.type=="Done")].status}' True
operand "realm import tcn without errors" -n keycloak get keycloakrealmimport tcn -o jsonpath='{.status.conditions[?(@.type=="HasErrors")].status}' False
operand "cloudflared Deployment available" -n keycloak get deployment cloudflared -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' True

if [[ "${failed}" == true ]]; then
    exit 1
fi

kubectl get nodes -o wide
kubectl get pods -A
helm list -A
echo "Platform healthy."
