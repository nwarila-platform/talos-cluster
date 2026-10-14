#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

if [[ "${CONFIRM_REBUILD:-}" != "TDNHQ-TALCL01" ]]; then
    echo "ERROR: set CONFIRM_REBUILD=TDNHQ-TALCL01 to authorize platform changes" >&2
    exit 1
fi

for command in helm kubectl; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done

STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
KUBECONFIG="${STATE_ROOT}/configs/kubeconfig"
export KUBECONFIG
[[ -f "${KUBECONFIG}" ]] || { echo "ERROR: kubeconfig not found: ${KUBECONFIG}" >&2; exit 1; }
actual_server="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
[[ "${actual_server}" == "${CLUSTER_ENDPOINT}" ]] || {
    echo "ERROR: kubeconfig server ${actual_server:-missing} is not ${CLUSTER_ENDPOINT}" >&2
    exit 1
}

helm repo add projectcalico https://docs.tigera.io/calico/charts --force-update
helm repo add longhorn https://charts.longhorn.io --force-update
helm repo add argo https://argoproj.github.io/argo-helm --force-update
helm repo add hashicorp https://helm.releases.hashicorp.com --force-update
helm repo update

helm template calico-crds projectcalico/crd.projectcalico.org.v1 --version "${CALICO_VERSION}" \
    | kubectl apply --server-side -f -
helm upgrade --install calico projectcalico/tigera-operator \
    --version "${CALICO_VERSION}" --namespace tigera-operator --create-namespace \
    --values "${ROOT_DIR}/platform/calico/values.yaml" --atomic --timeout 10m
kubectl wait nodes --all --for=condition=Ready --timeout=10m

kubectl apply -f "${ROOT_DIR}/platform/longhorn/namespace.yaml"
# Do not use --atomic: Longhorn guards uninstall through a pre-delete hook.
helm upgrade --install longhorn longhorn/longhorn \
    --version "${LONGHORN_VERSION}" --namespace longhorn-system \
    --values "${ROOT_DIR}/platform/longhorn/values.yaml" --wait --timeout 15m

helm upgrade --install argocd argo/argo-cd \
    --version "${ARGO_CD_VERSION}" --namespace argocd --create-namespace \
    --values "${ROOT_DIR}/platform/argocd/values.yaml" --atomic --timeout 10m

kubectl apply -k "${ROOT_DIR}/platform/vault"
"${ROOT_DIR}/scripts/vault-tls.sh"
helm upgrade --install vault hashicorp/vault \
    --version "${VAULT_CHART_VERSION}" --namespace vault \
    --values "${ROOT_DIR}/platform/vault/values.yaml" --timeout 10m

kubectl -n vault wait --for=create pod/vault-0 --timeout=5m
kubectl -n vault wait --for=condition=PodScheduled pod/vault-0 --timeout=5m

echo "Platform installed. Initialize and unseal Vault with: make vault-init"
