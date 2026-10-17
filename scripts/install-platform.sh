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
kubectl apply -f "${ROOT_DIR}/platform/longhorn/recurringjob-default-backup.yaml"

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

# Certificates: cert-manager from its OCI chart, fetched by digest (CRDs installed and kept), the
# Vault CA as the issuer's trust anchor, and the cluster issuer that signs through Vault (its Vault
# role is created by make gitlab-vault; until then the issuer reports not ready).
helm upgrade --install cert-manager "${CERT_MANAGER_CHART}" \
    --namespace cert-manager --create-namespace \
    --values "${ROOT_DIR}/platform/cert-manager/values.yaml" --atomic --timeout 10m
kubectl -n cert-manager create secret generic vault-ca \
    --from-file=ca.crt="${STATE_ROOT}/vault/tls/ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "${ROOT_DIR}/platform/cert-manager/issuer.yaml"

# Keycloak: the namespace first (both operators live in it, namespace-scoped), then CloudNativePG
# (chart by digest, watching only this namespace), the vendored Keycloak operator (server-side
# apply: its CRDs exceed the client-side annotation limit), and the
# workload: database, certificate, server, LAN Service, tunnel connector. Keycloak waits for its
# certificate (gitlab-vault) and the connector for its token Secret (cloudflare); the realm is
# imported by make keycloak.
# The GitLab tunnel connector (its token Secret comes from terraform/cloudflare; until then it waits).
kubectl apply -k "${ROOT_DIR}/platform/cloudflared"
kubectl apply -f "${ROOT_DIR}/platform/keycloak/namespace.yaml"
helm upgrade --install cnpg "${CNPG_CHART}" \
    --namespace keycloak \
    --values "${ROOT_DIR}/platform/cnpg/values.yaml" --atomic --timeout 10m
kubectl apply --server-side --force-conflicts -k "${ROOT_DIR}/platform/keycloak-operator"
kubectl -n keycloak rollout status deployment/keycloak-operator --timeout=5m
kubectl apply -k "${ROOT_DIR}/platform/keycloak"

echo "Platform installed. Initialize and unseal Vault with: make vault-init"
