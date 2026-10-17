#!/usr/bin/env bash
# Upgrades nodes to the Talos image declared in cluster/config.env (TALOS_INSTALL_IMAGE: the
# installer-secureboot image of TALOS_SCHEMATIC_ID at TALOS_VERSION), one node at a time, stopping at
# the first failed check. Kubernetes is not touched (that is talosctl upgrade-k8s, a separate step).
#   CONFIRM_REBUILD=TDNHQ-TALCL01 make upgrade NODES="w3"         one node
#   CONFIRM_REBUILD=TDNHQ-TALCL01 make upgrade                     every node, in the order below
# Default order, lowest recovery risk first: the workers, then the control planes, with the one
# holding the Vault raft leader last. Each node reboots; the nodes boot with Secure Boot and unlock
# their disks from the TPM, and a node that cannot unlock is recovered at the rack, so the checks
# before each node refuse to start on anything less than a healthy cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

[[ "${CONFIRM_REBUILD:-}" == "TDNHQ-TALCL01" ]] || { echo "ERROR: set CONFIRM_REBUILD=TDNHQ-TALCL01 to authorize node upgrades" >&2; exit 1; }
STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
TALOSCONFIG="${STATE_ROOT}/configs/talosconfig"
KUBECONFIG="${STATE_ROOT}/configs/kubeconfig"
export TALOSCONFIG KUBECONFIG
VIP="${CLUSTER_VIP}"

declare -A NODE_IP=() NODE_ROLE=()
for entry in ${CP_NODES}; do NODE_IP["${entry%%:*}"]="${entry##*:}"; NODE_ROLE["${entry%%:*}"]=controlplane; done
for entry in ${WORKER_NODES}; do NODE_IP["${entry%%:*}"]="${entry##*:}"; NODE_ROLE["${entry%%:*}"]=worker; done

t() { local ip="$1"; shift; talosctl -e "${VIP}" -n "${ip}" "$@"; }
ready() { [[ "$(kubectl get node "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" == True ]]; }
# Every encrypted volume on the node (STATE, EPHEMERAL, u-*) unlocked and ready.
volumes_ok() { t "$1" get volumestatus -o json | jq -se '[.[] | select((.spec.encryptionProvider // "") != "")] | length > 0 and all(.spec.phase == "ready")' >/dev/null; }
longhorn_ok() { kubectl -n longhorn-system get volumes.longhorn.io -o json | jq -e '[.items[] | select(.status.state == "attached")] | all(.status.robustness == "healthy")' >/dev/null; }
# etcd on the node is healthy and sees every control plane as a voting member.
etcd_ok() { [[ "$(t "$1" etcd members 2>/dev/null | grep -c 'false$')" == "${#CP_LIST[@]}" ]] && t "$1" service etcd 2>/dev/null | grep -q '^HEALTH *OK'; }
CP_LIST=(); for entry in ${CP_NODES}; do CP_LIST+=("${entry%%:*}"); done

read -r -a TARGETS <<< "${NODES:-}"
if (( ${#TARGETS[@]} == 0 )); then
    leader="$(kubectl -n vault get pods -l vault-active=true -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null || true)"
    for entry in ${WORKER_NODES}; do TARGETS+=("${entry%%:*}"); done
    for name in "${CP_LIST[@]}"; do [[ "${name}" == "${leader}" ]] || TARGETS+=("${name}"); done
    [[ -z "${leader}" ]] || TARGETS+=("${leader}")
fi
for name in "${TARGETS[@]}"; do [[ -v "NODE_IP[${name}]" ]] || { echo "ERROR: unknown node ${name}" >&2; exit 1; }; done
echo "Upgrading ${TARGETS[*]} to ${TALOS_INSTALL_IMAGE##*/}"

for name in "${TARGETS[@]}"; do
    ip="${NODE_IP[${name}]}"
    echo; echo "== ${name} (${ip}) $(date -u +%H:%M:%SZ)"
    current="$(t "${ip}" version 2>/dev/null | awk '/^Server/ {s=1} s && /Tag:/ {print $2; exit}')"
    schematic="$(t "${ip}" get extensions -o json | jq -r 'select(.spec.metadata.name == "schematic") | .spec.metadata.version')"
    if [[ "${current}" == "${TALOS_VERSION}" && "${schematic}" == "${TALOS_SCHEMATIC_ID}" ]]; then
        echo "already on ${TALOS_VERSION} with the declared schematic; skipped"; continue
    fi
    # Before: a healthy node and cluster, or no reboot.
    ready "${name}" || { echo "STOP: ${name} is not Ready" >&2; exit 1; }
    [[ "$(t "${ip}" get securitystate -o json | jq -r .spec.secureBoot)" == true ]] || { echo "STOP: ${name} does not report Secure Boot" >&2; exit 1; }
    volumes_ok "${ip}" || { echo "STOP: an encrypted volume on ${name} is not ready" >&2; exit 1; }
    longhorn_ok || { echo "STOP: a Longhorn volume is not healthy; a reboot now could leave it without a replica" >&2; exit 1; }
    if [[ "${NODE_ROLE[${name}]}" == controlplane ]]; then
        etcd_ok "${ip}" || { echo "STOP: etcd is not healthy with all ${#CP_LIST[@]} members" >&2; exit 1; }
        # Before the first control plane of a run: an etcd snapshot. A new Talos version can bring a
        # new etcd whose data an older one cannot read back, so a rollback past that point needs it.
        if [[ -z "${ETCD_SNAPSHOT:-}" ]]; then
            ETCD_SNAPSHOT="${STATE_ROOT}/etcd/etcd-$(date -u +%Y%m%dT%H%M%SZ).db"
            ( umask 077; mkdir -p "${STATE_ROOT}/etcd"; t "${ip}" etcd snapshot "${ETCD_SNAPSHOT}" )
            [[ -s "${ETCD_SNAPSHOT}" ]] || { echo "STOP: the etcd snapshot is empty" >&2; exit 1; }
            echo "etcd snapshot: ${ETCD_SNAPSHOT}"
        fi
    fi
    # The key Sidero signs each boot's PCR policy with; the disks unlock only while it stays the same.
    pcr_key="$(t "${ip}" get securitystate -o json | jq -r .spec.pcrSigningKeyFingerprint)"
    echo "before: ${current} schematic ${schematic:0:12}, PCR signing key ${pcr_key:0:23}; checks passed"

    # The upgrade: Talos cordons and drains the node, installs the image, reboots and waits.
    t "${ip}" upgrade --image "${TALOS_INSTALL_IMAGE}" --wait --timeout 25m

    # After: the declared version and image, Secure Boot, every disk unlocked, the node back in service.
    for _ in $(seq 1 60); do ready "${name}" && break; sleep 10; done
    ready "${name}" || { echo "STOP: ${name} did not become Ready" >&2; exit 1; }
    after="$(t "${ip}" version 2>/dev/null | awk '/^Server/ {s=1} s && /Tag:/ {print $2; exit}')"
    [[ "${after}" == "${TALOS_VERSION}" ]] || { echo "STOP: ${name} runs ${after:-unknown}, not ${TALOS_VERSION}" >&2; exit 1; }
    [[ "$(t "${ip}" get securitystate -o json | jq -r .spec.secureBoot)" == true ]] || { echo "STOP: ${name} lost Secure Boot" >&2; exit 1; }
    [[ "$(t "${ip}" get securitystate -o json | jq -r .spec.pcrSigningKeyFingerprint)" == "${pcr_key}" ]] \
        || { echo "STOP: ${name} boots with a different PCR signing key; do not upgrade another node" >&2; exit 1; }
    [[ "$(t "${ip}" get extensions -o json | jq -r 'select(.spec.metadata.name == "schematic") | .spec.metadata.version')" == "${TALOS_SCHEMATIC_ID}" ]] \
        || { echo "STOP: ${name} is not on schematic ${TALOS_SCHEMATIC_ID}" >&2; exit 1; }
    for _ in $(seq 1 24); do volumes_ok "${ip}" && break; sleep 5; done
    volumes_ok "${ip}" || { echo "STOP: an encrypted volume on ${name} did not unlock" >&2; t "${ip}" get volumestatus >&2; exit 1; }
    [[ -z "$(kubectl get node "${name}" -o jsonpath='{.spec.unschedulable}')" ]] || kubectl uncordon "${name}"
    if [[ "${NODE_ROLE[${name}]}" == controlplane ]]; then
        for _ in $(seq 1 30); do etcd_ok "${ip}" && break; sleep 10; done
        etcd_ok "${ip}" || { echo "STOP: etcd did not return to healthy" >&2; exit 1; }
        # The Vault pod on this node (if any) is ready once the unsealer has opened it.
        pod="$(kubectl -n vault get pods -l app.kubernetes.io/name=vault,component=server --field-selector "spec.nodeName=${name}" -o name 2>/dev/null | head -1)"
        [[ -z "${pod}" ]] || kubectl -n vault wait --for=condition=Ready "${pod}" --timeout=5m
    fi
    for _ in $(seq 1 60); do longhorn_ok && break; sleep 10; done
    longhorn_ok || { echo "STOP: Longhorn volumes did not return to healthy" >&2; exit 1; }
    lockdown="$(t "${ip}" read /sys/kernel/security/lockdown 2>/dev/null | grep -oE '\[[a-z]+\]' || true)"
    echo "after: ${after}, Secure Boot on, same PCR signing key, kernel lockdown ${lockdown:-unknown}, schematic ${TALOS_SCHEMATIC_ID:0:12}, encrypted volumes ready; ${name} done $(date -u +%H:%M:%SZ)"
done
echo; echo "Upgrade complete: ${TARGETS[*]} on ${TALOS_VERSION}. Then: make health"
