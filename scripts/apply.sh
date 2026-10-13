#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

if [[ "${CONFIRM_REBUILD:-}" != "TDNHQ-TALCL01" ]]; then
    echo "ERROR: set CONFIRM_REBUILD=TDNHQ-TALCL01 to authorize machine changes" >&2
    exit 1
fi

STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
TALOSCONFIG="${STATE_ROOT}/configs/talosconfig"
INSECURE_ARGS=()
TARGETS=()

while (( $# > 0 )); do
    case "$1" in
        --insecure) INSECURE_ARGS=(--insecure); shift ;;
        --) shift; TARGETS+=("$@"); break ;;
        -*) echo "ERROR: unknown option: $1" >&2; exit 1 ;;
        *) TARGETS+=("$1"); shift ;;
    esac
done

declare -A NODE_IP=()
declare -A NODE_ROLE=()
for entry in ${CP_NODES}; do
    NODE_IP["${entry%%:*}"]="${entry##*:}"
    NODE_ROLE["${entry%%:*}"]="controlplane"
done
for entry in ${WORKER_NODES}; do
    NODE_IP["${entry%%:*}"]="${entry##*:}"
    NODE_ROLE["${entry%%:*}"]="worker"
done

if (( ${#TARGETS[@]} == 0 )); then
    for entry in ${CP_NODES} ${WORKER_NODES}; do TARGETS+=("${entry%%:*}"); done
fi

for hostname in "${TARGETS[@]}"; do
    [[ -v "NODE_IP[${hostname}]" ]] || { echo "ERROR: unknown node ${hostname}" >&2; exit 1; }
    config="${STATE_ROOT}/generated/${NODE_ROLE[${hostname}]}/${hostname}.yaml"
    [[ -f "${config}" ]] || { echo "ERROR: missing ${config}; run make generate" >&2; exit 1; }
done

for hostname in "${TARGETS[@]}"; do
    config="${STATE_ROOT}/generated/${NODE_ROLE[${hostname}]}/${hostname}.yaml"
    echo "Applying ${hostname} (${NODE_IP[${hostname}]})"
    talosctl apply-config --talosconfig "${TALOSCONFIG}" \
        --nodes "${NODE_IP[${hostname}]}" --file "${config}" "${INSECURE_ARGS[@]}"
done
