#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

for command in talosctl sed grep; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done

client_version="$(talosctl version --client --short | awk '/Talos v/ {print $2; exit}')"
if [[ "${client_version}" != "${TALOS_VERSION}" ]]; then
    echo "ERROR: talosctl ${TALOS_VERSION} is required; found ${client_version:-unknown}" >&2
    exit 1
fi

STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT
umask 077

mkdir -p "${STATE_ROOT}/secrets" "${STATE_ROOT}/configs"
mkdir -p "${STATE_ROOT}/generated/controlplane" "${STATE_ROOT}/generated/worker"

if [[ ! -f "${STATE_ROOT}/secrets/talos-secrets.yaml" ]]; then
    talosctl gen secrets --output-file "${STATE_ROOT}/secrets/talos-secrets.yaml"
fi

talosctl gen config "${CLUSTER_NAME}" "${CLUSTER_ENDPOINT}" \
    --with-secrets "${STATE_ROOT}/secrets/talos-secrets.yaml" \
    --kubernetes-version "${KUBERNETES_VERSION}" \
    --install-image "${TALOS_INSTALL_IMAGE}" \
    --config-patch @"${ROOT_DIR}/cluster/patches/common.yaml" \
    --config-patch-control-plane @"${ROOT_DIR}/cluster/patches/controlplane.yaml" \
    --config-patch-worker @"${ROOT_DIR}/cluster/patches/worker.yaml" \
    --output "${TEMP_DIR}" \
    --force

install -m 0600 "${TEMP_DIR}/talosconfig" "${STATE_ROOT}/configs/talosconfig"
cp_ips=(); for entry in ${CP_NODES}; do cp_ips+=("${entry##*:}"); done
talosctl --talosconfig "${STATE_ROOT}/configs/talosconfig" config endpoint "${cp_ips[@]}"

set_hostname() {
    local config_file="$1"
    local hostname="$2"

    grep -q '^auto: stable' "${config_file}" || {
        echo "ERROR: Talos HostnameConfig format changed in ${config_file}" >&2
        exit 1
    }
    sed -i "s/^auto: stable.*$/hostname: ${hostname}/" "${config_file}"
    grep -q "^hostname: ${hostname}$" "${config_file}"
}

render_role() {
    local role="$1"
    local inventory="$2"
    local base_config="$3"
    local volume_patch="$4"
    local entry hostname ip output node_patch

    for entry in ${inventory}; do
        hostname="${entry%%:*}"
        ip="${entry##*:}"
        output="${STATE_ROOT}/generated/${role}/${hostname}.yaml"
        node_patch="${TEMP_DIR}/${hostname}.yaml"
        {
            printf 'machine:\n'
            printf '  install:\n'
            printf '    disk: %s\n' "${INSTALL_DISK}"
            printf '  network:\n'
            printf '    interfaces:\n'
            printf '      - deviceSelector:\n'
            printf '          busPath: "%s"\n' "${NIC_BUS_PATH}"
            printf '        dhcp: false\n'
            printf '        addresses: [%s/%s]\n' "${ip}" "${CLUSTER_NETMASK}"
            printf '        routes:\n'
            printf '          - network: 0.0.0.0/0\n'
            printf '            gateway: %s\n' "${CLUSTER_GATEWAY}"
            if [[ "${role}" == "controlplane" ]]; then
                printf '        vip:\n'
                printf '          ip: %s\n' "${CLUSTER_VIP}"
            fi
        } > "${node_patch}"
        talosctl machineconfig patch "${base_config}" \
            --patch @"${node_patch}" \
            --output "${output}"
        set_hostname "${output}" "${hostname}"
        {
            printf '\n'
            sed -n '1,$p' "${volume_patch}"
            printf '\n'
            sed -n '1,$p' "${ROOT_DIR}/cluster/patches/firewall.yaml"
        } >> "${output}"
        chmod 0600 "${output}"
    done
}

render_role controlplane "${CP_NODES}" "${TEMP_DIR}/controlplane.yaml" \
    "${ROOT_DIR}/cluster/patches/volumes-controlplane.yaml"
render_role worker "${WORKER_NODES}" "${TEMP_DIR}/worker.yaml" \
    "${ROOT_DIR}/cluster/patches/volumes-worker.yaml"

echo "Generated six machine configs under ${STATE_ROOT}/generated."
