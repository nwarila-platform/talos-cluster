#!/usr/bin/env bash
# =============================================================================
# build-maintenance-iso.sh - Build a per-node Talos maintenance ISO schematic
#
# The critical invariant is that the static IPv4 kernel cmdline pins the device
# field to eno1. An empty device field makes Linux apply the address broadly,
# including to synthetic interfaces, and can create duplicate default routes.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

NODE_DEVICE="eno1"
FACTORY_URL="${FACTORY_URL:-https://factory.talos.dev}"
TEMP_DIR=""

usage() {
    cat <<'EOF'
Usage:
  scripts/build-maintenance-iso.sh <node>
  scripts/build-maintenance-iso.sh --self-test

Builds a Talos Image Factory schematic for a SecureBoot maintenance ISO.
The generated ip= kernel argument is always pinned to eno1.
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

ip_arg_device() {
    local ip_arg="$1"
    local payload
    local -a parts

    payload="${ip_arg#ip=}"
    IFS=':' read -r -a parts <<< "${payload}"
    printf '%s\n' "${parts[5]:-}"
}

assert_pinned_ip_arg() {
    local ip_arg="$1"
    local device

    [[ "${ip_arg}" == ip=* ]] || die "kernel arg does not start with ip=: ${ip_arg}"
    device="$(ip_arg_device "${ip_arg}")"
    if [[ -z "${device}" ]]; then
        die "ip= kernel arg has an empty device field: ${ip_arg}"
    fi
    if [[ "${device}" != "${NODE_DEVICE}" ]]; then
        die "ip= kernel arg device is '${device}', expected '${NODE_DEVICE}': ${ip_arg}"
    fi
}

self_test() {
    local pinned="ip=10.69.112.70::10.69.112.1:24:w3:${NODE_DEVICE}:off"
    local empty_device="ip=10.69.112.70::10.69.112.1:24:w3::off"

    assert_pinned_ip_arg "${pinned}"
    if ( assert_pinned_ip_arg "${empty_device}" ) >/dev/null 2>&1; then
        die "self-test expected empty-device ip= arg to fail"
    fi

    echo "PASS: pinned ip= arg accepted"
    echo "PASS: empty-device ip= arg refused"
}

lookup_node_ip() {
    local node="$1"
    local entry
    local -a inventory

    read -r -a inventory <<< "${CP_NODES} ${WORKER_NODES}"
    for entry in "${inventory[@]}"; do
        if [[ "${entry%%:*}" == "${node}" ]]; then
            printf '%s\n' "${entry##*:}"
            return 0
        fi
    done

    return 1
}

verify_patch_network_matches_config() {
    local node="$1"
    local node_ip="$2"
    local patch="${ROOT_DIR}/cluster/patches/${node}.yaml"
    local node_ip_re="${node_ip//./\\.}"
    local gateway_re="${CLUSTER_GATEWAY//./\\.}"

    [[ -f "${patch}" ]] || die "node patch not found: ${patch}"
    grep -Eq "^[[:space:]]+-[[:space:]]+${node_ip_re}/${CLUSTER_NETMASK}[[:space:]]*$" "${patch}" \
        || die "${patch} does not declare ${node_ip}/${CLUSTER_NETMASK}"
    grep -Eq "^[[:space:]]+gateway:[[:space:]]+${gateway_re}[[:space:]]*$" "${patch}" \
        || die "${patch} does not declare gateway ${CLUSTER_GATEWAY}"
}

write_maintenance_schematic() {
    local base_schematic="$1"
    local output_schematic="$2"
    local ip_arg="$3"

    if grep -Eq '^[[:space:]]+extraKernelArgs:|^extraKernelArgs:' "${base_schematic}"; then
        die "base schematic already contains extraKernelArgs; refusing to merge blindly"
    fi

    if grep -Eq '^customization:[[:space:]]*$' "${base_schematic}"; then
        awk -v ip_arg="${ip_arg}" '
            /^customization:[[:space:]]*$/ {
                print
                print "  extraKernelArgs:"
                print "    - \"" ip_arg "\""
                print "    - \"talos.halt_if_installed=0\""
                next
            }
            { print }
        ' "${base_schematic}" > "${output_schematic}"
    else
        {
            echo "customization:"
            echo "  extraKernelArgs:"
            echo "    - \"${ip_arg}\""
            echo "    - \"talos.halt_if_installed=0\""
            cat "${base_schematic}"
        } > "${output_schematic}"
    fi
}

extract_schematic_id() {
    local response="$1"
    local id

    id="$(printf '%s\n' "${response}" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    if [[ -z "${id}" ]]; then
        id="$(printf '%s\n' "${response}" | tr -d '[:space:]')"
    fi

    [[ "${id}" =~ ^[0-9a-f]{64}$ ]] || die "could not parse schematic id from Factory response: ${response}"
    printf '%s\n' "${id}"
}

build_iso() {
    local node="$1"
    local node_ip
    local ip_arg
    local base_schematic
    local maintenance_schematic
    local response
    local schematic_id

    # shellcheck source=../cluster/config.env
    source "${ROOT_DIR}/cluster/config.env"

    node_ip="$(lookup_node_ip "${node}")" || die "unknown node '${node}' (expected one of CP_NODES/WORKER_NODES)"
    [[ -n "${TALOS_SCHEMATIC_ID:-}" ]] || die "TALOS_SCHEMATIC_ID missing from cluster/config.env"
    [[ -n "${TALOS_VERSION:-}" ]] || die "TALOS_VERSION missing from cluster/config.env"
    [[ -n "${CLUSTER_GATEWAY:-}" ]] || die "CLUSTER_GATEWAY missing from cluster/config.env"
    [[ -n "${CLUSTER_NETMASK:-}" ]] || die "CLUSTER_NETMASK missing from cluster/config.env"

    verify_patch_network_matches_config "${node}" "${node_ip}"

    ip_arg="ip=${node_ip}::${CLUSTER_GATEWAY}:${CLUSTER_NETMASK}:${node}:${NODE_DEVICE}:off"
    assert_pinned_ip_arg "${ip_arg}"

    TEMP_DIR="$(mktemp -d)"
    trap 'rm -rf "${TEMP_DIR:-}"' EXIT
    base_schematic="${TEMP_DIR}/base-schematic.yaml"
    maintenance_schematic="${TEMP_DIR}/maintenance-schematic.yaml"

    echo "==> Fetching base schematic ${TALOS_SCHEMATIC_ID}"
    curl --proto '=https' --tlsv1.2 -fsSL \
        "${FACTORY_URL}/schematics/${TALOS_SCHEMATIC_ID}" \
        -o "${base_schematic}"

    echo "==> Writing maintenance schematic"
    write_maintenance_schematic "${base_schematic}" "${maintenance_schematic}" "${ip_arg}"

    echo "==> Posting maintenance schematic"
    response="$(curl --proto '=https' --tlsv1.2 -fsSL \
        -X POST \
        --data-binary @"${maintenance_schematic}" \
        "${FACTORY_URL}/schematics")"
    schematic_id="$(extract_schematic_id "${response}")"

    echo ""
    echo "Node: ${node}"
    echo "IP arg: ${ip_arg}"
    echo "Installer image: factory.talos.dev/installer-secureboot/${schematic_id}:${TALOS_VERSION}"
    echo "Maintenance ISO URL: ${FACTORY_URL}/image/${schematic_id}/${TALOS_VERSION}/metal-amd64-secureboot.iso"
}

main() {
    if [[ "${1:-}" == "--self-test" ]]; then
        self_test
        return 0
    fi

    if [[ $# -ne 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        usage
        [[ $# -eq 1 && ( "${1:-}" == "-h" || "${1:-}" == "--help" ) ]] && return 0
        return 2
    fi

    build_iso "$1"
}

main "$@"
