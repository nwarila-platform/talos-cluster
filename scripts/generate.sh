#!/usr/bin/env bash
# =============================================================================
# generate.sh — Generate Talos machine configs from patches + secrets
#
# Generates base configs with talosctl gen config, then applies per-node
# patches using talosctl machineconfig patch. Secrets are created on first
# run and reused on subsequent runs.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${ROOT_DIR}/cluster/config.env"

S3_DIR="${ROOT_DIR}/${LOCAL_S3_DIR}"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "${TEMP_DIR}"' EXIT

# ---------------------------------------------------------------------------
# Helper: set static hostname in a Talos 1.12+ multi-document config
# Replaces the HostnameConfig "auto: stable" with "hostname: <name>"
# ---------------------------------------------------------------------------
set_hostname() {
    local config_file="$1"
    local desired_hostname="$2"

    # Fail closed: sed -i exits 0 on zero substitutions, so without these
    # guards a future Talos release that renames/indents the HostnameConfig
    # field would silently produce auto-hostname configs.
    if ! grep -q '^auto: stable' "${config_file}"; then
        echo "ERROR: set_hostname expected '^auto: stable' in ${config_file}" >&2
        echo "       Talos HostnameConfig format may have changed; refusing to" >&2
        echo "       generate a config with the wrong hostname." >&2
        exit 1
    fi
    sed -i "s/^auto: stable.*$/hostname: ${desired_hostname}/" "${config_file}"
    if ! grep -q "^hostname: ${desired_hostname}$" "${config_file}"; then
        echo "ERROR: set_hostname failed to install 'hostname: ${desired_hostname}' in ${config_file}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Create directory structure
# ---------------------------------------------------------------------------
mkdir -p "${S3_DIR}/secrets"
mkdir -p "${S3_DIR}/configs"
mkdir -p "${S3_DIR}/generated/controlplane"
mkdir -p "${S3_DIR}/generated/worker"

# ---------------------------------------------------------------------------
# Generate secrets (once)
# ---------------------------------------------------------------------------
if [[ ! -f "${S3_DIR}/secrets/secrets.yaml" ]]; then
    echo "==> Generating Talos secrets bundle..."
    talosctl gen secrets -o "${S3_DIR}/secrets/secrets.yaml"
    echo "    Created ${S3_DIR}/secrets/secrets.yaml"
else
    echo "==> Secrets bundle already exists, reusing."
fi

# ---------------------------------------------------------------------------
# Generate base configs
# ---------------------------------------------------------------------------
echo "==> Generating base machine configs..."
echo "    Cluster:    ${CLUSTER_NAME}"
echo "    Endpoint:   ${CLUSTER_ENDPOINT}"
echo "    Talos:      ${TALOS_VERSION}"
echo "    Kubernetes: ${KUBERNETES_VERSION}"

talosctl gen config "${CLUSTER_NAME}" "${CLUSTER_ENDPOINT}" \
    --with-secrets "${S3_DIR}/secrets/secrets.yaml" \
    --kubernetes-version "${KUBERNETES_VERSION}" \
    --install-image "${TALOS_INSTALL_IMAGE}" \
    --config-patch @"${ROOT_DIR}/cluster/patches/common.yaml" \
    --config-patch-control-plane @"${ROOT_DIR}/cluster/patches/controlplane.yaml" \
    --config-patch-worker @"${ROOT_DIR}/cluster/patches/worker.yaml" \
    --output "${TEMP_DIR}/" \
    --force

# Copy talosconfig
cp "${TEMP_DIR}/talosconfig" "${S3_DIR}/configs/talosconfig"
echo "    Talosconfig saved."

# ---------------------------------------------------------------------------
# Patch per-node control plane configs
# ---------------------------------------------------------------------------
VOLUMES_PATCH="${ROOT_DIR}/cluster/patches/volumes.yaml"

# Append the multi-doc volumes patch (VolumeConfig + UserVolumeConfig).
# `talosctl machineconfig patch` only strategically-merges the v1alpha1 main
# doc; new top-level kinds like VolumeConfig must be appended after.
append_volumes() {
    local target="$1"
    if [[ ! -f "${VOLUMES_PATCH}" ]]; then
        echo "ERROR: ${VOLUMES_PATCH} missing" >&2
        exit 1
    fi
    cat "${VOLUMES_PATCH}" >> "${target}"
}

echo "==> Generating per-node control plane configs..."
for entry in ${CP_NODES}; do
    node_name="${entry%%:*}"
    ip="${entry##*:}"
    node_hostname=$(echo "${node_name}" | tr '[:upper:]' '[:lower:]')
    echo "    ${node_name} (${ip}) → hostname: ${node_hostname}"

    talosctl machineconfig patch "${TEMP_DIR}/controlplane.yaml" \
        --patch @"${ROOT_DIR}/cluster/patches/${node_name}.yaml" \
        --output "${S3_DIR}/generated/controlplane/${node_name}.yaml"

    set_hostname "${S3_DIR}/generated/controlplane/${node_name}.yaml" "${node_hostname}"
    append_volumes "${S3_DIR}/generated/controlplane/${node_name}.yaml"
done

# ---------------------------------------------------------------------------
# Patch per-node worker configs
# ---------------------------------------------------------------------------
echo "==> Generating per-node worker configs..."
for entry in ${WORKER_NODES}; do
    node_name="${entry%%:*}"
    ip="${entry##*:}"
    node_hostname=$(echo "${node_name}" | tr '[:upper:]' '[:lower:]')
    echo "    ${node_name} (${ip}) → hostname: ${node_hostname}"

    talosctl machineconfig patch "${TEMP_DIR}/worker.yaml" \
        --patch @"${ROOT_DIR}/cluster/patches/${node_name}.yaml" \
        --output "${S3_DIR}/generated/worker/${node_name}.yaml"

    set_hostname "${S3_DIR}/generated/worker/${node_name}.yaml" "${node_hostname}"
    append_volumes "${S3_DIR}/generated/worker/${node_name}.yaml"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "==> Generation complete!"
echo "    Secrets:        ${S3_DIR}/secrets/secrets.yaml"
echo "    Talosconfig:    ${S3_DIR}/configs/talosconfig"
echo "    CP configs:     ${S3_DIR}/generated/controlplane/"
echo "    Worker configs: ${S3_DIR}/generated/worker/"
echo ""
echo "    Next steps:"
echo "      make validate       # Validate generated configs"
echo "      make apply-insecure # Apply to nodes (first time)"
echo "      make apply          # Apply to nodes (after PKI)"
