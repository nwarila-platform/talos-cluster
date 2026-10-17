#!/usr/bin/env bash
# Installs what make validate and make selftest need on a plain Ubuntu 24.04 image (the GitLab
# merge-request job, .gitlab-ci.yml): distribution packages from apt, and the pinned tools from
# cluster/config.env into /usr/local/bin, each checked against its publisher's checksum file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl git jq make openssl python3 python3-jsonschema python3-yaml shellcheck unzip yamllint >/dev/null

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
cd "${work}"
fetch() { curl --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"; }

# talosctl
fetch "https://github.com/siderolabs/talos/releases/download/${TALOS_VERSION}/talosctl-linux-amd64" talosctl-linux-amd64
fetch "https://github.com/siderolabs/talos/releases/download/${TALOS_VERSION}/sha256sum.txt" talos-sums
grep '  talosctl-linux-amd64$' talos-sums | sha256sum -c -
install -m 0755 talosctl-linux-amd64 /usr/local/bin/talosctl

# kubectl, at the cluster's Kubernetes version
fetch "https://dl.k8s.io/release/${KUBERNETES_VERSION}/bin/linux/amd64/kubectl" kubectl
fetch "https://dl.k8s.io/release/${KUBERNETES_VERSION}/bin/linux/amd64/kubectl.sha256" kubectl.sha256
printf '%s  kubectl\n' "$(cat kubectl.sha256)" | sha256sum -c -
install -m 0755 kubectl /usr/local/bin/kubectl

# helm
fetch "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" helm.tar.gz
fetch "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz.sha256sum" helm.sha256sum
printf '%s  helm.tar.gz\n' "$(awk '{print $1}' helm.sha256sum)" | sha256sum -c -
tar -xzf helm.tar.gz linux-amd64/helm
install -m 0755 linux-amd64/helm /usr/local/bin/helm

# terraform and vault (HashiCorp releases)
for tool in "terraform:${TERRAFORM_VERSION#v}" "vault:${VAULT_CLI_VERSION#v}"; do
    name="${tool%%:*}" version="${tool#*:}"
    archive="${name}_${version}_linux_amd64.zip"
    fetch "https://releases.hashicorp.com/${name}/${version}/${archive}" "${archive}"
    fetch "https://releases.hashicorp.com/${name}/${version}/${name}_${version}_SHA256SUMS" "${name}-sums"
    grep "  ${archive}$" "${name}-sums" | sha256sum -c -
    unzip -o -q "${archive}" "${name}"
    install -m 0755 "${name}" "/usr/local/bin/${name}"
done

# actionlint
archive="actionlint_${ACTIONLINT_VERSION#v}_linux_amd64.tar.gz"
fetch "https://github.com/rhysd/actionlint/releases/download/${ACTIONLINT_VERSION}/${archive}" "${archive}"
fetch "https://github.com/rhysd/actionlint/releases/download/${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION#v}_checksums.txt" actionlint-sums
grep "  ${archive}$" actionlint-sums | sha256sum -c -
tar -xzf "${archive}" actionlint
install -m 0755 actionlint /usr/local/bin/actionlint

echo "Tools installed: talosctl ${TALOS_VERSION}, kubectl ${KUBERNETES_VERSION}, helm ${HELM_VERSION}, terraform ${TERRAFORM_VERSION}, vault ${VAULT_CLI_VERSION}, actionlint ${ACTIONLINT_VERSION}."
