#!/usr/bin/env bash
# =============================================================================
# check-live-vault-config-invariants.sh - Ensure live Vault stays hardened.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIVE_VAULT_BASE="clusters/talos-cluster/apps/vault/base"
FORBIDDEN_DIRECTIVE="enable_unauthenticated_access"

cd "${ROOT_DIR}"

rendered="$(mktemp)"
trap 'rm -f "${rendered}"' EXIT

kubectl kustomize "${LIVE_VAULT_BASE}" >"${rendered}"

python3 - "${rendered}" "${FORBIDDEN_DIRECTIVE}" <<'PY'
import sys

import yaml

rendered_path = sys.argv[1]
forbidden = sys.argv[2]

with open(rendered_path, encoding="utf-8") as handle:
    documents = list(yaml.safe_load_all(handle))

matches = []
violations = []

for document in documents:
    if not isinstance(document, dict) or document.get("kind") != "ConfigMap":
        continue

    metadata = document.get("metadata") or {}
    namespace = metadata.get("namespace", "")
    name = metadata.get("name", "")

    # Kustomize adds a content hash to generated ConfigMaps and rewrites the
    # StatefulSet reference. Match both hashed and unhashed renderings.
    if namespace != "deploy-vault" or not (name == "vault-config" or name.startswith("vault-config-")):
        continue

    matches.append(f"{namespace}/{name}")
    vault_hcl = ((document.get("data") or {}).get("vault.hcl") or "")
    if forbidden in vault_hcl:
        violations.append(f"{namespace}/{name}")

if not matches:
    print("ERROR: rendered live Vault ConfigMap was not found", file=sys.stderr)
    sys.exit(1)

if violations:
    print("ERROR: live Vault ConfigMap must not contain enable_unauthenticated_access", file=sys.stderr)
    for resource in violations:
        print(f"- {resource}", file=sys.stderr)
    sys.exit(1)

print("OK: live Vault ConfigMap omits enable_unauthenticated_access")
PY
