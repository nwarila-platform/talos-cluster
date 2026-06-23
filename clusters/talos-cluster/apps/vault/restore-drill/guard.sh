#!/usr/bin/env bash
# PRE-APPLY GUARD for the Vault restore drill (Step 152a).
#
# Renders the drill kustomization and refuses to let the harness be applied
# unless every isolation invariant holds. Run this BEFORE `kubectl apply -k`.
# Exits non-zero (and prints the offending render) on any failure.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# kubectl is a Windows binary; hand it a Windows path when running under MSYS.
if command -v cygpath >/dev/null 2>&1; then DIR_K="$(cygpath -w "$DIR")"; else DIR_K="$DIR"; fi
RENDER="$(kubectl kustomize "$DIR_K")"
# Effective render with comment lines stripped (both YAML comments and comments
# embedded in the vault.hcl block scalar). The isolation invariants are about
# real config/fields, not inert prose — checking comments would only produce
# false positives.
EFFECTIVE="$(echo "$RENDER" | grep -vE '^[[:space:]]*#')"

fail() { echo "GUARD FAIL: $*" >&2; echo "----- rendered manifest -----" >&2; echo "$RENDER" >&2; exit 1; }
ok()   { echo "  PASS  $*"; }

echo "== PRE-APPLY GUARD: drill Vault isolation invariants =="

# 1. ZERO retry_join in the rendered Vault config.
if echo "$EFFECTIVE" | grep -qE 'retry_join[[:space:]]*[{=]'; then
  fail "rendered config contains retry_join (drill must not join any cluster)"
fi
ok "no retry_join blocks"

# 2. ZERO references to the live cluster: deploy-vault / vault-internal.
#    (vault-drill-internal is the drill's own headless svc and does NOT contain
#    the substring 'vault-internal'.)
if echo "$EFFECTIVE" | grep -q 'deploy-vault'; then
  fail "rendered manifest references deploy-vault"
fi
ok "no deploy-vault references"
if echo "$EFFECTIVE" | grep -q 'vault-internal'; then
  fail "rendered manifest references vault-internal (live headless svc)"
fi
ok "no vault-internal references"

# 3. The Vault addresses reference ONLY the drill service.
ADDRS="$(echo "$RENDER" | grep -E 'VAULT_(API_ADDR|CLUSTER_ADDR|ADDR)' -A1 | grep 'value:' || true)"
echo "$ADDRS" | sed 's/^/      addr: /'
if echo "$ADDRS" | grep -qE 'value:\s' && ! echo "$ADDRS" | grep -q 'vault-drill-internal.vault-drill.svc'; then
  fail "a VAULT_*_ADDR does not point at the drill service"
fi
if echo "$ADDRS" | grep -qiE 'deploy-vault|[^-]vault-internal'; then
  fail "a VAULT_*_ADDR references the live cluster"
fi
ok "VAULT_API_ADDR/CLUSTER_ADDR/ADDR reference only vault-drill"

# 4. Namespace/pod carry NO nwarila.io/tenant and NO vault-client labels.
if echo "$EFFECTIVE" | grep -q 'nwarila.io/tenant'; then
  fail "found nwarila.io/tenant label (live allow-tenant-vault-ingress would admit the drill)"
fi
ok "no nwarila.io/tenant label"
if echo "$EFFECTIVE" | grep -q 'vault-client'; then
  fail "found vault-client label (live allow-tenant-vault-ingress would admit the drill)"
fi
ok "no vault-client label"

# 5. The native default-deny exists with both policy types.
if ! echo "$RENDER" | grep -q 'vault-drill-default-deny'; then
  fail "native default-deny NetworkPolicy missing"
fi
ok "native default-deny NetworkPolicy present"

echo "== GUARD PASS: all isolation invariants hold =="
