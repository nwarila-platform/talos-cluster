# Vault Generate-Root Break-Glass

This runbook drafts the owner-gated S0 ceremony for proving that a restored
Vault snapshot can be recovered from the real escrowed recovery-key quorum
without relying on any preexisting Vault token.

Status: draft for independent review. Do not execute until the owner approves
the exact snapshot, scratch target, AWS break-glass session, and rollback plan.

## Scope

S0 is a scratch-only proof. It performs NO live Vault mutation.

S0 proves four things, in this order:

1. A real latest live Vault snapshot can be restored into isolated scratch.
2. The real escrowed recovery-key quorum can complete token-less
   `sys/generate-root` against that restored scratch Vault.
3. The generated root token can read `sys/mounts` plus a reviewer-confirmed
   known-populated path from the restored snapshot, then is revoked during the
   same run.
4. All scratch state is wiped afterward.

Do not run this against the production Vault service for generate-root or token
revocation during S0. Do not print, paste into chat, commit, or persist
recovery-key shares, root tokens, generated root tokens, OTPs, or decoded token
material.

The ADR-0009 initial-root-token revocation is a separate owner-executed live
mutation in the appendix. It is deliberately outside S0 because live Vault keeps
`generate-root` token-gated; revoking the last root-capable live credential
without a working non-root admin path can lock out live administration.

## Repository Facts To Reconfirm

ADR-0009 records the real init as `recovery_shares=5`,
`recovery_threshold=3`, with SSM escrow at
`/nwarila-platform/vault/talos-cluster/init-material`. The same ADR says
`recovery_pgp_keys` was optional, and its as-built status only records
"recovery 5/3"; it does not prove whether the escrowed shares are PGP-wrapped.

ADR-0009 also documents the maintainer model as one SSM blob plus one offline
file. Before the ceremony, the owner must verify that the offline copy exists
and is decryptable without AWS. If that cannot be proven, stop: S0 would not
establish the floor against AWS-account compromise.

The recovery Vault must include:

```hcl
enable_unauthenticated_access = ["generate-root"]
```

Keep this directive out of live Vault. It belongs only in isolated scratch or a
replacement recovery StatefulSet used for a specific DR run.

## Hard Stops

Stop before touching live or scratch if any item is false:

- Independent review of this runbook and the exact restore harness is complete.
- The latest live snapshot source and scratch target are named in the review.
- `clusters/talos-cluster/apps/vault/restore-drill/guard.sh` passes before
  any scratch apply.
- The scratch network proof blocks live Vault DNS and TCP while preserving AWS
  KMS reachability.
- The ceremony environment has the `vault` CLI available; this runbook uses it
  for OTP generation and Vault-native generated-root decode.
- `SHARES_PGP_WRAPPED` is known for the real escrowed shares.
- The offline recovery-key copy has been owner-verified outside AWS.
- The restored-secret proof path is confirmed present in the selected snapshot.
- S0 contains no live Vault mutation. The ADR-0009 initial-root-token revocation
  remains a separate appendix procedure.
- Terminal history, shell tracing, screen recording, and transcript logging are
  disabled for all secret-handling commands.

## Classify Escrowed Shares

The repository is not definitive about PGP wrapping. The owner must run this
check from a private shell with the MFA-gated `vault-break-glass` AWS identity.
It fetches one share through a pipe, never echoes it, and prints only
`pgp_wrapped=true` or `pgp_wrapped=false`.

The `jq` extractor below accepts the known bundle shapes
`recovery_keys_b64`, `recovery_keys`, `keys_base64`, and `keys`. The owner must
confirm the actual SSM bundle schema before the ceremony. A key-name miss should
make `jq -e` fail loudly; adjust the selector to the real escrow schema during
review instead of weakening the check. The `.root_token` selector in the
separate revoke appendix has the same schema caveat.

```bash
set -euo pipefail
set +x
set +o history 2>/dev/null || true

export AWS_PROFILE=vault-break-glass
PARAM_NAME="/nwarila-platform/vault/talos-cluster/init-material"

aws ssm get-parameter \
  --name "$PARAM_NAME" \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text |
jq -er '
  if type == "string" then fromjson else . end
  | (.recovery_keys_b64 // .recovery_keys // .keys_base64 // .keys // empty) as $keys
  | if ($keys | type) == "array" then $keys[0] else $keys end
' |
python3 -c '
import base64
import binascii
import sys

s = sys.stdin.read().strip()
pgp = False
if s.startswith("-----BEGIN PGP MESSAGE-----"):
    pgp = True
else:
    try:
        decoded = base64.b64decode(s, validate=True)
    except binascii.Error:
        decoded = b""
    if len(decoded) > 64 and decoded[0] & 0x80:
        first = decoded[0]
        tag = (first & 0x3F) if (first & 0x40) else ((first >> 2) & 0x0F)
        pgp = tag in {1, 3, 9, 18}

print("pgp_wrapped=" + ("true" if pgp else "false"))
'

unset PARAM_NAME
```

If `pgp_wrapped=false`, the recovery-key shares are raw-submittable to
`sys/generate-root/update`.

If `pgp_wrapped=true`, stop unless the owner can decrypt the quorum outside AWS
without persisting plaintext shares. Each submitted value must be the decrypted
raw recovery-key share, typed or pasted into the silent prompt below. Do not
import PGP private keys into the cluster, the scratch namespace, AWS, CI, or any
long-lived operator workstation profile. If outside-AWS decryption is not
available, the automated token-less recovery design is not currently viable.

## Restore Real Snapshot Into Scratch

Run this from the repository root. Use the reviewed restore harness for the
current branch; do not substitute ad hoc live Vault commands during the
ceremony.

```bash
export MSYS_NO_PATHCONV=1
export KUBECONFIG="${KUBECONFIG:-.s3/configs/kubeconfig}"
export VAULT_DRILL_WORK_DIR="${VAULT_DRILL_WORK_DIR:-C:/tmp/vault-drill-s0}"

cd clusters/talos-cluster/apps/vault/restore-drill
bash guard.sh
```

The reviewed restore harness must then:

1. Stand up only the isolated `vault-drill` scratch workload.
2. Copy only the runtime material needed for KMS auto-unseal.
3. Capture or select the owner-approved latest live snapshot.
4. Restore that snapshot into the scratch Vault PVC.
5. Confirm scratch Vault is initialized, auto-unsealed, active, and isolated.
6. Confirm live Vault pods remain healthy and are not modified.

Record the snapshot identifier, scratch namespace, scratch service, Vault
version, and guard output in the ceremony notes. Do not record secrets.

## Generate-Root Endpoint Gate

Positive gate: against restored scratch with the recovery directive present,
an unauthenticated `generate-root` attempt must return HTTP 200 and a nonce.

Negative gate: do not call live Vault. For S0, use the already-reviewed
Step-156/ADR-0019 evidence that Vault v2.0.1 returns HTTP 403 for token-less
`generate-root` without the directive, and that the isolated `vault-drill`
scratch path succeeds only when the recovery config includes
`enable_unauthenticated_access = ["generate-root"]`. If reviewers require a
fresh negative control, stand up a second isolated scratch Vault with a reviewed
`vault-drill.hcl` variant that omits the directive and point a loopback
`CONTROL_VAULT_ADDR` at that scratch service. Never use live production Vault
for the negative API call.

For scratch:

```bash
kubectl -n vault-drill port-forward svc/vault-drill 18200:8200 >/tmp/vault-s0-pf.log 2>&1 &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true' EXIT

VAULT_ADDR="http://127.0.0.1:18200"
OTP="$(vault operator generate-root -generate-otp)"

ATTEMPT_RESPONSE="$(
  printf '%s\n' "$OTP" |
  python3 -c 'import json,sys; print(json.dumps({"otp": sys.stdin.read().strip()}, separators=(",", ":")))' |
  curl -sS --request PUT \
    --header 'Content-Type: application/json' \
    --data-binary @- \
    --write-out '\n%{http_code}' \
    "$VAULT_ADDR/v1/sys/generate-root/attempt"
)"
ATTEMPT_STATUS="${ATTEMPT_RESPONSE##*$'\n'}"
ATTEMPT_JSON="${ATTEMPT_RESPONSE%$'\n'*}"
test "$ATTEMPT_STATUS" = "200"
NONCE="$(printf '%s' "$ATTEMPT_JSON" | jq -er '.nonce')"
REQUIRED="$(printf '%s' "$ATTEMPT_JSON" | jq -er '.required')"
printf 'generate-root_started=true required=%s\n' "$REQUIRED"
```


## Complete Generate-Root From The Real Quorum

Submit exactly the threshold number of real recovery-key shares. For the
ADR-0009 as-built threshold, that is three shares. The prompt is silent. If
shares are PGP-wrapped, type or paste the outside-AWS decrypted raw share, not
the PGP message.

```bash
submit_recovery_share() {
  local share response complete progress required
  IFS= read -r -s -p "Recovery share: " share
  printf '\n'

  response="$(
    { printf '%s\n' "$share"; printf '%s\n' "$NONCE"; } |
    python3 -c '
import json
import sys
key = sys.stdin.readline().rstrip("\n")
nonce = sys.stdin.readline().rstrip("\n")
print(json.dumps({"key": key, "nonce": nonce}, separators=(",", ":")))
' |
    curl -sS --request PUT \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "$VAULT_ADDR/v1/sys/generate-root/update"
  )"
  unset share

  complete="$(printf '%s' "$response" | jq -r '.complete')"
  progress="$(printf '%s' "$response" | jq -r '.progress')"
  required="$(printf '%s' "$response" | jq -r '.required')"
  printf 'generate-root_progress=%s/%s complete=%s\n' "$progress" "$required" "$complete"

  if [ "$complete" = "true" ]; then
    ENCODED_ROOT_TOKEN="$(printf '%s' "$response" | jq -er '.encoded_root_token // .encoded_token')"
  fi
}

for _ in $(seq 1 "$REQUIRED"); do
  submit_recovery_share
done

test -n "${ENCODED_ROOT_TOKEN:-}"

# Vault v2.0.1 generates base62 OTPs by default. Do not manually base64/XOR
# decode the generated-root output; let Vault handle the OTP encoding.
ROOT_TOKEN="$(vault operator generate-root -decode="$ENCODED_ROOT_TOKEN" -otp="$OTP")"
test -n "${ROOT_TOKEN:-}"
```

## Prove And Revoke Generated Root

Use the generated root only against the restored scratch Vault. Do not use it
against live Vault.

```bash
vault_root_json() {
  local method="$1"
  local path="$2"
  {
    printf 'request = "%s"\n' "$method"
    printf 'url = "%s/v1/%s"\n' "$VAULT_ADDR" "$path"
    printf 'header = "X-Vault-Token: %s"\n' "$ROOT_TOKEN"
  } | curl -fsS --config -
}

vault_root_status() {
  local method="$1"
  local path="$2"
  {
    printf 'request = "%s"\n' "$method"
    printf 'url = "%s/v1/%s"\n' "$VAULT_ADDR" "$path"
    printf 'header = "X-Vault-Token: %s"\n' "$ROOT_TOKEN"
  } | curl -sS --output /dev/null --write-out '%{http_code}' --config -
}

vault_root_json GET sys/mounts | jq -e 'has("sys/") and has("identity/")' >/dev/null

# This default is a real platform path used by the restore-validation evidence.
# The review must confirm it exists in the selected snapshot, or set an
# owner-approved guaranteed-present restored path for this ceremony.
RESTORED_SECRET_PROOF_PATH="${RESTORED_SECRET_PROOF_PATH:-secret/data/platform/org-pull/hwg/gitops-source-auth}"
RESTORED_SECRET_STATUS="$(vault_root_status GET "$RESTORED_SECRET_PROOF_PATH")"
test "$RESTORED_SECRET_STATUS" = "200"
printf 'generated_root_proof_ok=true\n'

REVOKE_STATUS="$(vault_root_status POST auth/token/revoke-self)"
test "$REVOKE_STATUS" = "204"
printf 'generated_root_revoked=true\n'

unset ROOT_TOKEN ENCODED_ROOT_TOKEN OTP ATTEMPT_JSON ATTEMPT_RESPONSE
unset RESTORED_SECRET_PROOF_PATH RESTORED_SECRET_STATUS
```


## Wipe Scratch And Verify Empty Isolation

After the generated root has been revoked, wipe the scratch. Keep no restored
PVC, snapshot, init JSON, OTP, or generated token material.

```bash
kubectl delete pod -n vault-drill netcheck --ignore-not-found --wait=true
kubectl -n vault-drill delete sts vault-drill --ignore-not-found --wait=true
kubectl -n vault-drill delete pvc data-vault-drill-0 --ignore-not-found --wait=true
kubectl delete ns vault-drill --ignore-not-found --wait=true
rm -rf "$VAULT_DRILL_WORK_DIR"
```

To prove the scratch name is safe to reuse, re-run the empty drill once, verify
guarded isolation and default mounts only, then delete it again:

```bash
cd clusters/talos-cluster/apps/vault/restore-drill
FINAL_INIT_OUT="/c/tmp/vault-drill-s0-final-init.json" PF_PORT=18202 bash drill-run.sh
rm -f /c/tmp/vault-drill-s0-final-init.json
kubectl delete ns vault-drill --ignore-not-found --wait=true
```

Final pass criteria:

- Restored scratch reached `generate-root_started=true` with HTTP 200 and a
  nonce.
- Step-156/ADR-0019 negative-control evidence was accepted, or a separately
  reviewed isolated no-directive scratch returned HTTP 403 for unauthenticated
  `generate-root`.
- Generated root read `sys/mounts` and a reviewer-confirmed known-populated
  path from the restored snapshot without printing the secret value.
- Generated root was revoked in the same run.
- Scratch namespace, PVC, restored snapshot file, transient init JSON, OTP, and
  decoded token material were removed.
- Live Vault pods stayed healthy and live base config still omits
  `enable_unauthenticated_access`.
- S0 performed no live Vault mutation. The ADR-0009 initial-root-token revoke,
  if still needed, remains a separate owner-gated appendix procedure.

## Appendix: Revoke The ADR-0009 Initial Root Token (Separate Gated Step)

This appendix is not part of S0. It is a separate owner-executed live mutation
for the ADR-0009 follow-up after the scratch proof is accepted.

Hard precondition: do not read the escrowed root token or call live
`auth/token/revoke-self` unless all of these are true:

1. The ADR-0009 orphan least-privilege live admin path exists and authenticates
   successfully now.
2. That live admin credential is confirmed non-root, and it can perform an
   owner-approved harmless admin read such as `sys/mounts`.
3. Live break-glass recovery is accepted as a full restore into a recovery
   config carrying `enable_unauthenticated_access = ["generate-root"]`. Live
   Vault intentionally omits that directive, so revoking the last root-capable
   live credential without a working alternate admin can lock out live
   administration.
4. The owner has approved this live mutation separately from S0.
5. The actual SSM bundle schema has been confirmed; the `.root_token` selector
   below must match the real escrow field and fail closed if it does not.

Keep the live Vault connection on a loopback `kubectl port-forward`. A 204 means
the initial root token was revoked. A 403 from `revoke-self` means the token was
already revoked or otherwise invalid, which is expected-good for this follow-up:
stop, record that fact, and do not retry with root material in memory.

```bash
set +x
set +o history 2>/dev/null || true

export AWS_PROFILE=vault-break-glass
PARAM_NAME="/nwarila-platform/vault/talos-cluster/init-material"
ADMIN_PROOF_PATH="${ADMIN_PROOF_PATH:-sys/mounts}"

kubectl -n deploy-vault port-forward svc/vault 18201:8200 >/tmp/vault-live-revoke-pf.log 2>&1 &
LIVE_PF_PID=$!
trap 'kill "$LIVE_PF_PID" 2>/dev/null || true' EXIT
LIVE_VAULT_ADDR="https://127.0.0.1:18201"

IFS= read -r -s -p "Live non-root admin token: " LIVE_ADMIN_TOKEN
printf '\n'

ADMIN_NON_ROOT="$(
  {
    printf 'request = "GET"\n'
    printf 'url = "%s/v1/auth/token/lookup-self"\n' "$LIVE_VAULT_ADDR"
    printf 'header = "X-Vault-Token: %s"\n' "$LIVE_ADMIN_TOKEN"
    printf 'insecure = true\n'
  } | curl -fsS --config - |
  jq -er '((.data.policies // []) | index("root")) == null'
)"
test "$ADMIN_NON_ROOT" = "true"

ADMIN_PROOF_STATUS="$(
  {
    printf 'request = "GET"\n'
    printf 'url = "%s/v1/%s"\n' "$LIVE_VAULT_ADDR" "$ADMIN_PROOF_PATH"
    printf 'header = "X-Vault-Token: %s"\n' "$LIVE_ADMIN_TOKEN"
    printf 'insecure = true\n'
  } | curl -sS --output /dev/null --write-out '%{http_code}' --config -
)"
test "$ADMIN_PROOF_STATUS" = "200"
printf 'live_non_root_admin_continuity_ok=true\n'
unset LIVE_ADMIN_TOKEN ADMIN_NON_ROOT ADMIN_PROOF_STATUS ADMIN_PROOF_PATH

INITIAL_REVOKE_STATUS="$(
  aws ssm get-parameter \
    --name "$PARAM_NAME" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text |
  jq -er 'if type == "string" then fromjson else . end | .root_token' |
  {
    IFS= read -r initial_root_token
    {
      printf 'request = "POST"\n'
      printf 'url = "%s/v1/auth/token/revoke-self"\n' "$LIVE_VAULT_ADDR"
      printf 'header = "X-Vault-Token: %s"\n' "$initial_root_token"
      printf 'insecure = true\n'
    } | curl -sS --output /dev/null --write-out '%{http_code}' --config -
    unset initial_root_token
  }
)"

case "$INITIAL_REVOKE_STATUS" in
  204)
    printf 'adr_0009_initial_root_revoked=true\n'
    ;;
  403)
    printf 'adr_0009_initial_root_already_revoked=true\n'
    ;;
  *)
    printf 'ERROR: unexpected initial-root revoke status=%s\n' "$INITIAL_REVOKE_STATUS" >&2
    exit 1
    ;;
esac

unset PARAM_NAME INITIAL_REVOKE_STATUS LIVE_VAULT_ADDR
kill "$LIVE_PF_PID" 2>/dev/null || true
trap - EXIT
```

The `insecure = true` line is acceptable only for this loopback port-forward
where Kubernetes owns the hop to the service and the URL hostname cannot match
the live service certificate. Do not use it against a routable Vault endpoint.
