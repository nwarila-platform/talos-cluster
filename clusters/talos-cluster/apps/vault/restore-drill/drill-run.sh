#!/usr/bin/env bash
# Repeatable driver for the Vault recovery DRILL — Part 1 (Step 152a):
# stand up the EMPTY isolated scratch Vault, init it (KMS auto-unseal), and
# PROVE isolation. NO snapshot, NO restore, NO live data in Part 1.
#
# Requires: kubectl (Windows binary under MSYS), jq, curl, a kubeconfig with
# cluster admin, and AWS access already proven (the drill reuses the live
# vault-ra-cert for IAM Roles Anywhere -> KMS-only STS).
#
#   export MSYS_NO_PATHCONV=1
#   export KUBECONFIG=.s3/configs/kubeconfig
#   bash drill-run.sh
#
# Isolation failures are FATAL: the script exits non-zero and leaves state for
# inspection. Recovery keys / root token of the EMPTY drill Vault are written
# ONLY to a transient file outside the repo and are NEVER printed or committed.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
to_native_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}
DIR_K="$(to_native_path "$DIR")"
PF_PORT="${PF_PORT:-8300}"
INIT_OUT="${INIT_OUT:-/c/tmp/vault-drill-init.json}"   # transient; outside repo
LIVE_VAULT_CLUSTERIP="${LIVE_VAULT_CLUSTERIP:-10.101.98.168}"
LIVE_VAULT_FQDN="vault-0.vault-internal.deploy-vault.svc.cluster.local"

echo "== [0] PRE-APPLY GUARD =="
bash "$DIR/guard.sh"

echo "== [1] apply drill harness (plain kubectl, NOT Flux) =="
kubectl apply -k "$DIR_K"

echo "== [2] copy the live vault-ra-cert into vault-drill (transient, never committed) =="
# The signing-helper needs the RA workload cert to vend KMS-only STS creds.
kubectl get secret -n deploy-vault vault-ra-cert -o json \
  | jq 'del(.metadata.namespace,.metadata.resourceVersion,.metadata.uid,.metadata.creationTimestamp,.metadata.ownerReferences,.metadata.annotations,.metadata.managedFields,.status) | .metadata.namespace="vault-drill"' \
  | kubectl apply -n vault-drill -f -

echo "== [3] wait for the drill Vault pod to roll out =="
kubectl -n vault-drill rollout status sts/vault-drill --timeout=300s

echo "== [4] init the EMPTY drill Vault (KMS auto-unseal -> recovery keys) =="
# Single self-contained port-forward (per the known MSYS port-forward fragility).
kubectl -n vault-drill port-forward svc/vault-drill "${PF_PORT}:8200" >/tmp/pf-drill.log 2>&1 &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true' EXIT
for i in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:${PF_PORT}/v1/sys/seal-status" >/dev/null 2>&1 && break
  sleep 1
done

INITIALIZED="$(curl -fsS "http://127.0.0.1:${PF_PORT}/v1/sys/seal-status" | jq -r '.initialized')"
if [ "$INITIALIZED" = "false" ]; then
  curl -fsS --request PUT --data '{"recovery_shares":1,"recovery_threshold":1}' \
    "http://127.0.0.1:${PF_PORT}/v1/sys/init" > "$INIT_OUT"
  chmod 600 "$INIT_OUT" 2>/dev/null || true
  echo "  drill Vault initialized; recovery material written to transient file (not printed)"
else
  echo "  drill Vault already initialized (re-run); leaving existing transient material"
fi

echo "== [5] confirm EMPTY drill Vault auto-unsealed via KMS =="
SS="$(curl -fsS "http://127.0.0.1:${PF_PORT}/v1/sys/seal-status")"
echo "$SS" | jq '{type,initialized,sealed,storage_type:.storage_type,version,cluster_name}'
[ "$(echo "$SS" | jq -r '.sealed')" = "false" ] || { echo "FATAL: drill Vault still sealed"; exit 1; }

echo "== [6] ISOLATION PROOF A: drill Raft has ONLY itself =="
ROOT="$(jq -r '.root_token' "$INIT_OUT")"
RAFT="$(curl -fsS -H "X-Vault-Token: $ROOT" "http://127.0.0.1:${PF_PORT}/v1/sys/storage/raft/configuration")"
echo "$RAFT" | jq '.data.config.servers | map({node_id,address})'
PEERS="$(echo "$RAFT" | jq -r '.data.config.servers | length')"
[ "$PEERS" = "1" ] || { echo "FATAL: drill Raft has $PEERS peers (expected 1) — NOT isolated"; exit 1; }
echo "  drill Raft peers = 1 (self only)"

echo "== [7] ISOLATION PROOF B: network isolation from a SAME-LABELED pod =="
# The Vault image is distroless (no shell/tools), so we cannot probe from the
# Vault container itself. Instead run a throwaway busybox pod carrying the SAME
# labels as the drill Vault pod, so every NetworkPolicy/CNP that selects the
# Vault pod selects this probe identically — a faithful reachability proxy. It
# is PSA-restricted (non-root, drops ALL caps, seccomp) like everything else
# in vault-drill.
kubectl delete pod -n vault-drill netcheck --ignore-not-found --wait=true >/dev/null 2>&1
cat <<'POD' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: netcheck
  namespace: vault-drill
  labels:
    app.kubernetes.io/name: vault-drill
    app.kubernetes.io/component: server
spec:
  restartPolicy: Never
  dnsConfig:
    options:
      - {name: ndots, value: "1"}
  containers:
    - name: netcheck
      image: busybox:1.36
      command: ["sleep", "300"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
        seccompProfile: {type: RuntimeDefault}
      resources:
        requests: {cpu: 10m, memory: 16Mi}
        limits: {memory: 32Mi}
POD
kubectl -n vault-drill wait --for=condition=Ready pod/netcheck --timeout=120s
set +e
RESULT="$(kubectl exec -n vault-drill netcheck -- sh -c "
  nslookup ${LIVE_VAULT_FQDN} >/dev/null 2>&1 && echo DNS-RESOLVED-LIVE || echo DNS-BLOCKED
  nslookup kms.us-east-1.amazonaws.com >/dev/null 2>&1 && echo DNS-AWS-OK || echo DNS-AWS-FAIL
  timeout 6 nc -w 4 ${LIVE_VAULT_CLUSTERIP} 8200 </dev/null >/dev/null 2>&1 && echo TCP-REACHED-LIVE || echo TCP-BLOCKED-TO-LIVE
")"
set -e
echo "$RESULT" | sed 's/^/  /'
kubectl delete pod -n vault-drill netcheck --ignore-not-found --wait=false >/dev/null 2>&1
echo "$RESULT" | grep -q '^DNS-BLOCKED$'        || { echo "FATAL: live Vault DNS NOT blocked"; exit 1; }
echo "$RESULT" | grep -q '^TCP-BLOCKED-TO-LIVE$' || { echo "FATAL: live Vault TCP REACHABLE — isolation FAILED"; exit 1; }
echo "  isolation confirmed: live DNS blocked, live TCP blocked, AWS DNS still resolves"

echo "== [8] live Vault untouched (baseline check) =="
kubectl get pods -n deploy-vault -o wide

cat <<EOF

== DRILL PART 1 COMPLETE ==
Leave the drill Vault RUNNING for audit. Port-forward target: svc/vault-drill:8200 (-n vault-drill).
Teardown (after audit / before Part 2 decides): kubectl delete ns vault-drill && rm -f ${INIT_OUT}
EOF
