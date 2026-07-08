#!/usr/bin/env bash
# Zero-live-mutation S0 restore driver for the Vault generate-root drill.
#
# This driver prepares the isolated vault-drill scratch target, captures a fresh
# live Raft snapshot through the read-only vault-snapshot-backup role, restores
# it into scratch with snapshot-force, proves the restored scratch is unsealed,
# active, and isolated, proves live Vault pods stayed healthy, removes local
# transient files, and stops.
#
# It intentionally does not seed or read a canary, does not read recovery escrow
# or MFA material, does not call generate-root, and does not revoke any token.
set -Eeuo pipefail
set +x

export MSYS_NO_PATHCONV=1

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
WORK_DIR="${VAULT_DRILL_WORK_DIR:-C:/tmp/vault-drill-s0}"
INIT_OUT="${VAULT_DRILL_INIT_OUT:-${WORK_DIR}/vault-drill-empty-init.json}"
SNAPSHOT_FILE="${VAULT_DRILL_SNAPSHOT_FILE:-${WORK_DIR}/live-raft-s0.snap}"
VAULT_CA_CONFIGMAP="${REPO_ROOT}/clusters/talos-cluster/apps/dr-backup/vault-ca-configmap.yaml"
VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY:-false}"
LIVE_VAULT_FQDN="vault-0.vault-internal.deploy-vault.svc.cluster.local"
LIVE_PODS=(vault-0 vault-1 vault-2)

PF_PID=""
PF_PORT=""
VAULT_CA_FILE=""
ACTIVE_LIVE_POD=""
RESTORE_ATTEMPTED="false"
S0_READY="false"

if [[ -z "${KUBECONFIG:-}" && -f "${REPO_ROOT}/.s3/configs/kubeconfig" ]]; then
  export KUBECONFIG="${REPO_ROOT}/.s3/configs/kubeconfig"
fi

mkdir -p "${WORK_DIR}"
chmod 700 "${WORK_DIR}" 2>/dev/null || true
TMPDIR="$(mktemp -d "${WORK_DIR}/tmp.XXXXXX")"

to_native_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}

cleanup_sensitive_transients() {
  rm -f "${SNAPSHOT_FILE}" "${INIT_OUT}"
}

cleanup() {
  kubectl delete pod -n vault-drill netcheck --ignore-not-found --wait=false >/dev/null 2>&1 || true
  stop_pf
  if [[ "${S0_READY}" != "true" ]]; then
    cleanup_sensitive_transients
  fi
  rm -rf "${TMPDIR}"
}

wipe_scratch_objects() {
  stop_pf
  kubectl delete pod -n vault-drill netcheck --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl -n vault-drill delete sts vault-drill --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl -n vault-drill delete pvc data-vault-drill-0 --ignore-not-found --wait=true >/dev/null 2>&1 || true
}

on_error() {
  local rc=$?
  trap - ERR
  echo "S0_RESTORE_DRIVER_FAILED rc=${rc}" >&2
  if [[ "${RESTORE_ATTEMPTED}" == "true" && "${S0_READY}" != "true" ]]; then
    echo "S0_RESTORE_FAILURE_WIPE_ATTEMPT" >&2
    wipe_scratch_objects || true
  fi
  exit "${rc}"
}

on_signal() {
  trap - INT TERM
  echo "S0_RESTORE_DRIVER_INTERRUPTED" >&2
  if [[ "${RESTORE_ATTEMPTED}" == "true" && "${S0_READY}" != "true" ]]; then
    echo "S0_RESTORE_INTERRUPT_WIPE_ATTEMPT" >&2
    wipe_scratch_objects || true
  fi
  exit 130
}

trap cleanup EXIT
trap on_error ERR
trap on_signal INT TERM

pick_port() {
  python - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

utc_now() {
  python - <<'PY'
from datetime import datetime, timezone

print(datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
PY
}

json_get() {
  local file="$1"
  local expr="$2"
  python - "${file}" "${expr}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    cur = json.load(fh)

for part in sys.argv[2].split("."):
    if not part:
        continue
    if isinstance(cur, dict):
        cur = cur.get(part)
    else:
        cur = None
        break

if isinstance(cur, bool):
    print(str(cur).lower())
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur, separators=(",", ":"), sort_keys=True))
elif cur is None:
    print("")
else:
    print(cur)
PY
}

write_vault_ca_file() {
  VAULT_CA_FILE="${TMPDIR}/vault-ca.crt"
  python - "$(to_native_path "${VAULT_CA_CONFIGMAP}")" "$(to_native_path "${VAULT_CA_FILE}")" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
lines = source.read_text(encoding="utf-8").splitlines()

for idx, line in enumerate(lines):
    if line.strip() != "ca.crt: |":
        continue
    indent = len(line) - len(line.lstrip())
    cert_lines = []
    for child in lines[idx + 1:]:
        if not child.strip():
            cert_lines.append("")
            continue
        child_indent = len(child) - len(child.lstrip())
        if child_indent <= indent:
            break
        cert_lines.append(child[indent + 2:])
    target.write_text("\n".join(cert_lines).rstrip() + "\n", encoding="utf-8")
    raise SystemExit(0)

raise SystemExit(f"ca.crt not found in {source}")
PY
}

stop_pf() {
  if [[ -n "${PF_PID}" ]] && kill -0 "${PF_PID}" >/dev/null 2>&1; then
    kill "${PF_PID}" >/dev/null 2>&1 || true
    wait "${PF_PID}" >/dev/null 2>&1 || true
  fi
  PF_PID=""
  PF_PORT=""
}

start_pf() {
  local namespace="$1"
  local target="$2"

  stop_pf
  PF_PORT="$(pick_port)"
  kubectl -n "${namespace}" port-forward "${target}" "${PF_PORT}:8200" >"${TMPDIR}/pf-${namespace}-${PF_PORT}.log" 2>&1 &
  PF_PID="$!"
}

ensure_scratch_pf() {
  if [[ -z "${PF_PID}" ]] || ! kill -0 "${PF_PID}" >/dev/null 2>&1; then
    start_pf vault-drill svc/vault-drill
  fi
}

live_api() {
  local token="$1"
  local method="$2"
  local path="$3"
  local payload_file="${4:-}"
  local output_file="${5:-}"

  VAULT_ADDR="https://127.0.0.1:${PF_PORT}" \
  VAULT_TOKEN_API="${token}" \
  VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY}" \
  VAULT_CACERT="$(to_native_path "${VAULT_CA_FILE}")" \
  python - "${method}" "${path}" "${payload_file}" "${output_file}" <<'PY'
import json
import os
import pathlib
import ssl
import sys
import urllib.error
import urllib.request

method, path, payload_file, output_file = sys.argv[1:5]
addr = os.environ["VAULT_ADDR"].rstrip("/")
token = os.environ.get("VAULT_TOKEN_API", "")
url = f"{addr}/v1/{path.lstrip('/')}"
headers = {}
if token:
    headers["X-Vault-Token"] = token

data = None
if payload_file:
    data = pathlib.Path(payload_file).read_bytes()
    headers["Content-Type"] = "application/json"

if os.environ.get("VAULT_SKIP_VERIFY", "").lower() == "true":
    ctx = ssl._create_unverified_context()
else:
    ctx = ssl.create_default_context(cafile=os.environ["VAULT_CACERT"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED

req = urllib.request.Request(url, data=data, headers=headers, method=method)
try:
    with urllib.request.urlopen(req, context=ctx, timeout=300) as response:
        if output_file:
            with open(output_file, "wb") as fh:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
        else:
            sys.stdout.buffer.write(response.read())
except urllib.error.HTTPError as exc:
    body = exc.read()
    sys.stderr.write(f"Vault API error: method={method} path={path} status={exc.code}\n")
    if body:
        sys.stderr.buffer.write(body[:1024])
        sys.stderr.write("\n")
    raise
PY
}

scratch_api() {
  local token="$1"
  local method="$2"
  local path="$3"
  local payload_file="${4:-}"
  local output_file="${5:-}"

  VAULT_ADDR="http://127.0.0.1:${PF_PORT}" \
  VAULT_TOKEN_API="${token}" \
  python - "${method}" "${path}" "${payload_file}" "${output_file}" <<'PY'
import os
import pathlib
import sys
import urllib.error
import urllib.request

method, path, payload_file, output_file = sys.argv[1:5]
addr = os.environ["VAULT_ADDR"].rstrip("/")
token = os.environ.get("VAULT_TOKEN_API", "")
url = f"{addr}/v1/{path.lstrip('/')}"
headers = {}
if token:
    headers["X-Vault-Token"] = token

data = None
if payload_file:
    data = pathlib.Path(payload_file).read_bytes()
    headers["Content-Type"] = "application/octet-stream"

req = urllib.request.Request(url, data=data, headers=headers, method=method)
try:
    with urllib.request.urlopen(req, timeout=300) as response:
        if output_file:
            pathlib.Path(output_file).write_bytes(response.read())
        else:
            sys.stdout.buffer.write(response.read())
except urllib.error.HTTPError as exc:
    body = exc.read()
    sys.stderr.write(f"Scratch Vault API error: method={method} path={path} status={exc.code}\n")
    if body:
        sys.stderr.buffer.write(body[:1024])
        sys.stderr.write("\n")
    raise
PY
}

scratch_root() {
  python - "$(to_native_path "${INIT_OUT}")" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
token = doc.get("root_token")
if not token:
    raise SystemExit("root_token missing from transient init JSON")
print(token, end="")
PY
}

wait_scratch_token() {
  local token="$1"

  for _ in $(seq 1 120); do
    if scratch_api "${token}" GET auth/token/lookup-self "" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  scratch_api "${token}" GET auth/token/lookup-self "" >/dev/null
}

check_empty_mounts() {
  local label="$1"
  local root mounts_file

  root="$(scratch_root)"
  mounts_file="${TMPDIR}/${label}-mounts.json"
  start_pf vault-drill svc/vault-drill
  wait_scratch_token "${root}"
  scratch_api "${root}" GET sys/mounts "" "${mounts_file}"
  stop_pf

  python - "${mounts_file}" "${label}" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
label = sys.argv[2]
allowed = {"agent-registry/", "cubbyhole/", "identity/", "sys/"}
mounts = set(doc.get("data", doc).keys())
unexpected = sorted(mounts - allowed)
base = ",".join(sorted(mounts & allowed))
print(f"{label}_EMPTY_MOUNTS base_mounts={base} unexpected_mounts={','.join(unexpected)}")
if unexpected:
    raise SystemExit(1)
PY
}

capture_live_pods() {
  local label="$1"
  local outfile="${TMPDIR}/live-${label}.json"

  kubectl -n deploy-vault get pods \
    -l app.kubernetes.io/name=vault,app.kubernetes.io/component=server \
    -o json >"${outfile}"
  python - "${outfile}" "${label}" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
label = sys.argv[2]
items = doc.get("items", [])
if not items:
    raise SystemExit("no live Vault pods found")
for item in sorted(items, key=lambda obj: obj["metadata"]["name"]):
    name = item["metadata"]["name"]
    statuses = item.get("status", {}).get("containerStatuses", []) or []
    ready = sum(1 for status in statuses if status.get("ready"))
    total = len(statuses)
    restarts = sum(int(status.get("restartCount", 0)) for status in statuses)
    phase = item.get("status", {}).get("phase", "")
    print(f"LIVE_POD_{label} name={name} phase={phase} ready={ready}/{total} restarts={restarts}")
PY
}

verify_live_undisturbed() {
  local before="${TMPDIR}/live-before.json"
  local after="${TMPDIR}/live-after.json"

  capture_live_pods after
  python - "${before}" "${after}" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))

def pod_state(doc):
    states = {}
    for item in doc.get("items", []):
        name = item["metadata"]["name"]
        statuses = item.get("status", {}).get("containerStatuses", []) or []
        ready = sum(1 for status in statuses if status.get("ready"))
        total = len(statuses)
        restarts = sum(int(status.get("restartCount", 0)) for status in statuses)
        states[name] = {
            "phase": item.get("status", {}).get("phase", ""),
            "ready": ready,
            "total": total,
            "restarts": restarts,
        }
    return states

b = pod_state(before)
a = pod_state(after)
ok = bool(a) and b.keys() == a.keys()
for name in sorted(a):
    before_state = b.get(name, {})
    after_state = a[name]
    unchanged = before_state.get("restarts") == after_state["restarts"]
    ready_now = after_state["total"] > 0 and after_state["ready"] == after_state["total"]
    print(
        "LIVE_POD_UNDISTURBED "
        f"name={name} phase={after_state['phase']} "
        f"ready={after_state['ready']}/{after_state['total']} "
        f"restarts_before={before_state.get('restarts', 'missing')} "
        f"restarts_after={after_state['restarts']} unchanged={str(unchanged).lower()}"
    )
    ok = ok and after_state["phase"] == "Running" and ready_now and unchanged

if not ok:
    raise SystemExit("live Vault pod state changed or is unhealthy")
print("LIVE_VAULT_UNDISTURBED_OK")
PY
}

find_active_live_pod() {
  local pod standby

  write_vault_ca_file
  for pod in "${LIVE_PODS[@]}"; do
    start_pf deploy-vault "pod/${pod}"
    for _ in $(seq 1 40); do
      if live_api "" GET "sys/health?standbyok=true" "" "${TMPDIR}/health-${pod}.json" >/dev/null 2>&1; then
        break
      fi
      sleep 0.5
    done
    if live_api "" GET "sys/health?standbyok=true" "" "${TMPDIR}/health-${pod}.json" >/dev/null 2>&1; then
      standby="$(json_get "${TMPDIR}/health-${pod}.json" "standby")"
      if [[ "${standby}" == "false" ]]; then
        ACTIVE_LIVE_POD="${pod}"
        return
      fi
    fi
    stop_pf
  done

  echo "STOP: could not identify active live Vault pod" >&2
  exit 1
}

capture_live_snapshot() {
  local jwt login_payload login_response token token_type lease_duration size

  SNAPSHOT_START_UTC="$(utc_now)"
  echo "SNAPSHOT_START_UTC=${SNAPSHOT_START_UTC}"
  rm -f "${SNAPSHOT_FILE}"

  find_active_live_pod
  echo "LIVE_ACTIVE_POD=${ACTIVE_LIVE_POD}"

  jwt="$(kubectl -n dr-backup create token dr-backup --duration=10m)"
  login_payload="${TMPDIR}/snapshot-login.json"
  login_response="${TMPDIR}/snapshot-login-response.json"
  SA_JWT="${jwt}" python - "${login_payload}" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
jwt = os.environ["SA_JWT"]
path.write_text(json.dumps({"role": "vault-snapshot-backup", "jwt": jwt}, separators=(",", ":")), encoding="utf-8")
PY
  unset jwt SA_JWT

  live_api "" POST auth/kubernetes/login "${login_payload}" "${login_response}"
  token="$(json_get "${login_response}" "auth.client_token")"
  token_type="$(json_get "${login_response}" "auth.token_type")"
  lease_duration="$(json_get "${login_response}" "auth.lease_duration")"
  if [[ -z "${token}" ]]; then
    echo "STOP: snapshot k8s-auth login did not return a token" >&2
    exit 1
  fi
  if [[ "${token_type}" != "batch" ]]; then
    echo "WARNING: vault-snapshot-backup returned token_type=${token_type:-missing}; proceeding with the existing least-privilege snapshot-read token" >&2
    echo "WARNING: a transient 15m capture token may ride in the snapshot, but it is inert on the throwaway scratch used for this S0 generate-root proof" >&2
  fi
  echo "LIVE_AUTH_LOGIN_READ_ROLE_OK role=vault-snapshot-backup token_type=${token_type} lease_duration_seconds=${lease_duration}"

  live_api "${token}" GET sys/storage/raft/snapshot "" "${SNAPSHOT_FILE}"
  unset token
  stop_pf

  size="$(wc -c < "${SNAPSHOT_FILE}" | tr -d '[:space:]')"
  if [[ -z "${size}" || "${size}" == "0" ]]; then
    echo "STOP: live snapshot was empty" >&2
    exit 1
  fi
  chmod 600 "${SNAPSHOT_FILE}" 2>/dev/null || true
  echo "SNAPSHOT_CAPTURED_OK source_role=vault-snapshot-backup size_bytes=${size}"
}

wipe_and_reinit_empty_scratch() {
  echo "SCRATCH_PREEXISTING_WIPE_START"
  wipe_scratch_objects
  rm -f "${INIT_OUT}"
  INIT_OUT="${INIT_OUT}" PF_PORT="$(pick_port)" bash "${DIR}/drill-run.sh"
  [[ -f "${INIT_OUT}" ]] || { echo "STOP: scratch init JSON missing after reinit: ${INIT_OUT}" >&2; exit 1; }
  check_empty_mounts "PRE_RESTORE"
  echo "SCRATCH_CLEAN_EMPTY_READY_OK namespace=vault-drill service=svc/vault-drill"
}

restore_snapshot_into_scratch() {
  local root

  root="$(scratch_root)"
  start_pf vault-drill svc/vault-drill
  wait_scratch_token "${root}"

  RESTORE_SUBMIT_UTC="$(utc_now)"
  RESTORE_ATTEMPTED="true"
  echo "RESTORE_SUBMIT_UTC=${RESTORE_SUBMIT_UTC}"
  scratch_api "${root}" POST sys/storage/raft/snapshot-force "${SNAPSHOT_FILE}" >/dev/null
  unset root
  echo "RESTORE_FORCE_OK target=vault-drill"
}

wait_restored_scratch_active() {
  local sealed standby is_self initialized version cluster_name

  for _ in $(seq 1 180); do
    ensure_scratch_pf
    if scratch_api "" GET sys/seal-status "" "${TMPDIR}/scratch-seal.json" >/dev/null 2>&1; then
      sealed="$(json_get "${TMPDIR}/scratch-seal.json" "sealed")"
      if [[ "${sealed}" == "false" ]]; then
        break
      fi
    fi
    sleep 1
  done

  ensure_scratch_pf
  scratch_api "" GET sys/seal-status "" "${TMPDIR}/scratch-seal.json" >/dev/null
  scratch_api "" GET "sys/health?standbyok=true" "" "${TMPDIR}/scratch-health.json" >/dev/null
  scratch_api "" GET sys/leader "" "${TMPDIR}/scratch-leader.json" >/dev/null

  initialized="$(json_get "${TMPDIR}/scratch-seal.json" "initialized")"
  sealed="$(json_get "${TMPDIR}/scratch-seal.json" "sealed")"
  standby="$(json_get "${TMPDIR}/scratch-health.json" "standby")"
  is_self="$(json_get "${TMPDIR}/scratch-leader.json" "is_self")"
  version="$(json_get "${TMPDIR}/scratch-seal.json" "version")"
  cluster_name="$(json_get "${TMPDIR}/scratch-seal.json" "cluster_name")"

  [[ "${initialized}" == "true" ]] || { echo "STOP: restored scratch initialized=${initialized}" >&2; exit 1; }
  [[ "${sealed}" == "false" ]] || { echo "STOP: restored scratch sealed=${sealed}" >&2; exit 1; }
  [[ "${standby}" == "false" ]] || { echo "STOP: restored scratch standby=${standby}" >&2; exit 1; }
  [[ "${is_self}" == "true" ]] || { echo "STOP: restored scratch leader is_self=${is_self}" >&2; exit 1; }

  echo "ACTIVE_PROOF_OK initialized=true sealed=false standby=false is_self=true version=${version} cluster_name=${cluster_name}"
  stop_pf
}

live_vault_cluster_ip() {
  local ip

  ip="$(kubectl -n deploy-vault get svc vault -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
  if [[ -n "${LIVE_VAULT_CLUSTERIP:-}" ]]; then
    printf '%s' "${LIVE_VAULT_CLUSTERIP}"
  elif [[ -n "${ip}" && "${ip}" != "None" ]]; then
    printf '%s' "${ip}"
  else
    echo "STOP: could not determine live Vault ClusterIP; set LIVE_VAULT_CLUSTERIP" >&2
    exit 1
  fi
}

prove_network_isolation() {
  local live_ip result

  live_ip="$(live_vault_cluster_ip)"
  kubectl delete pod -n vault-drill netcheck --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl apply -f - >/dev/null <<'YAML'
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
YAML
  kubectl -n vault-drill wait --for=condition=Ready pod/netcheck --timeout=120s

  set +e
  result="$(kubectl exec -n vault-drill netcheck -- sh -c "
    nslookup ${LIVE_VAULT_FQDN} >/dev/null 2>&1 && echo DNS-RESOLVED-LIVE || echo DNS-BLOCKED
    nslookup kms.us-east-1.amazonaws.com >/dev/null 2>&1 && echo DNS-AWS-OK || echo DNS-AWS-FAIL
    timeout 6 nc -w 4 ${live_ip} 8200 </dev/null >/dev/null 2>&1 && echo TCP-REACHED-LIVE || echo TCP-BLOCKED-TO-LIVE
  ")"
  set -e

  echo "${result}" | sed 's/^/  /'
  kubectl delete pod -n vault-drill netcheck --ignore-not-found --wait=false >/dev/null 2>&1 || true
  echo "${result}" | grep -q '^DNS-BLOCKED$' || { echo "STOP: live Vault DNS was not blocked" >&2; exit 1; }
  echo "${result}" | grep -q '^DNS-AWS-OK$' || { echo "STOP: AWS DNS did not resolve from scratch" >&2; exit 1; }
  echo "${result}" | grep -q '^TCP-BLOCKED-TO-LIVE$' || { echo "STOP: live Vault TCP was reachable from scratch" >&2; exit 1; }
  echo "POST_RESTORE_ISOLATION_OK live_dns=blocked live_tcp=blocked aws_dns=ok"
}

cleanup_success_transients() {
  cleanup_sensitive_transients
  python - "$(to_native_path "${SNAPSHOT_FILE}")" "$(to_native_path "${INIT_OUT}")" <<'PY'
import pathlib
import sys

ok = True
for raw in sys.argv[1:]:
    path = pathlib.Path(raw)
    exists = path.exists()
    print(f"S0_TRANSIENT_CLEANUP path={path} exists={str(exists).lower()}")
    ok = ok and not exists
if not ok:
    raise SystemExit(1)
PY
  echo "S0_TRANSIENT_CLEANUP_OK"
}

main() {
  echo "== [0] PRE-RESTORE GUARD AND CLEAN SCRATCH =="
  bash "${DIR}/guard.sh"
  wipe_and_reinit_empty_scratch

  echo "== [1] CAPTURE FRESH LIVE RAFT SNAPSHOT =="
  capture_live_pods before
  capture_live_snapshot

  echo "== [2] RESTORE SNAPSHOT INTO ISOLATED SCRATCH =="
  restore_snapshot_into_scratch

  echo "== [3] PROVE RESTORED SCRATCH ACTIVE AND ISOLATED =="
  wait_restored_scratch_active
  prove_network_isolation

  echo "== [4] PROVE LIVE VAULT UNDISTURBED =="
  verify_live_undisturbed

  echo "== [5] REMOVE LOCAL TRANSIENTS AND STOP BEFORE GENERATE-ROOT =="
  cleanup_success_transients
  S0_READY="true"
  echo "S0_RESTORE_READY namespace=vault-drill service=svc/vault-drill status=restored_unsealed_active_isolated_live_undisturbed"
  echo "NEXT_STEP=owner_interactive_generate_root"
}

main "$@"
