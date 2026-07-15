#!/usr/bin/env bash
set -Eeuo pipefail
set +x

# Requires a short-TTL minted Vault admin token, preferably via VAULT_TOKEN.
# Do not use a standing root token. Revoke the token after the proof; set
# REVOKE_TOKEN_AFTER=true to opt into `vault token revoke -self` on success.

export MSYS_NO_PATHCONV=1

REPO_ROOT="$(git rev-parse --show-toplevel)"
# CP-4 S4a: the vault-snapshot-backup policy/role are operator-MANAGED; the
# single source of truth is the redhatcop CR pair under vault-config/managed/.
# This break-glass DR path (Vault rebuilt before the operator is running)
# extracts the same content from those CRs — no second copy of the policy.
POLICY_CR="${REPO_ROOT}/clusters/talos-cluster/apps/vault/vault-config/managed/policy-vault-snapshot-backup.yaml"
ROLE_CR="${REPO_ROOT}/clusters/talos-cluster/apps/vault/vault-config/managed/role-vault-snapshot-backup.yaml"
DR_APP_DIR="${REPO_ROOT}/clusters/talos-cluster/apps/dr-backup"
VAULT_CA_CONFIGMAP="${DR_APP_DIR}/vault-ca-configmap.yaml"
TOKEN_FILE_DEFAULT="${REPO_ROOT}/../admin-token.json"
VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY:-false}"
if [[ -z "${KUBECONFIG:-}" && -f "${REPO_ROOT}/.s3/configs/kubeconfig" ]]; then
  export KUBECONFIG="${REPO_ROOT}/.s3/configs/kubeconfig"
fi

TMPDIR="$(mktemp -d)"
PF_PID=""
VAULT_CA_FILE="${TMPDIR}/vault-ca.crt"
POLICY_FILE="${TMPDIR}/vault-snapshot-backup.hcl"
ROLE_FILE="${TMPDIR}/vault-snapshot-backup.role.json"

# Extract the policy HCL + the Vault role payload from the managed CRs. The
# role projection mirrors the operator's VRole.toMap() write payload so the
# break-glass apply and the operator converge to the SAME live object.
extract_from_managed_crs() {
  python3 - "${POLICY_CR}" "${ROLE_CR}" "${POLICY_FILE}" "${ROLE_FILE}" <<'PY'
import json
import pathlib
import sys

import yaml

policy_cr, role_cr, policy_out, role_out = sys.argv[1:5]

policy = yaml.safe_load(pathlib.Path(policy_cr).read_text(encoding="utf-8"))
assert policy["kind"] == "Policy", policy_cr
pathlib.Path(policy_out).write_text(policy["spec"]["policy"], encoding="utf-8")

role = yaml.safe_load(pathlib.Path(role_cr).read_text(encoding="utf-8"))
assert role["kind"] == "KubernetesAuthEngineRole", role_cr
spec = role["spec"]
target_ns = (spec.get("targetNamespaces") or {}).get("targetNamespaces")
if not target_ns:
    raise SystemExit(
        f"{role_cr}: expected a static targetNamespaces list (selector roles "
        "are not managed by this script)"
    )
payload = {
    "bound_service_account_names": spec["targetServiceAccounts"],
    "bound_service_account_namespaces": target_ns,
    "alias_name_source": spec.get("aliasNameSource", "serviceaccount_uid"),
    "token_ttl": spec.get("tokenTTL", 0),
    "token_max_ttl": spec.get("tokenMaxTTL", 0),
    "token_policies": spec["policies"],
    "token_bound_cidrs": spec.get("tokenBoundCIDRs") or [],
    "token_explicit_max_ttl": spec.get("tokenExplicitMaxTTL", 0),
    "token_no_default_policy": spec.get("tokenNoDefaultPolicy", False),
    "token_num_uses": spec.get("tokenNumUses", 0),
    "token_period": spec.get("tokenPeriod", 0),
    "token_type": spec.get("tokenType", "default"),
}
if spec.get("audience"):
    payload["audience"] = spec["audience"]
pathlib.Path(role_out).write_text(json.dumps(payload), encoding="utf-8")
PY
}
extract_from_managed_crs

to_native_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

cleanup() {
  kubectl delete job -n dr-backup vault-snapshot-backup-proof --ignore-not-found --wait=false >/dev/null 2>&1 || true
  if [[ -n "${PF_PID}" ]] && kill -0 "${PF_PID}" >/dev/null 2>&1; then
    kill "${PF_PID}" >/dev/null 2>&1 || true
    wait "${PF_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMPDIR}"
}
trap cleanup EXIT

read_admin_token() {
  if [[ -n "${VAULT_TOKEN:-}" ]]; then
    printf '%s' "${VAULT_TOKEN}"
    return
  fi

  local token_file="${VAULT_TOKEN_FILE:-${TOKEN_FILE_DEFAULT}}"
  if [[ ! -f "${token_file}" ]]; then
    echo "ERROR: set VAULT_TOKEN or VAULT_TOKEN_FILE; default token file not found" >&2
    exit 1
  fi

  python - "${token_file}" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
try:
    data = json.loads(text)
except Exception:
    print(text, end="")
    raise SystemExit(0)

def get_path(obj, path):
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur if isinstance(cur, str) and cur else None

for path in (
    ("root_token",),
    ("token",),
    ("client_token",),
    ("auth", "client_token"),
    ("data", "token"),
    ("data", "client_token"),
):
    token = get_path(data, path)
    if token:
        print(token, end="")
        raise SystemExit(0)

raise SystemExit("token not found in token file")
PY
}

write_vault_ca_file() {
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

pick_port() {
  python - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])
PY
}

vault_api() {
  local method="$1"
  local path="$2"
  local payload_file="${3:-}"
  VAULT_ADDR="https://127.0.0.1:${PF_PORT}" \
  VAULT_TOKEN="${ADMIN_TOKEN}" \
  VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY}" \
  VAULT_CACERT="$(to_native_path "${VAULT_CA_FILE}")" \
  python - "${method}" "${path}" "${payload_file}" <<'PY'
import json
import os
import pathlib
import ssl
import sys
import urllib.request

method, path, payload_file = sys.argv[1], sys.argv[2], sys.argv[3]
addr = os.environ["VAULT_ADDR"].rstrip("/")
token = os.environ["VAULT_TOKEN"]
url = f"{addr}/v1/{path.lstrip('/')}"
headers = {"X-Vault-Token": token}
data = None
if payload_file:
    if path.startswith("sys/policies/acl/"):
        policy = pathlib.Path(payload_file).read_text(encoding="utf-8")
        data = json.dumps({"policy": policy}).encode("utf-8")
    else:
        data = pathlib.Path(payload_file).read_bytes()
    headers["Content-Type"] = "application/json"
if os.environ.get("VAULT_SKIP_VERIFY", "").lower() == "true":
    ctx = ssl._create_unverified_context()
else:
    ctx = ssl.create_default_context(cafile=os.environ["VAULT_CACERT"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
req = urllib.request.Request(url, data=data, headers=headers, method=method)
with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
    sys.stdout.buffer.write(response.read())
PY
}

self_revoke_admin_token() {
  if [[ "${REVOKE_TOKEN_AFTER:-false}" != "true" ]]; then
    return
  fi

  VAULT_ADDR="https://127.0.0.1:${PF_PORT}" \
  VAULT_TOKEN="${ADMIN_TOKEN}" \
  VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY}" \
  VAULT_CACERT="$(to_native_path "${VAULT_CA_FILE}")" \
  VAULT_TLS_SERVER_NAME="vault.deploy-vault.svc.cluster.local" \
  vault token revoke -self >/dev/null
  echo "ADMIN_TOKEN_REVOKED_OK"
}

wait_for_proof_job() {
  local deadline=$((SECONDS + 300))
  local status succeeded failed

  while (( SECONDS < deadline )); do
    status="$(kubectl -n dr-backup get job vault-snapshot-backup-proof -o jsonpath='{.status.succeeded}{"|"}{.status.failed}' 2>/dev/null || true)"
    IFS='|' read -r succeeded failed <<<"${status}"
    if [[ "${succeeded:-0}" == "1" ]]; then
      return 0
    fi
    if [[ "${failed:-0}" =~ ^[0-9]+$ ]] && (( failed > 0 )); then
      echo "PROOF_JOB_FAILED"
      kubectl -n dr-backup logs job/vault-snapshot-backup-proof --all-containers=true || true
      return 1
    fi
    sleep 2
  done

  echo "PROOF_JOB_TIMEOUT"
  kubectl -n dr-backup logs job/vault-snapshot-backup-proof --all-containers=true || true
  return 1
}

ADMIN_TOKEN="$(read_admin_token)"
write_vault_ca_file
PF_PORT="$(pick_port)"

kubectl -n deploy-vault port-forward svc/vault "${PF_PORT}:8200" >"${TMPDIR}/port-forward.log" 2>&1 &
PF_PID="$!"

for _ in $(seq 1 40); do
  if vault_api GET auth/token/lookup-self >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
vault_api GET auth/token/lookup-self >/dev/null

vault_api PUT sys/policies/acl/vault-snapshot-backup "${POLICY_FILE}" >/dev/null
vault_api POST auth/kubernetes/role/vault-snapshot-backup "${ROLE_FILE}" >/dev/null
vault_api GET sys/policies/acl/vault-snapshot-backup >"${TMPDIR}/policy-read.txt"
vault_api GET auth/kubernetes/role/vault-snapshot-backup >"${TMPDIR}/role-read.json"
echo "POLICY_ROLE_APPLIED_OK"

kubectl apply -k "${DR_APP_DIR}" >/dev/null
kubectl -n dr-backup get serviceaccount dr-backup >/dev/null
kubectl -n dr-backup get configmap vault-ca >/dev/null
echo "DR_BACKUP_MANIFESTS_APPLIED_OK"

kubectl -n deploy-vault get pods \
  -l app.kubernetes.io/name=vault,app.kubernetes.io/component=server \
  -o json >"${TMPDIR}/vault-before.json"

kubectl delete job -n dr-backup vault-snapshot-backup-proof --ignore-not-found --wait=true >/dev/null 2>&1 || true
cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: vault-snapshot-backup-proof
  namespace: dr-backup
  labels:
    app.kubernetes.io/name: dr-backup
    app.kubernetes.io/component: backup
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 300
  template:
    metadata:
      labels:
        app.kubernetes.io/name: dr-backup
        app.kubernetes.io/component: backup
        app.kubernetes.io/part-of: vault-snapshot-backup-proof
    spec:
      serviceAccountName: dr-backup
      automountServiceAccountToken: true
      restartPolicy: Never
      # Cilium L7 DNS matchName only allows the exact FQDN. Keep ndots:1 here
      # and on the future standing backup Job so resolv.conf does not try
      # search-domain expansions that the proxy correctly refuses.
      dnsConfig:
        options:
          - name: ndots
            value: "1"
      securityContext:
        runAsNonRoot: true
        runAsUser: 100
        runAsGroup: 100
        fsGroup: 100
        fsGroupChangePolicy: OnRootMismatch
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: proof
          image: python@sha256:8373231e1e906ddfb457748bfc032c4c06ada8c759b7b62d9c73ec2a3c56e710
          imagePullPolicy: IfNotPresent
          command:
            - python3
            - -c
            - |
              import json
              import os
              import ssl
              import sys
              import time
              import urllib.error
              import urllib.request

              VAULT_ADDR = "https://vault.deploy-vault.svc.cluster.local:8200"
              VAULT_CA = "/etc/vault-ca/ca.crt"
              SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
              CTX = ssl.create_default_context(cafile=VAULT_CA)

              class NoRedirect(urllib.request.HTTPRedirectHandler):
                  def redirect_request(self, req, fp, code, msg, headers, newurl):
                      return None

              OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), NoRedirect)
              REDIRECT_CODES = {301, 302, 303, 307, 308}

              def open_vault(req):
                  # Keep DNS pinned to the one allowed service name instead of following
                  # standby redirects to pod-internal names the DNS proxy refuses.
                  for attempt in range(30):
                      try:
                          return OPENER.open(req, timeout=120)
                      except urllib.error.HTTPError as exc:
                          if exc.code in REDIRECT_CODES and attempt < 29:
                              exc.close()
                              time.sleep(1)
                              continue
                          raise

              def vault(method, path, token=None, body=None, stream_to=None):
                  headers = {}
                  data = None
                  if token:
                      headers["X-Vault-Token"] = token
                  if body is not None:
                      data = json.dumps(body).encode("utf-8")
                      headers["Content-Type"] = "application/json"
                  url = f"{VAULT_ADDR}/v1/{path.lstrip('/')}"
                  req = urllib.request.Request(url, data=data, headers=headers, method=method)
                  with open_vault(req) as response:
                      if stream_to:
                          with open(stream_to, "wb") as fh:
                              while True:
                                  chunk = response.read(1024 * 1024)
                                  if not chunk:
                                      break
                                  fh.write(chunk)
                          return {}
                      raw = response.read()
                      return json.loads(raw.decode("utf-8") or "{}") if raw else {}

              def expect_403(label, method, path, body=None):
                  try:
                      vault(method, path, token=client_token, body=body)
                  except urllib.error.HTTPError as exc:
                      if exc.code == 403:
                          print(f"{label}_403_OK")
                          return
                      print(f"{label}_NOT_403 code={exc.code}")
                      raise SystemExit(1)
                  print(f"{label}_UNEXPECTED_SUCCESS")
                  raise SystemExit(1)

              jwt = open(SA_TOKEN, encoding="utf-8").read().strip()
              login = vault("POST", "auth/kubernetes/login", body={"role": "vault-snapshot-backup", "jwt": jwt})
              client_token = login["auth"]["client_token"]
              del jwt
              vault("GET", "auth/token/lookup-self", token=client_token)

              snap_path = "/tmp/x.snap"
              vault("GET", "sys/storage/raft/snapshot", token=client_token, stream_to=snap_path)
              size_bytes = os.path.getsize(snap_path)
              os.remove(snap_path)
              if size_bytes <= 0:
                  print("SNAPSHOT_SIZE_FAIL")
                  raise SystemExit(1)
              print(f"SNAPSHOT_OK size_bytes={size_bytes}")

              expect_403("SECRET_READ", "GET", "secret/data/platform/dr-backup-proof")
              expect_403("POLICY_LIST", "GET", "sys/policies/acl?list=true")
              expect_403("TOKEN_CREATE", "POST", "auth/token/create", body={})
          env:
            - name: PYTHONDONTWRITEBYTECODE
              value: "1"
            - name: HOME
              value: /tmp
          volumeMounts:
            - name: vault-ca
              mountPath: /etc/vault-ca
              readOnly: true
            - name: tmp
              mountPath: /tmp
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
      volumes:
        - name: vault-ca
          configMap:
            name: vault-ca
            defaultMode: 0444
            items:
              - key: ca.crt
                path: ca.crt
        - name: tmp
          emptyDir: {}
YAML

wait_for_proof_job
kubectl -n dr-backup logs job/vault-snapshot-backup-proof >"${TMPDIR}/proof.log"

kubectl -n deploy-vault get pods \
  -l app.kubernetes.io/name=vault,app.kubernetes.io/component=server \
  -o json >"${TMPDIR}/vault-after.json"

python - "$(to_native_path "${TMPDIR}/vault-before.json")" "$(to_native_path "${TMPDIR}/vault-after.json")" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))

def pod_state(doc):
    states = {}
    for item in doc.get("items", []):
        name = item["metadata"]["name"]
        statuses = item.get("status", {}).get("containerStatuses", []) or []
        ready = sum(1 for c in statuses if c.get("ready"))
        restarts = sum(int(c.get("restartCount", 0)) for c in statuses)
        states[name] = {
            "phase": item.get("status", {}).get("phase", ""),
            "ready": f"{ready}/{len(statuses)}",
            "restarts": restarts,
        }
    return states

b = pod_state(before)
a = pod_state(after)
ok = bool(a) and b.keys() == a.keys()
for name in sorted(a):
    unchanged = name in b and b[name]["restarts"] == a[name]["restarts"]
    print(
        f"VAULT_POD {name} phase={a[name]['phase']} ready={a[name]['ready']} "
        f"restarts_before={b.get(name, {}).get('restarts', 'missing')} "
        f"restarts_after={a[name]['restarts']} unchanged={str(unchanged).lower()}"
    )
    ready_now = a[name]["ready"].split("/")
    ok = ok and a[name]["phase"] == "Running" and len(ready_now) == 2 and ready_now[0] == ready_now[1] and unchanged

if ok:
    print("VAULT_UNDISTURBED_OK")
else:
    print("VAULT_UNDISTURBED_FAIL")
    raise SystemExit(1)
PY

cat "${TMPDIR}/proof.log"
echo "PROOF_JOB_DELETING"
kubectl delete job -n dr-backup vault-snapshot-backup-proof --ignore-not-found --wait=true >/dev/null
self_revoke_admin_token
echo "PROOF_COMPLETE_OK"
