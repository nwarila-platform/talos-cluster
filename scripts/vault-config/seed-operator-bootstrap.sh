#!/usr/bin/env bash
set -Eeuo pipefail
set +x

# CP-4 S2b — seed the vault-config-operator BOOTSTRAP identity into live Vault.
#
# THE OWNED, OUT-OF-BAND EXCEPTION (ADR-0028): applies the operator's own scoped
# ACL policy + k8s-auth role. This identity is excluded from the operator's
# managed set (the bootstrap paradox) and is applied ONLY here, owner-watched,
# NEVER by GitOps and NEVER by the operator itself.
#
# Requires a SHORT-TTL minted Vault admin token, preferably via VAULT_TOKEN.
# Do NOT use a standing root token. Set REVOKE_TOKEN_AFTER=true to run
# `vault token revoke -self` after a successful seed. This script never prints
# the admin token, the policy body, or the role body.
#
# Idempotent: PUT sys/policies/acl and POST auth/kubernetes/role are upserts;
# re-running converges. It applies then READS BACK both objects and asserts the
# live policy equals the authored HCL byte-for-byte (design acceptance: a fresh
# read matches git).

export MSYS_NO_PATHCONV=1

REPO_ROOT="$(git rev-parse --show-toplevel)"
BOOTSTRAP_DIR="${REPO_ROOT}/clusters/talos-cluster/apps/vault/vault-config/bootstrap"
POLICY_FILE="${BOOTSTRAP_DIR}/vault-config-operator.policy.hcl"
ROLE_FILE="${BOOTSTRAP_DIR}/vault-config-operator.role.json"
POLICY_NAME="vault-config-operator"
ROLE_NAME="vault-config-operator"
VAULT_CA_CONFIGMAP="${REPO_ROOT}/clusters/talos-cluster/apps/dr-backup/vault-ca-configmap.yaml"
TOKEN_FILE_DEFAULT="${REPO_ROOT}/../admin-token.json"
VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY:-false}"
if [[ -z "${KUBECONFIG:-}" && -f "${REPO_ROOT}/.s3/configs/kubeconfig" ]]; then
  export KUBECONFIG="${REPO_ROOT}/.s3/configs/kubeconfig"
fi

TMPDIR="$(mktemp -d)"
PF_PID=""
VAULT_CA_FILE="${TMPDIR}/vault-ca.crt"

to_native_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

cleanup() {
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
import json, pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
try:
    data = json.loads(text)
except Exception:
    print(text, end=""); raise SystemExit(0)
def get_path(obj, path):
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur if isinstance(cur, str) and cur else None
for path in (("root_token",), ("token",), ("client_token",), ("auth", "client_token"),
             ("data", "token"), ("data", "client_token")):
    tok = get_path(data, path)
    if tok:
        print(tok, end=""); raise SystemExit(0)
raise SystemExit("token not found in token file")
PY
}

write_vault_ca_file() {
  python - "$(to_native_path "${VAULT_CA_CONFIGMAP}")" "$(to_native_path "${VAULT_CA_FILE}")" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]); target = pathlib.Path(sys.argv[2])
lines = source.read_text(encoding="utf-8").splitlines()
for idx, line in enumerate(lines):
    if line.strip() != "ca.crt: |":
        continue
    indent = len(line) - len(line.lstrip())
    cert_lines = []
    for child in lines[idx + 1:]:
        if not child.strip():
            cert_lines.append(""); continue
        if (len(child) - len(child.lstrip())) <= indent:
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
    s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])
PY
}

vault_api() {
  local method="$1" path="$2" payload_file="${3:-}"
  VAULT_ADDR="https://127.0.0.1:${PF_PORT}" \
  VAULT_TOKEN="${ADMIN_TOKEN}" \
  VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY}" \
  VAULT_CACERT="$(to_native_path "${VAULT_CA_FILE}")" \
  python - "${method}" "${path}" "${payload_file}" <<'PY'
import json, os, pathlib, ssl, sys, urllib.request
method, path, payload_file = sys.argv[1], sys.argv[2], sys.argv[3]
addr = os.environ["VAULT_ADDR"].rstrip("/")
url = f"{addr}/v1/{path.lstrip('/')}"
headers = {"X-Vault-Token": os.environ["VAULT_TOKEN"]}
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

ADMIN_TOKEN="$(read_admin_token)"
write_vault_ca_file
PF_PORT="$(pick_port)"

kubectl -n deploy-vault port-forward svc/vault "${PF_PORT}:8200" >"${TMPDIR}/port-forward.log" 2>&1 &
PF_PID="$!"

for _ in $(seq 1 40); do
  if vault_api GET auth/token/lookup-self >/dev/null 2>&1; then break; fi
  sleep 0.5
done
vault_api GET auth/token/lookup-self >/dev/null

# Apply the bootstrap policy + role.
vault_api PUT "sys/policies/acl/${POLICY_NAME}" "${POLICY_FILE}" >/dev/null
vault_api POST "auth/kubernetes/role/${ROLE_NAME}" "${ROLE_FILE}" >/dev/null
echo "BOOTSTRAP_POLICY_ROLE_APPLIED_OK"

# Read back + assert the live policy body equals the authored HCL byte-for-byte.
vault_api GET "sys/policies/acl/${POLICY_NAME}" >"${TMPDIR}/policy-read.json"
vault_api GET "auth/kubernetes/role/${ROLE_NAME}" >"${TMPDIR}/role-read.json"
python - "${POLICY_FILE}" "${TMPDIR}/policy-read.json" <<'PY'
import json, pathlib, sys
authored = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
live = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
live_policy = (((live.get("data") or {}).get("policy")) or live.get("policy") or "")
if authored.strip() == live_policy.strip():
    print("BOOTSTRAP_POLICY_ROUNDTRIP_OK")
else:
    print("BOOTSTRAP_POLICY_ROUNDTRIP_MISMATCH"); raise SystemExit(1)
PY

# Non-secret proof: the live role binds exactly the dedicated SA + namespace.
python - "${ROLE_FILE}" "${TMPDIR}/role-read.json" <<'PY'
import json, pathlib, sys
authored = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
live = (json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")).get("data") or {})
def norm(v):
    return v if isinstance(v, list) else [v]
ok = True
for key in ("bound_service_account_names", "bound_service_account_namespaces", "token_policies"):
    if sorted(norm(live.get(key))) != sorted(norm(authored.get(key))):
        print(f"ROLE_FIELD_MISMATCH {key} live={live.get(key)!r}"); ok = False
if live.get("token_no_default_policy") is not True:
    print("ROLE_NO_DEFAULT_POLICY_NOT_TRUE"); ok = False
print("BOOTSTRAP_ROLE_BINDING_OK" if ok else "BOOTSTRAP_ROLE_BINDING_FAIL")
raise SystemExit(0 if ok else 1)
PY

# Sanity: the SA the role binds exists in-cluster (GitOps-applied via the operator release).
if kubectl -n vault-config-operator get serviceaccount vault-config-operator-vault >/dev/null 2>&1; then
  echo "VAULT_AUTH_SA_PRESENT_OK"
else
  echo "WARN: vault-config-operator-vault SA not found yet (apply the operator release first)"
fi

self_revoke_admin_token
echo "SEED_COMPLETE_OK"
