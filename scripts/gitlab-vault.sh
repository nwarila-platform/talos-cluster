#!/usr/bin/env bash
# Gated Terraform driver for terraform/gitlab-vault.
#   plan    discards any earlier accepted plan, writes a candidate plan under a
#           unique name, proves that every object it would create is absent
#           (directly, or because its container is created by the same plan),
#           and only then publishes it as .state/terraform/gitlab-vault.tfplan
#           (0600). On any other exit the shell can handle, the candidate is
#           removed and conflicting objects are listed with import ids. A kill
#           (SIGKILL, power loss) leaves one of three states: before the old
#           plan was voided, that old plan (it passed its own checks); between
#           voiding and publication, nothing applyable and at most one
#           candidate (the next run removes it); after publication, the new,
#           checked plan. Inspect the plan directory after any killed run.
#           A plan that REPLACES an object (delete+create) is refused: this
#           guard proves absence for pure creates only.
# One run at a time: plan and apply hold a lock in the plan directory.
#   apply   applies exactly that saved plan (CONFIRM_REBUILD required), then
#           proves convergence (an empty second plan) and that the runner's token
#           does not expire and the runner is online.
# Every terraform command runs under a constructed environment: only the named
# credentials and a few safe variables are passed, so ambient AWS keys, TF_VAR_*,
# TF_CLI_ARGS*, Vault overrides and provider logging cannot change what is applied.
# jq filters below take their values through --arg, so $name inside single quotes is a jq variable.
# shellcheck disable=SC2016
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
TF_DIR="${ROOT_DIR}/terraform/gitlab-vault"
PLAN_DIR="${STATE_ROOT}/terraform"
PLAN_FILE="${PLAN_DIR}/gitlab-vault.tfplan"
GITLAB_CA="${STATE_ROOT}/gitlab/ca.crt"
VAULT_CA="${STATE_ROOT}/vault/tls/ca.crt"
KUBECONFIG_FILE="${STATE_ROOT}/configs/kubeconfig"
umask 077
install -d -m 0700 "${PLAN_DIR}"
command -v flock >/dev/null || { echo "ERROR: flock is required" >&2; exit 1; }
# plan and apply are serialized: a plan may not void or replace the accepted
# plan while another run is checking or applying it.
exec 9> "${PLAN_DIR}/.lock"
flock -n 9 || { echo "ERROR: another gitlab-vault plan or apply holds ${PLAN_DIR}/.lock" >&2; exit 1; }
CANDIDATE=""  # this run's candidate plan, created just before terraform plan; never applyable
if [[ "${1:-}" == plan ]]; then
    # A plan attempt voids any earlier accepted plan, and any candidate a killed
    # run left behind, before anything else can fail.
    rm -f "${PLAN_FILE}" "${PLAN_DIR}"/gitlab-vault.tfplan.candidate.*
fi

for command in terraform curl jq kubectl helm; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done
: "${GITLAB_TOKEN:?set GITLAB_TOKEN (administrator personal access token, scopes api and create_runner)}"
: "${VAULT_TOKEN:?set VAULT_TOKEN (administrative Vault token)}"
: "${AWS_PROFILE:?set AWS_PROFILE (profile that can read and write the Terraform state bucket)}"
[[ "${AWS_PROFILE}" == "mgmt-admin" ]] || { echo "ERROR: AWS_PROFILE must be mgmt-admin (the state bucket's account)" >&2; exit 1; }


# Addresses the root uses, read from its own variable defaults so the preflight
# and the plan cannot disagree.
tf_default() {  # tf_default VARIABLE
    awk -v v="$1" '$0 ~ "^variable \""v"\"" {f=1} f && /^  default *=/ {gsub(/.*= *"|"$/, ""); print; exit}' "${TF_DIR}/variables.tf"
}
GITLAB_URL_TF="$(tf_default gitlab_url)"
VAULT_ADDR_TF="$(tf_default vault_addr)"
[[ -n "${GITLAB_URL_TF}" && -n "${VAULT_ADDR_TF}" ]] || { echo "ERROR: could not read variable defaults" >&2; exit 1; }

# tf: terraform under an allow-list environment.
tf() {
    env -i \
        HOME="${HOME}" PATH="${PATH}" LANG=C.UTF-8 \
        AWS_PROFILE="${AWS_PROFILE}" GITLAB_TOKEN="${GITLAB_TOKEN}" VAULT_TOKEN="${VAULT_TOKEN}" \
        ${TF_PLUGIN_CACHE_DIR:+TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR}"} \
        TF_IN_AUTOMATION=1 \
        terraform -chdir="${TF_DIR}" "$@"
}

# Every discovery command runs under a constructed environment too, so proxies
# and ambient credentials cannot change what the preflight sees.
clean() { env -i HOME="${HOME}" PATH="${PATH}" LANG=C.UTF-8 "$@"; }

# Decisions are made only on literal answers. decide LABEL [JQ-ARGS...] FILTER
# reads JSON on stdin and returns 0 when FILTER yields exactly `true`, 1 on
# exactly `false`; anything else (parse error, null, wrong shape) is fatal, so a
# malformed answer can never be read as "absent".
decide() {
    local label="$1" filter="${*: -1}" out
    out="$(jq -r "${@:2:$#-2}" "${filter}" 2>/dev/null)" || out="(jq failed)"
    case "${out}" in
        true) return 0 ;;
        false) return 1 ;;
        *) echo "ERROR: cannot decide ${label}: ${out:-(no output)}" >&2; exit 1 ;;
    esac
}
enc() { jq -rn --arg s "$1" '$s | @uri'; }

# gl PATH: authenticated GitLab API GET; prints the HTTP status, body in ${BODY}.
# vg PATH: the same against the Vault HTTP API.
AUTH_FILE="$(mktemp)"
VAULT_AUTH_FILE="$(mktemp)"
BODY="$(mktemp)"
ERR="$(mktemp)"
cleanup() {
    rm -f "${AUTH_FILE:?}" "${VAULT_AUTH_FILE:?}" "${BODY:?}" "${ERR:?}"
    [[ -n "${CANDIDATE}" ]] && rm -f "${CANDIDATE}"
    return 0
}
trap cleanup EXIT
printf 'header = "PRIVATE-TOKEN: %s"\n' "${GITLAB_TOKEN}" > "${AUTH_FILE}"
printf 'header = "X-Vault-Token: %s"\n' "${VAULT_TOKEN}" > "${VAULT_AUTH_FILE}"
gl() {
    clean curl --disable -sS --connect-timeout 10 --max-time 30 --cacert "${GITLAB_CA}" -K "${AUTH_FILE}" \
        -o "${BODY}" -w '%{http_code}' "${GITLAB_URL_TF}/api/v4$1" 2>/dev/null || printf '000'
}
vg() {
    clean curl --disable -sS --connect-timeout 10 --max-time 30 --cacert "${VAULT_CA}" -K "${VAULT_AUTH_FILE}" \
        -o "${BODY}" -w '%{http_code}' "${VAULT_ADDR_TF}/v1$1" 2>/dev/null || printf '000'
}
# gl_absent PATH: true only on a positive 404; any other answer is fatal.
gl_absent() {
    local status
    status="$(gl "$1")"
    case "${status}" in
        404) return 0 ;;
        200) return 1 ;;
        *) echo "ERROR: GET $1 -> HTTP ${status} (cannot decide presence)" >&2; exit 1 ;;
    esac
}
# vault_absent PATH: true only on Vault's positive answer for a missing object
# under an existing mount (404 with an empty error list). A 404 that names
# "no handler for route" means the mount itself is gone although state says
# otherwise, so it is fatal like every other answer.
vault_absent() {
    local status
    status="$(vg "$1")"
    case "${status}" in
        200) return 1 ;;
        404) decide "GET $1" '.errors == []' < "${BODY}" && return 0
             echo "ERROR: GET $1 -> HTTP 404 with errors $(jq -c '.errors' "${BODY}") (cannot decide presence)" >&2; exit 1 ;;
        *) echo "ERROR: GET $1 -> HTTP ${status} (cannot decide presence)" >&2; exit 1 ;;
    esac
}
# vault_name_absent MOUNT issuers|keys FIELD NAME: PKI issuers and keys are
# found by name through the listing (404 with an empty error list = none).
vault_name_absent() {
    local status
    status="$(vg "/$1/$2?list=true")"
    case "${status}" in
        200) decide "$2 listing of $1 (shape)" --arg f "$3" \
                 '(.data | type) == "object" and (.data.key_info | type) == "object" and all(.data.key_info[]; type == "object" and (.[$f] | type) == "string")' < "${BODY}" \
                 || { echo "ERROR: LIST $1/$2 -> HTTP 200 with an unexpected shape (cannot decide presence)" >&2; exit 1; }
             ! decide "$2 listing of $1" --arg f "$3" --arg n "$4" 'any(.data.key_info[]; .[$f] == $n)' < "${BODY}" ;;
        404) decide "LIST $1/$2" '.errors == []' < "${BODY}" && return 0
             echo "ERROR: LIST $1/$2 -> HTTP 404 with errors $(jq -c '.errors' "${BODY}") (cannot decide presence)" >&2; exit 1 ;;
        *) echo "ERROR: LIST $1/$2 -> HTTP ${status} (cannot decide presence)" >&2; exit 1 ;;
    esac
}
# k8s_absent KIND NAME [NAMESPACE]: only a positive NotFound is absence.
k8s_absent() {
    local args=("$1" "$2")
    [[ -n "${3:-}" ]] && args+=(-n "$3")
    if clean KUBECONFIG="${KUBECONFIG_FILE}" kubectl get "${args[@]}" -o name >/dev/null 2>"${ERR}"; then
        return 1
    elif grep -q 'NotFound' "${ERR}"; then
        return 0
    fi
    echo "ERROR: kubectl could not decide whether $1 ${3:+$3/}$2 exists: $(tr '\n' ' ' < "${ERR}")" >&2; exit 1
}
# helm_absent NAME NAMESPACE: presence is read from a successful JSON listing;
# any failure of the listing is fatal.
helm_absent() {
    clean KUBECONFIG="${KUBECONFIG_FILE}" helm list --all -n "$2" --filter "^$1\$" -o json > "${BODY}" 2>"${ERR}" || {
        echo "ERROR: helm could not list releases in $2: $(tr '\n' ' ' < "${ERR}")" >&2; exit 1; }
    decide "helm listing of $2 (shape)" 'type == "array" and all(.[]; type == "object" and (.name | type) == "string" and (.namespace | type) == "string")' < "${BODY}" \
        || { echo "ERROR: helm list in $2 returned an unexpected shape (cannot decide presence)" >&2; exit 1; }
    ! decide "helm listing of $2" --arg n "$1" --arg ns "$2" 'any(.[]; .name == $n and .namespace == $ns)' < "${BODY}"
}
# runner_absent DESCRIPTION: scans every instance runner (paginated).
runner_absent() {
    local page=1 present=1
    while :; do
        [[ "$(gl "/runners/all?type=instance_type&per_page=100&page=${page}")" == "200" ]] || { echo "ERROR: cannot list runners" >&2; exit 1; }
        decide "runner listing (shape)" 'type == "array" and all(.[]; type == "object" and (.description | type) == "string")' < "${BODY}" \
            || { echo "ERROR: runner listing has an unexpected shape (cannot decide presence)" >&2; exit 1; }
        decide "runner listing" --arg d "$1" 'any(.[]; .description == $d)' < "${BODY}" && present=0
        decide "runner page size" 'length == 100' < "${BODY}" || break
        page=$(( page + 1 )); (( page <= 50 )) || { echo "ERROR: more than 5000 runners" >&2; exit 1; }
    done
    (( present == 0 )) && return 1
    return 0
}

# preflight_access: the credentials and files must work before anything is decided.
MOUNTS=""
AUTHS=""
preflight_access() {
    [[ -r "${GITLAB_CA}" ]] || { echo "ERROR: ${GITLAB_CA} missing (the GitLab server certificate)" >&2; exit 1; }
    [[ -r "${VAULT_CA}" && -r "${KUBECONFIG_FILE}" ]] || { echo "ERROR: ${VAULT_CA} or ${KUBECONFIG_FILE} missing" >&2; exit 1; }
    if ! { [[ "$(gl /user)" == "200" ]] && decide "GitLab /user" '.is_admin == true' < "${BODY}"; }; then
        echo "ERROR: GITLAB_TOKEN is not a working administrator token" >&2; exit 1
    fi
    # Vault answers both listings with the mounts under .data as "<path>/" keys.
    local inventory='(.data | type) == "object" and all(.data | keys[]; endswith("/")) and all(.data[]; type == "object")'
    [[ "$(vg /sys/mounts)" == "200" ]] || { echo "ERROR: VAULT_TOKEN cannot read sys/mounts at ${VAULT_ADDR_TF}" >&2; exit 1; }
    decide "sys/mounts (shape)" "${inventory}" < "${BODY}" || { echo "ERROR: sys/mounts has an unexpected shape" >&2; exit 1; }
    MOUNTS="$(jq -c '.data' "${BODY}")"
    [[ "$(vg /sys/auth)" == "200" ]] || { echo "ERROR: VAULT_TOKEN cannot read sys/auth" >&2; exit 1; }
    decide "sys/auth (shape)" "${inventory}" < "${BODY}" || { echo "ERROR: sys/auth has an unexpected shape" >&2; exit 1; }
    AUTHS="$(jq -c '.data' "${BODY}")"
}

# preflight_creates PLAN: every object the plan would CREATE must be proven
# absent remotely, either directly (a positive not-found from its API) or
# because the object that contains it (its mount, auth backend or namespace,
# or for a repository file and branch protection its project) is created by
# the same plan. A planned create for something that already exists is listed
# with its import id; any answer that cannot be decided, and any resource type
# without a rule here, aborts. The caller publishes the plan only on success.
preflight_creates() {
    local creates n i type address index backend name key branch ns pid conflicts=()
    creates="$(tf show -json "$1" | jq -c '
        .resource_changes
        | if type != "array" then error("resource_changes is not an array") else . end
        | map(if type != "object" or (.address | type) != "string" or (.type | type) != "string"
                 or (.change | type) != "object" or (.change.actions | type) != "array"
                 or any(.change.actions[]; type != "string")
                 or ((.change.after | type) != "object" and .change.after != null)
              then error("malformed resource_changes entry: " + (.address | tostring)) else . end)
        | map(if (.change.actions | index("create")) != null and .change.actions != ["create"]
              then error("replacement is not a create: " + .address + " " + (.change.actions | tojson)
                         + " (apply replacements deliberately with terraform itself, after review)") else . end)
        | [ .[] | select(.change.actions == ["create"])
            | if (.change.after | type) != "object" then error("create without attributes: " + .address) else . end
            | { address, type, index,
                after: (.change.after | { path, name, key, description, backend, issuer_name, key_name,
                                          role_name, file_path, branch, project, namespace, metadata }) } ]')" \
        || { echo "ERROR: could not read the planned creates from the candidate plan" >&2; exit 1; }
    n="$(jq 'length' <<<"${creates}")"
    f() { jq -r --argjson i "${i}" ".[\$i]$1 // \"\"" <<<"${creates}"; }
    # need PATH: the identity an absence probe is about; anything but a non-empty string aborts.
    need() {
        local v
        v="$(jq -r --argjson i "${i}" "if (.[\$i]$1 | type) == \"string\" and (.[\$i]$1 | length) > 0 then .[\$i]$1 else empty end" <<<"${creates}")"
        [[ -n "${v}" ]] || { echo "ERROR: ${address}: $1 is missing from the plan (cannot decide presence)" >&2; exit 1; }
        printf '%s' "${v}"
    }
    # planned TYPE CONDITION VALUE: true when the same plan creates an object of
    # TYPE for which CONDITION (over the create entry, with $v = VALUE) holds.
    planned() { decide "plan lookup of $1" --arg t "$1" --arg v "$3" "any(.[]; .type == \$t and ($2))" <<<"${creates}"; }
    conflict() { conflicts+=("$1"); }
    for (( i = 0; i < n; i++ )); do
        type="$(f .type)"; address="$(f .address)"; index="$(f .index)"
        backend="$(f .after.backend)"; name="$(f .after.name)"
        [[ -n "${type}" && -n "${address}" ]] || { echo "ERROR: a planned create has no address or type" >&2; exit 1; }
        case "${type}" in
            gitlab_user_runner)
                name="$(need .after.description)"
                runner_absent "${name}" || conflict "GitLab instance runner '${name}' (replace deliberately; a runner token cannot be imported)" ;;
            gitlab_instance_variable)
                name="$(need .after.key)"
                gl_absent "/admin/ci/variables/${name}" || conflict "GitLab instance variable ${name} (import: ${address} ${name})" ;;
            gitlab_group)
                name="$(need .after.path)"
                gl_absent "/groups/$(enc "${name}")" || conflict "GitLab group ${name} (import: ${address} <id>)" ;;
            gitlab_project)
                index="$(need .index)"; need .after.path >/dev/null
                gl_absent "/projects/$(enc "${index}")" || conflict "GitLab project ${index} (import: ${address} <id>)" ;;
            gitlab_repository_file|gitlab_branch_protection)
                index="$(need .index)"; branch="$(need .after.branch)"
                if [[ "${type}" == gitlab_repository_file ]]; then name="$(need .after.file_path)"; fi
                planned gitlab_project '.index == $v' "${index}" && continue
                pid="$(f .after.project)"
                [[ "${pid}" =~ ^[0-9]+$ ]] || { echo "ERROR: ${address}: project id unknown and the project is not being created (cannot decide)" >&2; exit 1; }
                if [[ "${type}" == gitlab_repository_file ]]; then
                    gl_absent "/projects/${pid}/repository/files/$(enc "${name}")?ref=$(enc "${branch}")" \
                        || conflict "File ${name} on ${branch} of project ${pid} (import: ${address} ${pid}:${branch}:${name})"
                else
                    gl_absent "/projects/${pid}/protected_branches/$(enc "${branch}")" \
                        || conflict "Protection of ${branch} on project ${pid} (import: ${address} ${pid}:${branch})"
                fi ;;
            vault_mount)
                name="$(need .after.path)"
                decide "sys/mounts" --arg k "${name}/" 'has($k)' <<<"${MOUNTS}" && conflict "Vault mount ${name}/ (import: ${address} ${name})" ;;
            vault_jwt_auth_backend)
                name="$(need .after.path)"
                decide "sys/auth" --arg k "${name}/" 'has($k)' <<<"${AUTHS}" && conflict "Vault auth ${name}/ (import: ${address} ${name})" ;;
            vault_policy)
                # Policies are global in Vault: nothing contains them, so the name
                # must be known now (it is derived from the project key, not its id).
                name="$(need .after.name)"
                vault_absent "/sys/policies/acl/${name}" || conflict "Vault policy ${name} (import: ${address} ${name})" ;;
            vault_jwt_auth_backend_role)
                name="$(need .after.role_name)"; backend="$(need .after.backend)"
                planned vault_jwt_auth_backend '.after.path == $v' "${backend}" && continue
                vault_absent "/auth/${backend}/role/${name}" || conflict "Vault role auth/${backend}/role/${name} (import: ${address} auth/${backend}/role/${name})" ;;
            vault_pki_secret_backend_root_cert|vault_pki_secret_backend_intermediate_cert_request|vault_pki_secret_backend_issuer|vault_pki_secret_backend_role)
                backend="$(need .after.backend)"
                case "${type}" in
                    vault_pki_secret_backend_root_cert) name="$(need .after.issuer_name)"; key="$(need .after.key_name)" ;;
                    vault_pki_secret_backend_intermediate_cert_request) key="$(need .after.key_name)" ;;
                    vault_pki_secret_backend_issuer) name="$(need .after.issuer_name)" ;;
                    vault_pki_secret_backend_role) name="$(need .after.name)" ;;
                esac
                planned vault_mount '.after.path == $v' "${backend}" && continue
                case "${type}" in
                    vault_pki_secret_backend_root_cert)
                        vault_name_absent "${backend}" issuers issuer_name "${name}" || conflict "Vault PKI issuer ${name} in ${backend} (a root certificate cannot be imported; remove it or use another mount)"
                        vault_name_absent "${backend}" keys key_name "${key}" || conflict "Vault PKI key ${key} in ${backend} (cannot be imported; remove it or use another mount)" ;;
                    vault_pki_secret_backend_intermediate_cert_request)
                        vault_name_absent "${backend}" keys key_name "${key}" || conflict "Vault PKI key ${key} in ${backend} (cannot be imported; remove it or use another mount)" ;;
                    vault_pki_secret_backend_issuer)
                        vault_name_absent "${backend}" issuers issuer_name "${name}" || conflict "Vault PKI issuer ${name} in ${backend} (import: ${address} ${backend}/issuer/<issuer_id>)" ;;
                    vault_pki_secret_backend_role)
                        vault_absent "/${backend}/roles/${name}" || conflict "Vault PKI role ${name} in ${backend} (import: ${address} ${backend}/roles/${name})" ;;
                esac ;;
            vault_pki_secret_backend_root_sign_intermediate|vault_pki_secret_backend_intermediate_set_signed|vault_pki_secret_backend_config_issuers)
                # Actions and a setting, not objects: signing issues a new serial
                # every time, importing a re-signed certificate adds a second
                # issuer, and config/issuers overwrites the default. They are safe
                # only inside a mount this same plan creates.
                backend="$(need .after.backend)"
                planned vault_mount '.after.path == $v' "${backend}" || {
                    echo "ERROR: ${address}: mount ${backend} already exists but this action is planned as a create; reconcile state with Vault first (README: Preflight)" >&2; exit 1; } ;;
            kubernetes_namespace_v1)
                name="$(need '.after.metadata[0].name')"
                k8s_absent namespace "${name}" || conflict "Kubernetes namespace ${name} (import: ${address} ${name})" ;;
            kubernetes_secret_v1|helm_release)
                if [[ "${type}" == kubernetes_secret_v1 ]]; then
                    name="$(need '.after.metadata[0].name')"; ns="$(need '.after.metadata[0].namespace')"
                else
                    name="$(need .after.name)"; ns="$(need .after.namespace)"
                fi
                planned kubernetes_namespace_v1 '.after.metadata[0].name == $v' "${ns}" && continue
                if [[ "${type}" == kubernetes_secret_v1 ]]; then
                    k8s_absent secret "${name}" "${ns}" || conflict "Kubernetes Secret ${ns}/${name} (import: ${address} ${ns}/${name})"
                else
                    helm_absent "${name}" "${ns}" || conflict "Helm release ${ns}/${name} (import: ${address} ${ns}/${name})"
                fi ;;
            *)
                echo "ERROR: the preflight has no rule for resource type ${type} (${address}); add one to scripts/gitlab-vault.sh before planning this change" >&2; exit 1 ;;
        esac
    done
    if (( ${#conflicts[@]} > 0 )); then
        echo "ERROR: the plan would create these objects, but they already exist outside Terraform; import or replace them first (README: Preflight):" >&2
        printf '  - %s\n' "${conflicts[@]}" >&2
        exit 1
    fi
    echo "Preflight: all ${n} planned creates are for objects that do not exist yet."
}

case "${1:-}" in
    plan)
        tf init -input=false -lockfile=readonly >/dev/null
        preflight_access
        CANDIDATE="$(mktemp "${PLAN_DIR}/gitlab-vault.tfplan.candidate.XXXXXX")"
        tf plan -input=false -out="${CANDIDATE}"
        chmod 0600 "${CANDIDATE}"
        preflight_creates "${CANDIDATE}"
        mv -T "${CANDIDATE}" "${PLAN_FILE}"
        echo "Plan saved to ${PLAN_FILE} (sensitive; deleted after a successful apply)."
        echo "Review it above, then: CONFIRM_REBUILD=TDNHQ-TALCL01 make gitlab-vault"
        ;;
    apply)
        [[ "${CONFIRM_REBUILD:-}" == "TDNHQ-TALCL01" ]] || {
            echo "ERROR: set CONFIRM_REBUILD=TDNHQ-TALCL01 to apply the saved plan" >&2; exit 1; }
        [[ -f "${PLAN_FILE}" ]] || { echo "ERROR: no saved plan; run make gitlab-vault-plan first" >&2; exit 1; }
        tf init -input=false -lockfile=readonly >/dev/null
        # Terraform refuses a plan saved against an older state. On failure the
        # plan is kept for diagnosis; delete it yourself before re-planning.
        tf apply -input=false "${PLAN_FILE}"
        rm -f "${PLAN_FILE}"

        if ! tf plan -input=false -detailed-exitcode >/dev/null; then
            echo "ERROR: the configuration did not converge; run make gitlab-vault-plan and review" >&2
            exit 1
        fi
        echo "Converged: a second plan proposes no changes."

        runner_id="$(tf output -raw runner_id)"
        [[ "${runner_id}" =~ ^[0-9]+$ ]] || { echo "ERROR: runner_id output is not numeric" >&2; exit 1; }
        status="$(gl "/runners/${runner_id}")"
        [[ "${status}" == "200" ]] || { echo "ERROR: GET /runners/${runner_id} -> HTTP ${status}" >&2; exit 1; }
        jq -e 'type == "object" and has("token_expires_at") and .token_expires_at == null' "${BODY}" >/dev/null 2>&1 || {
            echo "ERROR: runner ${runner_id} has an expiring token (or an unexpected response); disable runner token expiration in GitLab and replace the runner" >&2
            exit 1
        }
        echo "Runner ${runner_id}: token does not expire."
        deadline=$(( SECONDS + 180 ))
        while :; do
            status="$(gl "/runners/${runner_id}")"
            runner_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "${BODY}" 2>/dev/null || true)"
            [[ "${status}" == "200" && "${runner_status}" == "online" ]] && break
            (( SECONDS < deadline )) || { echo "ERROR: runner ${runner_id} is '${runner_status:-unknown}' after 180s; check the gitlab-runner pod" >&2; exit 1; }
            sleep 10
        done
        echo "Runner ${runner_id} is online."
        echo "GitLab, Vault and the runner are reconciled. Seed a credential with: GITLAB_PROJECT_ID=<id> make vault-seed-aws"
        ;;
    *)
        echo "usage: $0 plan|apply" >&2
        exit 2 ;;
esac
