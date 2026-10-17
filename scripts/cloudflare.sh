#!/usr/bin/env bash
# Gated Terraform driver for terraform/cloudflare (the GitLab and Keycloak edges).
#   plan    voids any earlier accepted plan, writes a candidate plan, proves
#           that every tunnel, DNS record and Secret it would create is absent
#           and bound to the right planned tunnel, and only then publishes it
#           as .state/terraform/cloudflare.tfplan (0600).
#   apply   repeats that proof against the saved plan, applies exactly that
#           plan (CONFIRM_REBUILD required), proves convergence (an empty second
#           plan) and waits for both in-cluster connectors (cloudflared/
#           cloudflared-gitlab, keycloak/cloudflared) to roll out.
#   verify  proves both public paths work end to end: each hostname resolves
#           through DNS-over-HTTPS to Cloudflare, each tunnel is healthy, and
#           GitLab's OpenID discovery document and JWKS (what AWS IAM needs) and
#           Keycloak's realm discovery document are served through them with
#           the expected issuers.
# Credentials travel only in the environment and through a pipe into curl's
# configuration; this script never writes a token to an argument or a log.
# Every terraform and curl command runs under a constructed environment.
# jq filters take their values through --arg, so $v inside single quotes is a jq variable.
# shellcheck disable=SC2016
set +x  # inherited xtrace would print the token; nothing below may re-enable it
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

# The root's bytes must be the committed, reviewed bytes, decided FIRST — before any state cleanup,
# command lookup or credential is touched. git answers all of it: nothing modified, type-changed or
# deleted among the tracked files; nothing untracked, and nothing ignored either (the repository's
# .gitignore denies by default, so a stray override.tf, *.tfvars or extra .tf would be invisible to a
# plain status) except Terraform's own data directory; and the tracked set equal to the reviewed
# list. Names are compared NUL-delimited, so a name with a newline cannot stand for two.
root_is_reviewed() {  # root_is_reviewed DIR NAME...   (DIR relative to the repository root)
    local dir="$1" entry name found expected status; shift
    expected="$(printf '%s\n' "$@" | sort)"
    status="$(git -C "${ROOT_DIR}" -c core.quotePath=false status --porcelain=v1 -z --ignored=matching --untracked-files=all -- "${dir}" | tr '\0' '\n')" \
        || { echo "ERROR: git could not report the state of ${dir}" >&2; exit 1; }
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        [[ "${entry}" == "!! ${dir}/.terraform/" ]] && continue
        echo "ERROR: ${dir} is not the committed, reviewed tree: ${entry} (commit, remove or inspect it before planning)" >&2
        exit 1
    done <<<"${status}"
    found="$(git -C "${ROOT_DIR}" -c core.quotePath=false ls-files -z -- "${dir}" | tr '\0' '\n' | sed "s|^${dir}/||" | sort)"
    [[ "${found}" == "${expected}" ]] || {
        echo "ERROR: ${dir} must track exactly these reviewed files: $* (tracked: $(printf '%s' "${found}" | tr '\n' ' '))" >&2
        exit 1
    }
    for name in "$@"; do
        [[ -f "${ROOT_DIR}/${dir}/${name}" && ! -L "${ROOT_DIR}/${dir}/${name}" ]] \
            || { echo "ERROR: ${dir}/${name} is not a regular file" >&2; exit 1; }
    done
}
root_is_reviewed terraform/cloudflare .terraform.lock.hcl backend.tf keycloak.tf main.tf outputs.tf providers.tf variables.tf versions.tf

STATE_ROOT="$(readlink -f "${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}")"  # absolute: Terraform receives the kubeconfig path
TF_DIR="${ROOT_DIR}/terraform/cloudflare"
PLAN_DIR="${STATE_ROOT}/terraform"
PLAN_FILE="${PLAN_DIR}/cloudflare.tfplan"
API="https://api.cloudflare.com/client/v4"
DOH="https://cloudflare-dns.com/dns-query"
umask 077
install -d -m 0700 "${PLAN_DIR}"
command -v flock >/dev/null || { echo "ERROR: flock is required" >&2; exit 1; }
exec 9> "${PLAN_DIR}/.cloudflare.lock"
flock -n 9 || { echo "ERROR: another cloudflare plan or apply holds ${PLAN_DIR}/.cloudflare.lock" >&2; exit 1; }
CANDIDATE=""
rm -rf "${PLAN_DIR}"/cfrun.*
if [[ "${1:-}" == plan ]]; then
    rm -f "${PLAN_FILE}" "${PLAN_DIR}"/cloudflare.tfplan.candidate.*
fi

for command in terraform curl jq kubectl; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done
KUBECONFIG_FILE="${STATE_ROOT}/configs/kubeconfig"
[[ -f "${KUBECONFIG_FILE}" ]] || { echo "ERROR: kubeconfig not found: ${KUBECONFIG_FILE}" >&2; exit 1; }
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN (Cloudflare Tunnel: Edit, DNS: Edit, Zone: Read)}"
: "${AWS_PROFILE:?set AWS_PROFILE (profile that can read and write the Terraform state bucket)}"
[[ "${AWS_PROFILE}" == "mgmt-admin" ]] || { echo "ERROR: AWS_PROFILE must be mgmt-admin (the state bucket's account)" >&2; exit 1; }

tf_default() {  # tf_default VARIABLE
    awk -v v="$1" '$0 ~ "^variable \""v"\"" {f=1} f && /^  default *=/ {gsub(/.*= *"|"$/, ""); print; exit}' "${TF_DIR}/variables.tf"
}
ACCOUNT_TF="$(tf_default cloudflare_account_id)"
ZONE_TF="$(tf_default zone)"
HOST_TF="$(tf_default gitlab_host)"
TUNNEL_TF="$(tf_default gitlab_tunnel_name)"
KC_HOST_TF="$(tf_default keycloak_host)"
KC_TUNNEL_TF="$(tf_default keycloak_tunnel_name)"
[[ -n "${ACCOUNT_TF}" && -n "${ZONE_TF}" && -n "${HOST_TF}" && -n "${TUNNEL_TF}" && -n "${KC_HOST_TF}" && -n "${KC_TUNNEL_TF}" ]] || { echo "ERROR: could not read variable defaults" >&2; exit 1; }
[[ "${HOST_TF}" != "${KC_HOST_TF}" && "${TUNNEL_TF}" != "${KC_TUNNEL_TF}" ]] || { echo "ERROR: the GitLab and Keycloak hostnames and tunnel names must differ" >&2; exit 1; }
# Each tunnel serves exactly one hostname: host_for_tunnel NAME prints it (empty = not a reviewed tunnel).
host_for_tunnel() { case "$1" in "${TUNNEL_TF}") printf '%s' "${HOST_TF}" ;; "${KC_TUNNEL_TF}") printf '%s' "${KC_HOST_TF}" ;; esac; }
tunnel_for_host() { case "$1" in "${HOST_TF}") printf '%s' "${TUNNEL_TF}" ;; "${KC_HOST_TF}") printf '%s' "${KC_TUNNEL_TF}" ;; esac; }

tf() {
    env -i \
        HOME="${HOME}" PATH="${PATH}" LANG=C.UTF-8 \
        AWS_PROFILE="${AWS_PROFILE}" CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN}" \
        ${TF_PLUGIN_CACHE_DIR:+TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR}"} \
        TF_IN_AUTOMATION=1 \
        TF_VAR_kubeconfig="${KUBECONFIG_FILE}" \
        terraform -chdir="${TF_DIR}" "$@"
}
clean() { env -i HOME="${HOME}" PATH="${PATH}" LANG=C.UTF-8 "$@"; }
kc() { clean KUBECONFIG="${KUBECONFIG_FILE}" kubectl "$@"; }

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

RUN_DIR="$(mktemp -d "${PLAN_DIR}/cfrun.XXXXXX")"
BODY="${RUN_DIR}/body"
ERR="${RUN_DIR}/err"
cleanup() {
    rm -rf "${RUN_DIR:?}"
    [[ -n "${CANDIDATE}" ]] && rm -f "${CANDIDATE}"
    return 0
}
trap cleanup EXIT
# cf PATH: authenticated Cloudflare API GET; prints the HTTP status, body in ${BODY}.
cf() {
    printf 'header = "Authorization: Bearer %s"\n' "${CLOUDFLARE_API_TOKEN}" \
        | clean curl --disable -sS --connect-timeout 10 --max-time 30 -K - \
            -o "${BODY}" -w '%{http_code}' "${API}$1" 2>/dev/null || printf '000'
}
# cf_list PATH LABEL: a successful listing with an array result; prints its length.
cf_list() {
    [[ "$(cf "$1")" == "200" ]] || { echo "ERROR: cannot read $2 (${API}${1%%\?*})" >&2; exit 1; }
    decide "$2 (shape)" '.success == true and (.result | type) == "array"' < "${BODY}" \
        || { echo "ERROR: $2 has an unexpected shape (cannot decide presence)" >&2; exit 1; }
    jq '.result | length' "${BODY}"
}

# k8s_absent KIND NAME NAMESPACE: only a positive NotFound is absence (as in scripts/gitlab-vault.sh).
k8s_absent() {
    if kc get "$1" "$2" -n "$3" -o name >/dev/null 2>"${ERR}"; then
        return 1
    elif grep -q 'NotFound' "${ERR}"; then
        return 0
    fi
    echo "ERROR: kubectl could not decide whether $1 $3/$2 exists: $(tr '\n' ' ' < "${ERR}")" >&2; exit 1
}

ZONE_ID=""
preflight_access() {
    [[ "$(cf /user/tokens/verify)" == "200" ]] || { echo "ERROR: CLOUDFLARE_API_TOKEN is not accepted" >&2; exit 1; }
    decide "token" '.success == true and .result.status == "active"' < "${BODY}" || { echo "ERROR: CLOUDFLARE_API_TOKEN is not active" >&2; exit 1; }
    [[ "$(cf_list "/zones?name=$(enc "${ZONE_TF}")" "zone listing")" == "1" ]] || { echo "ERROR: zone ${ZONE_TF} is not exactly one zone the token can read" >&2; exit 1; }
    decide "zone account" --arg a "${ACCOUNT_TF}" '.result[0].account.id == $a and .result[0].status == "active"' < "${BODY}" \
        || { echo "ERROR: zone ${ZONE_TF} is not active in account ${ACCOUNT_TF}" >&2; exit 1; }
    ZONE_ID="$(jq -r '.result[0].id' "${BODY}")"
    [[ "${ZONE_ID}" =~ ^[0-9a-f]{32}$ ]] || { echo "ERROR: zone id has an unexpected form" >&2; exit 1; }
    local server
    server="$(kc config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
    [[ "${server}" == "${CLUSTER_ENDPOINT}" ]] || { echo "ERROR: kubeconfig server ${server:-missing} is not ${CLUSTER_ENDPOINT}" >&2; exit 1; }
}

# preflight_creates PLAN: every planned create must target the account, zone,
# one of the two reviewed hostnames and one of the two reviewed tunnel names
# (read from the plan's own known values, so a variable file or an extra .tf
# cannot redirect it); each tunnel must be absent by name, each DNS record by
# name, the connector Secret by name; a tunnel configuration is accepted only
# when its tunnel_id is unknown and references a tunnel the same plan creates
# and its single hostname rule names that tunnel's hostname; a record's content
# must be unknown and reference its hostname's tunnel; anything else aborts.
preflight_creates() {
    local creates n i type address name conflicts=() tunnel_addr refs tunnel_name host ns
    creates="$(tf show -json "$1" | jq -c '
        .resource_changes
        | if type != "array" then error("resource_changes is not an array") else . end
        | map(if type != "object" or (.address | type) != "string" or (.type | type) != "string"
                 or (.change | type) != "object" or (.change.actions | type) != "array"
              then error("malformed resource_changes entry") else . end)
        | map(if (.change.actions | index("create")) != null and .change.actions != ["create"]
              then error("replacement is not a create: " + .address + " (apply replacements deliberately with terraform itself)") else . end)
        | [ .[] | select(.change.actions == ["create"])
            | { address, type, after: (.change.after | { name, account_id, zone_id, type, proxied, config_src, tunnel_id, content, config, metadata }),
                unknown: (.change.after_unknown | { tunnel_id, content }) } ]')" \
        || { echo "ERROR: could not read the planned creates from the candidate plan" >&2; exit 1; }
    n="$(jq 'length' <<<"${creates}")"
    # known FIELD: the planned value, which must be a non-empty string (unknown or absent aborts).
    known() {
        local v
        v="$(jq -r --argjson i "${i}" "if (.[\$i].after.$1 | type) == \"string\" and (.[\$i].after.$1 | length) > 0 then .[\$i].after.$1 else empty end" <<<"${creates}")"
        [[ -n "${v}" ]] || { echo "ERROR: ${address}: $1 is not a known value in the plan (cannot decide)" >&2; exit 1; }
        printf '%s' "${v}"
    }
    for (( i = 0; i < n; i++ )); do
        type="$(jq -r --argjson i "${i}" '.[$i].type' <<<"${creates}")"
        address="$(jq -r --argjson i "${i}" '.[$i].address' <<<"${creates}")"
        case "${type}" in
            cloudflare_zero_trust_tunnel_cloudflared)
                name="$(known name)"
                [[ "$(known account_id)" == "${ACCOUNT_TF}" ]] || { echo "ERROR: ${address}: planned account is not ${ACCOUNT_TF}" >&2; exit 1; }
                [[ -n "$(host_for_tunnel "${name}")" ]] || { echo "ERROR: ${address}: planned tunnel name ${name} is neither ${TUNNEL_TF} nor ${KC_TUNNEL_TF}" >&2; exit 1; }
                [[ "$(known config_src)" == "cloudflare" ]] || { echo "ERROR: ${address}: the tunnel must be remotely configured (config_src = cloudflare)" >&2; exit 1; }
                [[ "$(cf_list "/accounts/${ACCOUNT_TF}/cfd_tunnel?is_deleted=false&name=$(enc "${name}")" "tunnel listing")" == "0" ]] \
                    || conflicts+=("tunnel ${name} (import: ${address} ${ACCOUNT_TF}/<tunnel id>)") ;;
            cloudflare_zero_trust_tunnel_cloudflared_config)
                [[ "$(known account_id)" == "${ACCOUNT_TF}" ]] || { echo "ERROR: ${address}: planned account is not ${ACCOUNT_TF}" >&2; exit 1; }
                # Binding is semantic, not syntactic: the planned tunnel_id must be UNKNOWN (it
                # can only come from a tunnel this plan creates) and the expression must
                # reference exactly one planned tunnel; a known constant — however the
                # expression is written — targets an existing tunnel and is refused.
                decide "config tunnel_id unknown" --argjson i "${i}" '.[$i].unknown.tunnel_id == true and .[$i].after.tunnel_id == null' <<<"${creates}" \
                    || { echo "ERROR: ${address}: tunnel_id is a known value in the plan; it must be the id of a tunnel this plan creates" >&2; exit 1; }
                refs="$(tf show -json "$1" | jq -r --arg a "${address}" '
                    [.configuration.root_module.resources[]? | select(.address == $a) | .expressions.tunnel_id.references[]?] | join(" ")' 2>/dev/null || true)"
                tunnel_addr="$(jq -r --arg r " ${refs} " '[.[] | select(.type == "cloudflare_zero_trust_tunnel_cloudflared") | .address | . as $a | select(($r | contains(" " + $a + ".id ")) or ($r | contains(" " + $a + " ")))] | if length == 1 then .[0] else "" end' <<<"${creates}")"
                [[ -n "${tunnel_addr}" ]] || { echo "ERROR: ${address}: tunnel_id does not reference exactly one tunnel this plan creates (references: ${refs:-none}); import the tunnel first" >&2; exit 1; }
                tunnel_name="$(jq -r --arg a "${tunnel_addr}" '[.[] | select(.address == $a) | .after.name][0]' <<<"${creates}")"
                host="$(host_for_tunnel "${tunnel_name}")"
                # Exactly two ingress rules: the tunnel's own hostname, then the catch-all.
                decide "config ingress" --argjson i "${i}" --arg h "${host}" '(.[$i].after.config.ingress | type) == "array" and (.[$i].after.config.ingress | length) == 2
                    and .[$i].after.config.ingress[0].hostname == $h and (.[$i].after.config.ingress[1].hostname // null) == null and .[$i].after.config.ingress[1].service == "http_status:404"' <<<"${creates}" \
                    || { echo "ERROR: ${address}: the ingress rules must be exactly [${host}, catch-all 404] for tunnel ${tunnel_name}" >&2; exit 1; } ;;
            cloudflare_dns_record)
                name="$(known name)"
                [[ "$(known zone_id)" == "${ZONE_ID}" ]] || { echo "ERROR: ${address}: planned zone is not ${ZONE_TF} (${ZONE_ID})" >&2; exit 1; }
                tunnel_name="$(tunnel_for_host "${name}")"
                [[ -n "${tunnel_name}" ]] || { echo "ERROR: ${address}: planned record name ${name} is neither ${HOST_TF} nor ${KC_HOST_TF}" >&2; exit 1; }
                [[ "$(known type)" == "CNAME" ]] || { echo "ERROR: ${address}: planned record is not a CNAME" >&2; exit 1; }
                decide "record proxied" --argjson i "${i}" '.[$i].after.proxied == true' <<<"${creates}" || { echo "ERROR: ${address}: planned record is not proxied" >&2; exit 1; }
                # The record's content is <tunnel id>.cfargotunnel.com, unknown until the tunnel
                # exists; a known content points somewhere else.
                decide "record content unknown" --argjson i "${i}" '.[$i].unknown.content == true and .[$i].after.content == null' <<<"${creates}" \
                    || { echo "ERROR: ${address}: planned record content is a known value; it must derive from the tunnel this plan creates" >&2; exit 1; }
                # ... and from the tunnel that serves this hostname, which the same plan must create.
                tunnel_addr="$(jq -r --arg t "${tunnel_name}" '[.[] | select(.type == "cloudflare_zero_trust_tunnel_cloudflared" and .after.name == $t) | .address] | if length == 1 then .[0] else "" end' <<<"${creates}")"
                [[ -n "${tunnel_addr}" ]] || { echo "ERROR: ${address}: record for ${name} but this plan does not create tunnel ${tunnel_name}; import the tunnel first" >&2; exit 1; }
                refs="$(tf show -json "$1" | jq -r --arg a "${address}" '
                    [.configuration.root_module.resources[]? | select(.address == $a) | .expressions.content.references[]?] | join(" ")' 2>/dev/null || true)"
                [[ " ${refs} " == *" ${tunnel_addr}.id "* || " ${refs} " == *" ${tunnel_addr} "* ]] \
                    || { echo "ERROR: ${address}: content does not reference ${tunnel_addr} (references: ${refs:-none})" >&2; exit 1; }
                [[ "$(cf_list "/zones/${ZONE_ID}/dns_records?name=$(enc "${name}")" "DNS record listing")" == "0" ]] \
                    || conflicts+=("DNS record ${name} (import: ${address} ${ZONE_ID}/<record id>)") ;;
            kubernetes_secret_v1)
                name="$(known 'metadata[0].name')"; ns="$(known 'metadata[0].namespace')"
                [[ "${ns}/${name}" == "keycloak/cloudflared-keycloak" || "${ns}/${name}" == "cloudflared/cloudflared-gitlab" ]] || { echo "ERROR: ${address}: the only Secrets this root may create are keycloak/cloudflared-keycloak and cloudflared/cloudflared-gitlab (planned ${ns}/${name})" >&2; exit 1; }
                k8s_absent secret "${name}" "${ns}" || conflicts+=("Kubernetes Secret ${ns}/${name} (import: ${address} ${ns}/${name})") ;;
            *)
                echo "ERROR: the preflight has no rule for resource type ${type} (${address}); add one to scripts/cloudflare.sh before planning this change" >&2; exit 1 ;;
        esac
    done
    if (( ${#conflicts[@]} > 0 )); then
        echo "ERROR: the plan would create these objects, but they already exist outside Terraform; import or replace them first:" >&2
        printf '  - %s\n' "${conflicts[@]}" >&2
        exit 1
    fi
    echo "Preflight: all ${n} planned creates are for objects that do not exist yet."
}

tunnel_status() {  # tunnel_status NAME: prints the status of the one tunnel with that name
    [[ "$(cf_list "/accounts/${ACCOUNT_TF}/cfd_tunnel?is_deleted=false&name=$(enc "$1")" "tunnel listing")" == "1" ]] \
        || { echo "ERROR: tunnel $1 is not exactly one tunnel" >&2; exit 1; }
    jq -r 'if (.result[0].status | type) == "string" then .result[0].status else "unknown" end' "${BODY}"
}

case "${1:-}" in
    plan)
        tf init -input=false -lockfile=readonly >/dev/null
        preflight_access
        CANDIDATE="$(mktemp "${PLAN_DIR}/cloudflare.tfplan.candidate.XXXXXX")"
        tf plan -input=false -out="${CANDIDATE}"
        chmod 0600 "${CANDIDATE}"
        preflight_creates "${CANDIDATE}"
        mv -T "${CANDIDATE}" "${PLAN_FILE}"
        echo "Plan saved to ${PLAN_FILE} (sensitive; deleted after a successful apply)."
        echo "Review it above, then: CONFIRM_REBUILD=TDNHQ-TALCL01 make cloudflare"
        ;;
    apply)
        [[ "${CONFIRM_REBUILD:-}" == "TDNHQ-TALCL01" ]] || { echo "ERROR: set CONFIRM_REBUILD=TDNHQ-TALCL01 to apply the saved plan" >&2; exit 1; }
        [[ -f "${PLAN_FILE}" ]] || { echo "ERROR: no saved plan; run make cloudflare-plan first" >&2; exit 1; }
        tf init -input=false -lockfile=readonly >/dev/null
        preflight_access
        preflight_creates "${PLAN_FILE}"
        tf apply -input=false "${PLAN_FILE}"
        rm -f "${PLAN_FILE}"
        if ! tf plan -input=false -detailed-exitcode >/dev/null; then
            echo "ERROR: the configuration did not converge; run make cloudflare-plan and review" >&2
            exit 1
        fi
        echo "Converged: a second plan proposes no changes."
        # Both connectors run in the cluster from the Secrets this apply wrote; they must come up.
        kc -n cloudflared rollout status deployment/cloudflared-gitlab --timeout=180s \
            || { echo "ERROR: the in-cluster GitLab connector did not become available (is platform/cloudflared applied?)" >&2; exit 1; }
        echo "GitLab connector rolled out. Tunnel status: $(tunnel_status "${TUNNEL_TF}")."
        # The Keycloak connector runs in the cluster from the Secret this apply wrote; it must come up.
        kc -n keycloak rollout status deployment/cloudflared --timeout=180s \
            || { echo "ERROR: the in-cluster Keycloak connector did not become available (is platform/keycloak applied?)" >&2; exit 1; }
        echo "Keycloak connector rolled out. Tunnel status: $(tunnel_status "${KC_TUNNEL_TF}")."
        echo "Then prove the public paths: make cloudflare-verify (after make keycloak for the Keycloak realm)"
        ;;
    verify)
        preflight_access
        # public_edge HOST: resolves HOST through DNS-over-HTTPS (the site resolver answers these
        # names with LAN addresses, which is not the path the Internet takes) and prints the edge IP.
        public_edge() {
            clean curl --disable -sS --connect-timeout 10 --max-time 30 -H 'accept: application/dns-json' \
                -o "${BODY}" "${DOH}?name=$(enc "$1")&type=A" < /dev/null || { echo "ERROR: DNS-over-HTTPS lookup of $1 failed" >&2; exit 1; }
            decide "public answer for $1" '.Status == 0 and (.Answer | type) == "array" and any(.Answer[]; .type == 1 and (.data | type) == "string")' < "${BODY}" \
                || { echo "ERROR: $1 has no public A answer (the proxied record is missing or not yet live)" >&2; exit 1; }
            local e
            e="$(jq -r '[.Answer[] | select(.type == 1) | .data][0]' "${BODY}")"
            [[ "${e}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "ERROR: public answer for $1 is not an IPv4 address" >&2; exit 1; }
            [[ "${e}" != 10.* ]] || { echo "ERROR: the public answer for $1 is a private address (${e}); the record is not proxied" >&2; exit 1; }
            printf '%s' "${e}"
        }
        status="$(tunnel_status "${TUNNEL_TF}")"
        [[ "${status}" == "healthy" ]] || { echo "ERROR: tunnel ${TUNNEL_TF} is '${status}', not healthy (is the cloudflared-gitlab Deployment in cloudflared running?)" >&2; exit 1; }
        edge="$(public_edge "${HOST_TF}")"
        clean curl --disable -sS --connect-timeout 10 --max-time 30 --resolve "${HOST_TF}:443:${edge}" \
            -o "${BODY}" "https://${HOST_TF}/.well-known/openid-configuration" < /dev/null || { echo "ERROR: discovery document unreachable through Cloudflare (${edge})" >&2; exit 1; }
        decide "discovery document" --arg i "https://${HOST_TF}" '.issuer == $i and .jwks_uri == ($i + "/oauth/discovery/keys")' < "${BODY}" \
            || { echo "ERROR: discovery document does not name https://${HOST_TF} as issuer" >&2; exit 1; }
        clean curl --disable -sS --connect-timeout 10 --max-time 30 --resolve "${HOST_TF}:443:${edge}" \
            -o "${BODY}" "https://${HOST_TF}/oauth/discovery/keys" < /dev/null || { echo "ERROR: JWKS unreachable through Cloudflare" >&2; exit 1; }
        decide "JWKS" '(.keys | type) == "array" and (.keys | length) > 0 and all(.keys[]; .kty == "RSA" and (.kid | type) == "string")' < "${BODY}" \
            || { echo "ERROR: JWKS has an unexpected shape" >&2; exit 1; }
        echo "Public path verified: ${HOST_TF} -> Cloudflare ${edge} -> tunnel ${TUNNEL_TF} (healthy); issuer and JWKS served. AWS IAM can read them."
        status="$(tunnel_status "${KC_TUNNEL_TF}")"
        [[ "${status}" == "healthy" ]] || { echo "ERROR: tunnel ${KC_TUNNEL_TF} is '${status}', not healthy (is the cloudflared Deployment in keycloak running?)" >&2; exit 1; }
        edge="$(public_edge "${KC_HOST_TF}")"
        clean curl --disable -sS --connect-timeout 10 --max-time 30 --resolve "${KC_HOST_TF}:443:${edge}" \
            -o "${BODY}" "https://${KC_HOST_TF}/realms/tcn/.well-known/openid-configuration" < /dev/null || { echo "ERROR: Keycloak realm discovery unreachable through Cloudflare (${edge}); run make keycloak first" >&2; exit 1; }
        decide "Keycloak discovery document" --arg i "https://${KC_HOST_TF}/realms/tcn" '.issuer == $i and (.jwks_uri | type) == "string" and (.jwks_uri | startswith($i + "/"))' < "${BODY}" \
            || { echo "ERROR: Keycloak discovery document does not name https://${KC_HOST_TF}/realms/tcn as issuer (hostname fixed to port 443?)" >&2; exit 1; }
        echo "Public path verified: ${KC_HOST_TF} -> Cloudflare ${edge} -> tunnel ${KC_TUNNEL_TF} (healthy); realm tcn discovery served with the expected issuer."
        ;;
    *)
        echo "usage: $0 plan|apply|verify" >&2
        exit 2 ;;
esac
