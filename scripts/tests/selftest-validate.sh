#!/usr/bin/env bash
# Mutation self-test for scripts/validate.sh and its checkers. A throwaway overlay of the working tree
# (tracked plus untracked, non-ignored files, as a commit would hold them) must validate cleanly; then
# each guarded property is broken one at a time and the FULL validator must fail with the guard's own
# message: vendored-byte checksum, chart references by digest, installer bypass, the exact LDAP mapper
# set, Kerberos off, unknown CR fields, wrong CR types, an unserved CR version. The checker-level
# mutants (absent or ambiguous CRD schema, a missing required document, cluster-scoped grants beyond
# the accepted ones) run the checkers directly against the renders the baseline produced. CEL rules
# are not evaluated offline: one case shows a CEL-violating Cluster is LISTED as deferred to the live
# server-side dry-run rather than silently passed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"
command -v git >/dev/null || { echo "ERROR: git is required" >&2; exit 1; }
git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "ERROR: ${ROOT_DIR} is not a git checkout" >&2; exit 1; }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "${TEST_ROOT:?}"' EXIT
OVERLAY="${TEST_ROOT}/overlay"
mkdir -p "${OVERLAY}"
(cd "${ROOT_DIR}" && git ls-files -z --cached --others --exclude-standard | while IFS= read -r -d '' path; do
    [[ -f "${path}" ]] || continue
    mkdir -p "${OVERLAY}/$(dirname "${path}")"; cp -p "${path}" "${OVERLAY}/${path}"
done)
CACHE="${XDG_CACHE_HOME:-${HOME}/.cache}/talos-cluster-validate/crds"
CM_RENDER="${CACHE}/cert-manager-${CERT_MANAGER_CHART##*@sha256:}.yaml"
CNPG_RENDER="${CACHE}/cnpg-${CNPG_CHART##*@sha256:}.yaml"
OP_RENDER="${CACHE}/keycloak-operator-render.yaml"
KC_RENDER="${CACHE}/keycloak-render.yaml"
UPSTREAM="${OVERLAY}/platform/keycloak-operator/upstream"

passed=0
failed=0
result() {  # result NAME RC WANT_RC OUTFILE WANT_TEXT (a traceback fails any row: diagnostics are the checker's own)
    if [[ "$2" == "$3" ]] && grep -qF -- "$5" "$4" && ! grep -qF 'Traceback (most recent call last)' "$4"; then
        passed=$((passed + 1)); printf 'ok   %-38s rc=%s\n' "$1" "$2"
    else
        failed=$((failed + 1)); printf 'FAIL %-38s rc=%s want=%s (%s)\n' "$1" "$2" "$3" "$5"
        sed 's/^/    | /' "$4" | tail -6
    fi
}
run_validate() {  # run_validate NAME WANT_RC WANT_TEXT: the full validator over the overlay
    local rc out="${TEST_ROOT}/$1.out"
    set +e; timeout 600 bash "${OVERLAY}/scripts/validate.sh" > "${out}" 2>&1; rc=$?; set -e
    result "$1" "${rc}" "$2" "${out}" "$3"
}
# mutate NAME FILE PYTHON-EXPR WANT_TEXT: replace FILE's text t by the expression's value (which must
# differ), run the full validator expecting failure with WANT_TEXT, then restore the file.
mutate() {
    local name="$1" file="${OVERLAY}/$2" expression="$3" want="$4"
    cp -p "${file}" "${TEST_ROOT}/saved"
    python3 -I - "${file}" "${expression}" <<'PY'
import sys
path, expression = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
new = eval(expression, {"t": text})
if new == text:
    sys.exit(f"selftest: mutation did not change {path}")
open(path, "w", encoding="utf-8").write(new)
PY
    run_validate "${name}" 1 "${want}"
    cp -p "${TEST_ROOT}/saved" "${file}"
}
run_checker() {  # run_checker NAME WANT_RC WANT_TEXT COMMAND...
    local name="$1" want_rc="$2" want="$3" rc out="${TEST_ROOT}/$1.out"
    shift 3
    set +e; "$@" > "${out}" 2>&1; rc=$?; set -e
    result "${name}" "${rc}" "${want_rc}" "${out}" "${want}"
}
yaml_edit() {  # yaml_edit IN OUT PYTHON-STATEMENTS: docs = all documents of IN; the statements edit docs
    python3 -I - "$1" "$2" "$3" <<'PY'
import sys
import yaml
source, target, statements = sys.argv[1:4]
docs = [d for d in yaml.safe_load_all(open(source, encoding="utf-8")) if d]
exec(statements, {"docs": docs})
with open(target, "w", encoding="utf-8") as stream:
    yaml.safe_dump_all(docs, stream, sort_keys=False)
PY
}

# Baseline: the untouched overlay validates (this also renders and caches the charts the checker-level
# mutants use).
run_validate baseline 0 "Tracked files are valid."
for file in "${CM_RENDER}" "${CNPG_RENDER}" "${OP_RENDER}" "${KC_RENDER}"; do
    [[ -s "${file}" ]] || { echo "ERROR: the baseline did not leave ${file}; cannot run the checker mutants" >&2; exit 1; }
done

# Full-validator mutants: each guard fails on its own.
mutate vendored-byte-changed platform/keycloak-operator/upstream/kubernetes.yml 't + "# changed\n"' "kubernetes.yml: FAILED"
mutate cnpg-chart-by-tag cluster/config.env \
    't.replace(t.split("CNPG_CHART=\"")[1].split("\"")[0], "oci://ghcr.io/cloudnative-pg/charts/cloudnative-pg:0.29.1")' \
    "CERT_MANAGER_CHART and CNPG_CHART must be oci://...@sha256:<digest> references"
# The expressions are Python (evaluated by mutate), so ${…} inside them is literal text, not shell expansion.
# shellcheck disable=SC2016
mutate installer-bypasses-digest scripts/install-platform.sh \
    't.replace("helm upgrade --install cnpg \"${CNPG_CHART}\"", "helm upgrade --install cnpg oci://ghcr.io/cloudnative-pg/charts/cloudnative-pg --version 0.29.1")' \
    "install-platform.sh must install cnpg from CNPG_CHART (digest)"
mutate mapper-attribute-changed platform/keycloak/realm-import.yaml \
    't.replace("ldap.attribute: [\"sAMAccountName\"]", "ldap.attribute: [\"userPrincipalName\"]")' \
    "mapper 'username' differs"
mutate mapper-removed platform/keycloak/realm-import.yaml \
    't.replace("              - name: MSAD account controls\n                providerId: msad-user-account-control-mapper\n                config:\n                  always.read.enabled.value.from.ldap: [\"true\"]\n", "")' \
    "mapper 'MSAD account controls' missing"
mutate mapper-extra platform/keycloak/realm-import.yaml \
    't.replace("              - name: MSAD account controls\n", "              - name: upn\n                providerId: user-attribute-ldap-mapper\n                config:\n                  user.model.attribute: [\"upn\"]\n                  ldap.attribute: [\"userPrincipalName\"]\n              - name: MSAD account controls\n")' \
    "unexpected mapper 'upn'"
mutate kerberos-enabled platform/keycloak/realm-import.yaml \
    't.replace("            editMode: [\"READ_ONLY\"]\n", "            editMode: [\"READ_ONLY\"]\n            allowKerberosAuthentication: [\"true\"]\n")' \
    "allowKerberosAuthentication must be absent"
mutate vendor-not-ad platform/keycloak/realm-import.yaml 't.replace("vendor: [\"ad\"]", "vendor: [\"other\"]")' \
    "LDAP provider vendor must be ['ad']"
mutate cr-unknown-field platform/keycloak/keycloak.yaml 't.replace("\n  hostname:\n", "\n  hostnmae:\n")' \
    "Additional properties are not allowed ('hostnmae' was unexpected)"
mutate cr-wrong-type platform/keycloak/database.yaml 't.replace("  instances: 2\n", "  instances: \"two\"\n")' \
    "'two' is not of type 'integer'"
mutate cr-unserved-version platform/keycloak/realm-import.yaml \
    't.replace("apiVersion: k8s.keycloak.org/v2beta1", "apiVersion: k8s.keycloak.org/v2alpha9")' \
    "apiVersion k8s.keycloak.org/v2alpha9 is not the required served version"

# Checker-level mutants against the baseline's renders.
REQUIRE=(--require Certificate.cert-manager.io/v1 --require ClusterIssuer.cert-manager.io/v1
    --require Cluster.postgresql.cnpg.io/v1 --require Keycloak.k8s.keycloak.org/v2beta1
    --require KeycloakRealmImport.k8s.keycloak.org/v2beta1)
MANIFESTS=("${KC_RENDER}" "${OVERLAY}/platform/keycloak/realm-import.yaml" "${OVERLAY}/platform/cert-manager/issuer.yaml")
CRS="${OVERLAY}/scripts/tests/check-crs.py"
run_checker crs-baseline 0 "check-crs: 5 custom resource(s) pass the pre-check" \
    python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}"/keycloak*.yml -- "${MANIFESTS[@]}"
run_checker crs-schema-absent 1 "no served schema loaded for KeycloakRealmImport k8s.keycloak.org/v2beta1" \
    python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}/keycloaks.k8s.keycloak.org-v1.yml" -- "${MANIFESTS[@]}"
run_checker crs-schema-ambiguous 1 "Keycloak k8s.keycloak.org/v2beta1 is served by more than one loaded CRD" \
    python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}"/keycloak*.yml "${UPSTREAM}/keycloaks.k8s.keycloak.org-v1.yml" -- "${MANIFESTS[@]}"
run_checker crs-document-missing 1 "no KeycloakRealmImport k8s.keycloak.org/v2beta1 document found" \
    python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}"/keycloak*.yml -- "${KC_RENDER}" "${OVERLAY}/platform/cert-manager/issuer.yaml"
run_checker crs-no-require 1 "at least one --require" \
    python3 -I "${CRS}" "${CM_RENDER}" -- "${KC_RENDER}"
yaml_edit "${KC_RENDER}" "${TEST_ROOT}/cel-render.yaml" \
    'next(d for d in docs if d["kind"] == "Cluster")["spec"]["imageCatalogRef"] = {"apiGroup": "postgresql.cnpg.io", "kind": "ImageCatalog", "name": "x", "major": 18}'
run_checker crs-cel-listed-not-passed 0 "deferred: Cluster keycloak-db: .spec: !(has(self.imageCatalogRef) && has(self.imageName))" \
    python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}"/keycloak*.yml -- "${TEST_ROOT}/cel-render.yaml" "${MANIFESTS[@]:1}"

RBAC="${OVERLAY}/scripts/tests/check-rbac.py"
ACCEPTED="${OVERLAY}/scripts/tests/rbac-accepted.json"
rbac() { python3 -I "${RBAC}" --accepted "${ACCEPTED}" "$@"; }
run_checker rbac-baseline 0 "check-rbac: RBAC objects and admission webhooks are exactly the reviewed fingerprint" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${CNPG_RENDER}" --keycloak-operator "${OP_RENDER}"
yaml_edit "${CNPG_RENDER}" "${TEST_ROOT}/cnpg-secrets.yaml" \
    'next(d for d in docs if d["kind"] == "ClusterRole" and d["metadata"]["name"] == "cnpg-cloudnative-pg")["rules"].append({"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]})'
run_checker rbac-cnpg-secret-rule 1 "cnpg: ClusterRole cnpg-cloudnative-pg touches Secrets" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${TEST_ROOT}/cnpg-secrets.yaml" --keycloak-operator "${OP_RENDER}"
yaml_edit "${CNPG_RENDER}" "${TEST_ROOT}/cnpg-extra-crb.yaml" \
    'docs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "cnpg-edit-everywhere"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cnpg-cloudnative-pg-edit"}, "subjects": [{"kind": "ServiceAccount", "name": "cnpg-cloudnative-pg", "namespace": "keycloak"}]})'
run_checker rbac-cnpg-extra-binding 1 "cnpg: ClusterRoleBindings ['cnpg-cloudnative-pg', 'cnpg-edit-everywhere'] != ['cnpg-cloudnative-pg']" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${TEST_ROOT}/cnpg-extra-crb.yaml" --keycloak-operator "${OP_RENDER}"
yaml_edit "${OP_RENDER}" "${TEST_ROOT}/operator-crb.yaml" \
    'docs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "keycloak-operator-clusterrole-binding"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "keycloakcontroller-cluster-role"}, "subjects": [{"kind": "ServiceAccount", "name": "keycloak-operator", "namespace": "keycloak"}]})'
run_checker rbac-operator-binding 1 "keycloak-operator: ClusterRoleBinding(s) present" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${CNPG_RENDER}" --keycloak-operator "${TEST_ROOT}/operator-crb.yaml"
yaml_edit "${CM_RENDER}" "${TEST_ROOT}/cm-extra-secret-role.yaml" \
    'next(d for d in docs if d["kind"] == "ClusterRole" and d["metadata"]["name"] == "cert-manager-controller-ingress-shim")["rules"].append({"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]})'
run_checker rbac-cert-manager-extra-secret-role 1 "cert-manager: object differs from the reviewed fingerprint" \
    rbac --cert-manager "${TEST_ROOT}/cm-extra-secret-role.yaml" --cnpg "${CNPG_RENDER}" --keycloak-operator "${OP_RENDER}"
yaml_edit "${CM_RENDER}" "${TEST_ROOT}/cm-foreign-subject.yaml" \
    'next(d for d in docs if d["kind"] == "ClusterRoleBinding" and d["roleRef"]["name"] == "cert-manager-controller-issuers")["subjects"].append({"kind": "ServiceAccount", "name": "default", "namespace": "keycloak"})'
run_checker rbac-cert-manager-foreign-subject 1 "has subjects outside cert-manager's service accounts" \
    rbac --cert-manager "${TEST_ROOT}/cm-foreign-subject.yaml" --cnpg "${CNPG_RENDER}" --keycloak-operator "${OP_RENDER}"

# Round-3 constructions: an operator RoleBinding with a foreign subject, a wildcard verb, an extra cert-manager
# binding of a non-Secret role, a changed CNPG webhook, and the fingerprint itself out of date.
yaml_edit "${OP_RENDER}" "${TEST_ROOT}/operator-foreign-subject.yaml" \
    'next(d for d in docs if d["kind"] == "RoleBinding")["subjects"].append({"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"})'
run_checker rbac-operator-foreign-subject 1 "only the keycloak-operator service account in keycloak is accepted" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${CNPG_RENDER}" --keycloak-operator "${TEST_ROOT}/operator-foreign-subject.yaml"
yaml_edit "${OP_RENDER}" "${TEST_ROOT}/operator-wildcard-verb.yaml" \
    'next(d for d in docs if d["kind"] == "ClusterRole")["rules"].append({"apiGroups": [""], "resources": ["secrets"], "verbs": ["*"]})'
run_checker rbac-operator-wildcard-verb 1 "has a wildcard rule" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${CNPG_RENDER}" --keycloak-operator "${TEST_ROOT}/operator-wildcard-verb.yaml"
yaml_edit "${CM_RENDER}" "${TEST_ROOT}/cm-extra-binding.yaml" \
    'docs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "audit-extra-binding"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cert-manager-controller-ingress-shim"}, "subjects": [{"kind": "ServiceAccount", "name": "cert-manager", "namespace": "cert-manager"}]})'
run_checker rbac-cert-manager-extra-binding 1 "cert-manager: object not in the reviewed fingerprint" \
    rbac --cert-manager "${TEST_ROOT}/cm-extra-binding.yaml" --cnpg "${CNPG_RENDER}" --keycloak-operator "${OP_RENDER}"
yaml_edit "${CNPG_RENDER}" "${TEST_ROOT}/cnpg-webhook-changed.yaml" \
    'next(d for d in docs if d["kind"] == "ValidatingWebhookConfiguration")["webhooks"][0]["namespaceSelector"] = {"matchLabels": {"x": "y"}}'
run_checker rbac-cnpg-webhook-changed 1 "cnpg: object differs from the reviewed fingerprint" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${TEST_ROOT}/cnpg-webhook-changed.yaml" --keycloak-operator "${OP_RENDER}"
yaml_edit "${CNPG_RENDER}" "${TEST_ROOT}/cnpg-webhook-removed.yaml" \
    'docs[:] = [d for d in docs if d["kind"] != "ValidatingWebhookConfiguration"]'
run_checker rbac-fingerprint-missing-object 1 "reviewed object missing from the render" \
    python3 -I "${RBAC}" --accepted "${ACCEPTED}" --cert-manager "${CM_RENDER}" --cnpg "${TEST_ROOT}/cnpg-webhook-removed.yaml" --keycloak-operator "${OP_RENDER}"

# Round-4 constructions: a grant hidden inside a Kubernetes List (the installer flattens lists), and an object
# whose identity occurs twice.
# Kubernetes treats ANY object with a top-level `items` array as a list, whatever its kind (round 5).
yaml_edit "${CNPG_RENDER}" "${TEST_ROOT}/cnpg-nonlist-kind-items.yaml" \
    'docs.append({"apiVersion": "example.invalid/v1", "kind": "Widget", "metadata": {"name": "w"}, "items": [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "hidden-through-generic-items"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"}, "subjects": [{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"}]}]})'
run_checker rbac-nonlist-kind-items 1 "ClusterRoleBinding hidden-through-generic-items binds" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${TEST_ROOT}/cnpg-nonlist-kind-items.yaml" --keycloak-operator "${OP_RENDER}"
yaml_edit "${KC_RENDER}" "${TEST_ROOT}/crs-nonlist-kind-items.yaml" \
    'c = next(d for d in docs if d["kind"] == "Cluster"); docs.remove(c); c["spec"]["instances"] = "two"; docs.append({"apiVersion": "example.invalid/v1", "kind": "Widget", "metadata": {"name": "w"}, "items": [c]})'
run_checker crs-nonlist-kind-items 1 "'two' is not of type 'integer'" \
    python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}"/keycloak*.yml -- "${TEST_ROOT}/crs-nonlist-kind-items.yaml" "${MANIFESTS[@]:1}"
# Malformed list children fail closed with the checkers' own diagnostics (round 6): a null child, scalars, a
# kindless mapping, a List whose items is not an array, a duplicated required custom resource.
yaml_edit "${CNPG_RENDER}" "${TEST_ROOT}/cnpg-null-child.yaml" \
    'docs.append({"apiVersion": "example.invalid/v1", "kind": "Widget", "metadata": {"name": "w"}, "items": [None]})'
run_checker rbac-null-list-child 1 "is not an object with a kind" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${TEST_ROOT}/cnpg-null-child.yaml" --keycloak-operator "${OP_RENDER}"
for shape in null scalars kindless malformed-list list-without-items; do
    case "${shape}" in
        null) statement='docs.append({"apiVersion": "example.invalid/v1", "kind": "Widget", "metadata": {"name": "w"}, "items": [None]})'; want="is not an object with a kind (NoneType)" ;;
        scalars) statement='docs.append({"apiVersion": "example.invalid/v1", "kind": "Widget", "metadata": {"name": "w"}, "items": ["text", 3]})'; want="is not an object with a kind (int)" ;;
        kindless) statement='docs.append({"apiVersion": "example.invalid/v1", "kind": "Widget", "metadata": {"name": "w"}, "items": [{"metadata": {"name": "x"}}]})'; want="is not an object with a kind (dict)" ;;
        malformed-list) statement='docs.append({"apiVersion": "v1", "kind": "List", "items": None})'; want="List items is missing or not a list" ;;
        list-without-items) statement='docs.append({"apiVersion": "v1", "kind": "List"})'; want="List items is missing or not a list" ;;
    esac
    yaml_edit "${KC_RENDER}" "${TEST_ROOT}/crs-${shape}.yaml" "${statement}"
    run_checker "crs-${shape}-child" 1 "${want}" \
        python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}"/keycloak*.yml -- "${TEST_ROOT}/crs-${shape}.yaml" "${MANIFESTS[@]:1}"
done
yaml_edit "${KC_RENDER}" "${TEST_ROOT}/crs-duplicate.yaml" 'docs.append(next(d for d in docs if d["kind"] == "Cluster"))'
run_checker crs-duplicate-required-cr 1 "Cluster keycloak-db occurs more than once" \
    python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}"/keycloak*.yml -- "${TEST_ROOT}/crs-duplicate.yaml" "${MANIFESTS[@]:1}"
yaml_edit "${CNPG_RENDER}" "${TEST_ROOT}/cnpg-list-without-items.yaml" 'docs.append({"apiVersion": "v1", "kind": "List"})'
run_checker rbac-list-without-items 1 "List items is missing or not a list" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${TEST_ROOT}/cnpg-list-without-items.yaml" --keycloak-operator "${OP_RENDER}"
yaml_edit "${CNPG_RENDER}" "${TEST_ROOT}/cnpg-list-wrapped.yaml" \
    'docs.append({"apiVersion": "v1", "kind": "List", "items": [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "hidden-admin"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"}, "subjects": [{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"}]}]})'
run_checker rbac-list-wrapped-binding 1 "ClusterRoleBinding hidden-admin binds" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${TEST_ROOT}/cnpg-list-wrapped.yaml" --keycloak-operator "${OP_RENDER}"
yaml_edit "${OP_RENDER}" "${TEST_ROOT}/operator-duplicate.yaml" \
    'docs.append(next(d for d in docs if d["kind"] == "RoleBinding"))'
run_checker rbac-duplicate-identity 1 "occurs more than once in the render" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${CNPG_RENDER}" --keycloak-operator "${TEST_ROOT}/operator-duplicate.yaml"
yaml_edit "${OP_RENDER}" "${TEST_ROOT}/operator-malformed-list.yaml" \
    'docs.append({"apiVersion": "v1", "kind": "List", "items": ["not-an-object"]})'
run_checker rbac-malformed-list-item 1 "is not an object with a kind" \
    rbac --cert-manager "${CM_RENDER}" --cnpg "${CNPG_RENDER}" --keycloak-operator "${TEST_ROOT}/operator-malformed-list.yaml"

# Round-3 CR constructions: an unknown field inside a shapeless object, a duplicated list-map key.
yaml_edit "${OVERLAY}/platform/keycloak/realm-import.yaml" "${TEST_ROOT}/realm-shapeless-unknown.yaml" \
    'docs[0]["spec"]["realm"].setdefault("federatedUsers", []).append({"username": "x", "userProfileMetadata": {"attributes": [{"name": "a", "annotations": {"k": {"mystery": 1}}}]}})'
run_checker crs-shapeless-object-unknown-field 1 "Additional properties are not allowed ('mystery' was unexpected)" \
    python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}"/keycloak*.yml -- "${KC_RENDER}" "${TEST_ROOT}/realm-shapeless-unknown.yaml" "${OVERLAY}/platform/cert-manager/issuer.yaml"
yaml_edit "${KC_RENDER}" "${TEST_ROOT}/cluster-listmap-duplicate.yaml" \
    'next(d for d in docs if d["kind"] == "Cluster")["spec"].setdefault("resources", {})["claims"] = [{"name": "gpu"}, {"name": "gpu"}]'
run_checker crs-list-map-duplicate-key 1 "duplicate map key" \
    python3 -I "${CRS}" "${REQUIRE[@]}" "${CM_RENDER}" "${CNPG_RENDER}" "${UPSTREAM}"/keycloak*.yml -- "${TEST_ROOT}/cluster-listmap-duplicate.yaml" "${MANIFESTS[@]:1}"

# Round-3 realm construction: a Kerberos principal attribute without the boolean flags.
mutate krb-principal-attribute platform/keycloak/realm-import.yaml \
    't.replace("            editMode: [\"READ_ONLY\"]\n", "            editMode: [\"READ_ONLY\"]\n            krbPrincipalAttribute: [\"userPrincipalName\"]\n")' \
    "krbPrincipalAttribute must be absent"

# Wiring: the FULL validator must run check-rbac on the renders it caches. Widen the cached CNPG render
# (a Secret rule), run validate.sh, require check-rbac's own failure, then restore the cache.
cp -p "${CNPG_RENDER}" "${TEST_ROOT}/cnpg-render.saved"
yaml_edit "${TEST_ROOT}/cnpg-render.saved" "${CNPG_RENDER}" \
    'next(d for d in docs if d["kind"] == "ClusterRole" and d["metadata"]["name"] == "cnpg-cloudnative-pg")["rules"].append({"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]})'
run_validate validate-runs-check-rbac 1 "cnpg: ClusterRole cnpg-cloudnative-pg touches Secrets"
cp -p "${TEST_ROOT}/cnpg-render.saved" "${CNPG_RENDER}"

total=$((passed + failed))
if (( failed > 0 )); then
    echo "Self-test FAILED: ${passed}/${total} validate cases passed, ${failed} failed."
    exit 1
fi
echo "All ${total} validate self-tests passed."
