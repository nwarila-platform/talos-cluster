#!/usr/bin/env bash
set -euo pipefail

readonly SCRATCH="dr-validate-vault-restore"
readonly LONGHORN_NS="longhorn-system"
readonly RESULT_NS="dr-validate"
readonly RESULT_CM="dr-restore-driver-result"

readonly STALE_THRESHOLD_SECONDS="${STALE_THRESHOLD_SECONDS:-93600}"
readonly RESTORE_TIMEOUT_SECONDS="${RESTORE_TIMEOUT_SECONDS:-600}"
readonly CLEANUP_TIMEOUT_SECONDS="${CLEANUP_TIMEOUT_SECONDS:-180}"
readonly POLL_SECONDS="${POLL_SECONDS:-10}"
readonly SIZE_TOLERANCE_PERCENT="${SIZE_TOLERANCE_PERCENT:-5}"
readonly SIZE_TOLERANCE_FLOOR_BYTES="${SIZE_TOLERANCE_FLOOR_BYTES:-1048576}"

status="FAIL"
reason="unhandled failure"
backup_name=""
source_volume=""
backup_size="0"
snapshot_created_at=""
git_sha="${GIT_SHA:-unknown}"
kubectl_version="unknown"
longhorn_api_version="unknown"
elapsed_restore_seconds="0"
cleanup_verified="false"
run_marker="${RUN_MARKER:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
restore_start_epoch="0"

json_escape() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "${value}"
}

json_string() {
  printf '"%s"' "$(json_escape "$1")"
}

is_integer() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

fail() {
  reason="$1"
  status="FAIL"
  exit 1
}

on_error() {
  local rc=$?
  if [[ "${reason}" == "unhandled failure" ]]; then
    reason="command failed before completion"
  fi
  status="FAIL"
  exit "${rc}"
}

on_signal() {
  reason="received termination signal"
  status="FAIL"
  exit 1
}

assert_scratch_name_safe() {
  if [[ "${SCRATCH}" == data-vault* ]]; then
    fail "scratch volume name matches protected live Vault prefix"
  fi
  if [[ "${SCRATCH}" != "dr-validate-vault-restore" ]]; then
    fail "scratch volume name is not the fixed restore-validator name"
  fi
}

delete_scratch_volume() {
  local target="$1"
  if [[ "${target}" != "${SCRATCH}" ]]; then
    echo "refusing to delete unexpected Longhorn volume ${target}" >&2
    return 1
  fi
  if [[ "${target}" == data-vault* ]]; then
    echo "refusing to delete protected live Vault Longhorn volume ${target}" >&2
    return 1
  fi
  kubectl -n "${LONGHORN_NS}" delete "volumes.longhorn.io/${target}" \
    --ignore-not-found=true \
    --wait=false >/dev/null
}

wait_scratch_absent() {
  local deadline
  local output
  local rc
  deadline=$(($(date +%s) + CLEANUP_TIMEOUT_SECONDS))

  while true; do
    if output="$(kubectl -n "${LONGHORN_NS}" get "volumes.longhorn.io/${SCRATCH}" 2>&1)"; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${rc}" -eq 0 ]]; then
      :
    elif grep -q "NotFound" <<<"${output}"; then
      return 0
    else
      echo "${output}" >&2
      return "${rc}"
    fi

    if (($(date +%s) >= deadline)); then
      return 1
    fi
    sleep "${POLL_SECONDS}"
  done
}

cleanup() {
  assert_scratch_name_safe
  delete_scratch_volume "${SCRATCH}"
  wait_scratch_absent
}

detect_versions() {
  local version
  version="$(kubectl version --client=true 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')" || true
  if [[ -n "${version}" ]]; then
    kubectl_version="${version}"
  fi
}

write_result_json() {
  local path="$1"
  cat >"${path}" <<EOF
{
  "status": $(json_string "${status}"),
  "reason": $(json_string "${reason}"),
  "backup_name": $(json_string "${backup_name}"),
  "source_volume": $(json_string "${source_volume}"),
  "backup_size": ${backup_size},
  "snapshot_created_at": $(json_string "${snapshot_created_at}"),
  "git_sha": $(json_string "${git_sha}"),
  "versions": {
    "kubectl": $(json_string "${kubectl_version}"),
    "longhorn_api": $(json_string "${longhorn_api_version}")
  },
  "elapsed_restore_seconds": ${elapsed_restore_seconds},
  "cleanup_verified": ${cleanup_verified},
  "run_marker": $(json_string "${run_marker}")
}
EOF
}

write_result_configmap() {
  local json_path="$1"
  local cm_path="/tmp/${RESULT_CM}.yaml"

  {
    cat <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${RESULT_CM}
  namespace: ${RESULT_NS}
  labels:
    app.kubernetes.io/name: vault-restore-validator
    app.kubernetes.io/component: restore-driver
data:
  result.json: |
EOF
    sed 's/^/    /' "${json_path}"
  } >"${cm_path}"

  if kubectl -n "${RESULT_NS}" get "configmap/${RESULT_CM}" >/dev/null 2>&1; then
    kubectl replace -f "${cm_path}" >/dev/null
  else
    kubectl create -f "${cm_path}" >/dev/null
  fi
}

emit_result() {
  local json_path="/tmp/result.json"
  write_result_json "${json_path}"
  cat "${json_path}"
  write_result_configmap "${json_path}"
}

finish() {
  local original_rc=$?
  local cleanup_rc=0
  local result_rc=0

  trap - EXIT ERR INT TERM
  set +e

  cleanup
  cleanup_rc=$?
  if [[ "${cleanup_rc}" -eq 0 ]]; then
    cleanup_verified="true"
  else
    cleanup_verified="false"
    status="FAIL"
    if [[ "${reason}" == "unhandled failure" ]]; then
      reason="scratch cleanup failed"
    else
      reason="${reason}; scratch cleanup failed"
    fi
  fi

  if [[ "${status}" == "PASS" && "${original_rc}" -ne 0 ]]; then
    status="FAIL"
    reason="restore driver exited non-zero after pass state"
  fi

  emit_result
  result_rc=$?

  if [[ "${status}" == "PASS" && "${result_rc}" -eq 0 ]]; then
    exit 0
  fi
  exit 1
}

parse_backup_epoch() {
  local timestamp="$1"
  date -u -d "${timestamp}" +%s
}

size_tolerance_bytes() {
  local size="$1"
  local tolerance
  tolerance=$((size * SIZE_TOLERANCE_PERCENT / 100))
  if ((tolerance < SIZE_TOLERANCE_FLOOR_BYTES)); then
    tolerance="${SIZE_TOLERANCE_FLOOR_BYTES}"
  fi
  printf '%s' "${tolerance}"
}

size_within_tolerance() {
  local expected="$1"
  local actual="$2"
  local tolerance="$3"
  local delta

  if ((actual >= expected)); then
    delta=$((actual - expected))
  else
    delta=$((expected - actual))
  fi

  ((delta <= tolerance))
}

select_newest_backup() {
  local rows
  local selected
  rows="$(kubectl -n "${LONGHORN_NS}" get backups.longhorn.io \
    -o=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.state}{"\t"}{.status.volumeName}{"\t"}{.status.snapshotCreatedAt}{"\t"}{.status.url}{"\t"}{.status.size}{"\n"}{end}')"

  selected="$(
    printf '%s\n' "${rows}" |
      awk -F '\t' '$2 == "Completed" && $3 ~ /^data-vault-/ && $4 != "" && $4 != "<no value>" { print }' |
      sort -t "$(printf '\t')" -k4,4 |
      tail -n 1
  )"

  if [[ -z "${selected}" ]]; then
    fail "no completed data-vault Longhorn backup found"
  fi

  IFS=$'\t' read -r backup_name _ source_volume snapshot_created_at backup_url backup_size <<<"${selected}"

  if [[ -z "${backup_name}" || "${backup_name}" == "<no value>" ]]; then
    fail "selected backup has no name"
  fi
  if [[ "${source_volume}" != data-vault-* ]]; then
    fail "selected backup source volume is not a data-vault volume"
  fi
  if [[ -z "${snapshot_created_at}" || "${snapshot_created_at}" == "<no value>" ]]; then
    fail "selected backup has no snapshot timestamp"
  fi
  if [[ -z "${backup_url}" || "${backup_url}" == "<no value>" ]]; then
    fail "selected backup has no restore URL"
  fi
  if ! is_integer "${backup_size}" || ((backup_size <= 0)); then
    fail "selected backup has invalid size"
  fi

  local snapshot_epoch
  local now_epoch
  local age_seconds
  snapshot_epoch="$(parse_backup_epoch "${snapshot_created_at}")"
  now_epoch="$(date -u +%s)"
  age_seconds=$((now_epoch - snapshot_epoch))
  if ((age_seconds < 0)); then
    fail "selected backup timestamp is in the future"
  fi
  if ((age_seconds > STALE_THRESHOLD_SECONDS)); then
    fail "selected backup is stale"
  fi
}

create_restore_volume() {
  local escaped_backup_url
  escaped_backup_url="${backup_url//\'/\'\'}"

  cat <<EOF | kubectl create -f - >/dev/null
apiVersion: longhorn.io/v1beta2
kind: Volume
metadata:
  name: dr-validate-vault-restore
  namespace: ${LONGHORN_NS}
  labels:
    app.kubernetes.io/name: vault-restore-validator
    app.kubernetes.io/component: restore-driver
spec:
  fromBackup: '${escaped_backup_url}'
  numberOfReplicas: 1
  dataEngine: v1
EOF
}

wait_for_restore() {
  local deadline
  local tolerance
  local volume_status
  local state
  local restore_required
  local actual_size

  deadline=$(($(date +%s) + RESTORE_TIMEOUT_SECONDS))
  tolerance="$(size_tolerance_bytes "${backup_size}")"
  restore_start_epoch="$(date +%s)"

  while (($(date +%s) < deadline)); do
    volume_status="$(kubectl -n "${LONGHORN_NS}" get "volumes.longhorn.io/${SCRATCH}" \
      -o=jsonpath='{.status.state}{"\t"}{.status.restoreRequired}{"\t"}{.status.actualSize}{"\t"}{.apiVersion}')"
    IFS=$'\t' read -r state restore_required actual_size longhorn_api_version <<<"${volume_status}"

    if [[ "${state}" == "detached" &&
      "${restore_required}" == "false" &&
      "${actual_size}" =~ ^[0-9]+$ ]] &&
      size_within_tolerance "${backup_size}" "${actual_size}" "${tolerance}"; then
      elapsed_restore_seconds=$(($(date +%s) - restore_start_epoch))
      return 0
    fi

    sleep "${POLL_SECONDS}"
  done

  fail "timed out waiting for scratch Longhorn restore to detach with expected size"
}

main() {
  trap finish EXIT
  trap on_error ERR
  trap on_signal INT TERM

  assert_scratch_name_safe
  detect_versions
  select_newest_backup

  delete_scratch_volume "${SCRATCH}"
  wait_scratch_absent

  create_restore_volume
  wait_for_restore

  status="PASS"
  reason="restore completed and scratch cleanup verified"
}

main "$@"
