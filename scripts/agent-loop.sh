#!/usr/bin/env bash
# =============================================================================
# agent-loop.sh - Autonomous Codex/Claude improvement loop
#
# Starts and supervises fixed-scope repository improvement cycles:
#   1. auditor LLM audits + plans one deficiency
#   2. reviewer LLM adversarially reviews the plan
#   3. auditor LLM implements only an approved plan
#   4. reviewer LLM verifies and records residual risk
#   5. roles swap for the next cycle
#
# The script stores local state under .agent-loop/. That directory is ignored.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

LOOP_DIR="${AGENT_LOOP_DIR:-.agent-loop}"
CYCLES_DIR="${LOOP_DIR}/cycles"
CURRENT_FILE="${LOOP_DIR}/current"
NEXT_AUDITOR_FILE="${LOOP_DIR}/next-auditor"

DEFAULT_MAX_CYCLES=1
DEFAULT_MAX_REVISIONS=2
DEFAULT_MAX_PHASE_RETRIES=2

usage() {
    cat <<'EOF'
Usage:
  scripts/agent-loop.sh run [--auditor codex|claude] [--max-cycles N] [--slug short-name]
                            [--max-revisions N] [--max-phase-retries N] [--fake-agents]
  scripts/agent-loop.sh start [--auditor codex|claude] [--slug short-name]
  scripts/agent-loop.sh status
  scripts/agent-loop.sh monitor
  scripts/agent-loop.sh prompt audit|review|implement|verify
  scripts/agent-loop.sh audit-ready
  scripts/agent-loop.sh approve-plan
  scripts/agent-loop.sh request-revision
  scripts/agent-loop.sh implementation-done
  scripts/agent-loop.sh complete

Autonomous command:
  run                 Drive cycles end-to-end. This is the normal command.

Manual/debug commands:
  start               Create a cycle and assign auditor/reviewer roles.
  prompt              Print the prompt for a phase.
  audit-ready         Move from audit/plan to adversarial review.
  approve-plan        Move from review to implementation.
  request-revision    Send the plan back to audit/plan.
  implementation-done Move from implementation to verification.
  complete            Close the cycle and rotate the next auditor.

Agent command configuration:
  AGENT_CODEX_CMD     Optional shell command for Codex. Reads prompt on stdin.
                      Default: codex exec --full-auto -m <model> -C <repo> -
  AGENT_CODEX_MODEL   Space-separated Codex model fallback list.
                      Default: gpt-5.5 gpt-5.4 gpt-5.3-codex gpt-5.2
  AGENT_CODEX_EFFORT  Space-separated Codex effort fallback list.
                      Default: max xhigh
  AGENT_CLAUDE_CMD    Optional shell command for Claude. Reads prompt on stdin.
                      Default: claude -p --permission-mode auto --model <model> --effort <effort>
  AGENT_CLAUDE_MODEL  Space-separated Claude model fallback list.
                      Default: opus claude-opus-4-7
  AGENT_CLAUDE_EFFORT Space-separated Claude effort fallback list.
                      Default: max

Examples:
  scripts/agent-loop.sh run --max-cycles 3
  scripts/agent-loop.sh run --auditor claude --max-cycles 1 --slug ci-hardening
  AGENT_CODEX_CMD='codex exec --full-auto -C . -' scripts/agent-loop.sh run

PowerShell on Windows:
  .\scripts\agent-loop.ps1 run --max-cycles 3

State is stored under .agent-loop/ and is intentionally local-only.
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

normalize_agent() {
    local value="${1,,}"
    case "${value}" in
        codex|claude) echo "${value}" ;;
        *) die "agent must be 'codex' or 'claude' (got '${1}')" ;;
    esac
}

other_agent() {
    case "$1" in
        codex) echo "claude" ;;
        claude) echo "codex" ;;
        *) die "unknown agent '${1}'" ;;
    esac
}

sanitize_slug() {
    local raw="${1:-unspecified-deficiency}"
    local slug
    slug="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')"
    if [[ -z "${slug}" ]]; then
        slug="unspecified-deficiency"
    fi
    printf '%s' "${slug}"
}

next_cycle_number() {
    local max=0
    local path base num
    mkdir -p "${CYCLES_DIR}"
    for path in "${CYCLES_DIR}"/[0-9][0-9][0-9][0-9]-*; do
        [[ -e "${path}" ]] || continue
        base="${path##*/}"
        num="${base%%-*}"
        if ((10#${num} > max)); then
            max=$((10#${num}))
        fi
    done
    printf '%04d' "$((max + 1))"
}

load_current() {
    [[ -f "${CURRENT_FILE}" ]] || die "no active cycle; run 'scripts/agent-loop.sh start' or 'run'"
    CYCLE_DIR="$(<"${CURRENT_FILE}")"
    [[ -d "${CYCLE_DIR}" ]] || die "active cycle directory is missing: ${CYCLE_DIR}"
    # shellcheck disable=SC1091
    source "${CYCLE_DIR}/state.env"
    PHASE_FILE="${CYCLE_DIR}/phase"
    [[ -f "${PHASE_FILE}" ]] || die "active cycle phase file is missing"
    PHASE="$(<"${PHASE_FILE}")"
}

log_event() {
    local message="$1"
    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%s %s\n' "${timestamp}" "${message}" >> "${CYCLE_DIR}/events.log"
}

set_phase() {
    local phase="$1"
    printf '%s\n' "${phase}" > "${PHASE_FILE}"
    PHASE="${phase}"
    log_event "phase=${phase}"
}

require_phase() {
    local expected="$1"
    [[ "${PHASE}" == "${expected}" ]] || die "current phase is '${PHASE}', expected '${expected}'"
}

contains_line() {
    local file="$1"
    local pattern="$2"
    grep -Eiq "^[[:space:]]*${pattern}[[:space:]]*$" "${file}"
}

write_context() {
    local cycle_dir="$1"
    local cycle_id="$2"
    local auditor="$3"
    local reviewer="$4"
    local created_at="$5"

    {
        echo "# ${cycle_id} Context"
        echo
        echo "- Created: ${created_at}"
        echo "- Auditor/planner/implementer: ${auditor}"
        echo "- Adversarial reviewer/verifier: ${reviewer}"
        echo "- Goal: one small fixed-scope improvement toward top 0.1% Talos repo quality"
        echo
        echo "## Required Reading"
        echo
        echo "- AGENTS.md"
        echo "- CLAUDE.md when Claude is participating"
        echo "- nwarila-platform/.github org baseline when the deficiency touches governance, docs, CI, dependency updates, or style"
        echo
        echo "## Repository Snapshot"
        echo
        echo "- Branch: $(git -C "${ROOT_DIR}" branch --show-current 2>/dev/null || echo unknown)"
        echo "- HEAD: $(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
        echo
        echo '```'
        git -C "${ROOT_DIR}" status --short --branch 2>/dev/null || true
        echo '```'
    } > "${cycle_dir}/00-context.md"
}

write_templates() {
    local cycle_dir="$1"
    local cycle_id="$2"
    local auditor="$3"
    local reviewer="$4"

    cat > "${cycle_dir}/01-audit-and-plan.md" <<EOF
# ${cycle_id} Audit And Plan

Auditor/planner: ${auditor}
Reviewer: ${reviewer}
Status: draft
Audit outcome: deficiency

## Audit Scope

- Repository areas inspected:
- Org baseline material checked:
- Talos/Kubernetes best-practice material checked:
- Commands or evidence used:

## One Deficiency

TBD

## Why It Matters

TBD

## Proposed Plan

- Files affected:
- Behavior affected:
- Verification:
- Rollback/safety:

## Non-Goals

- TBD

## Auditor Decision

Ready for adversarial review: no
EOF

    cat > "${cycle_dir}/02-adversarial-review.md" <<EOF
# ${cycle_id} Adversarial Review

Reviewer: ${reviewer}
Auditor/planner: ${auditor}
Status: pending
Review decision: pending

## Review Checklist

- Is exactly one deficiency being addressed?
- Is the proposed scope small enough to review in isolation?
- Does the plan align with AGENTS.md and the org baseline?
- Are production-sensitive Talos paths handled cautiously?
- Is verification meaningful and feasible?
- Are rollback or safety considerations clear?

## Objections

TBD

## Required Revisions

TBD

## Decision Rationale

TBD
EOF

    cat > "${cycle_dir}/03-implementation.md" <<EOF
# ${cycle_id} Implementation Notes

Status: blocked until approve-plan
Implementation status: pending

## Changes Made

TBD

## Files Touched

TBD

## Deviations From Approved Plan

TBD
EOF

    cat > "${cycle_dir}/04-verification.md" <<EOF
# ${cycle_id} Verification

Status: pending implementation
Verification status: pending

## Commands Run

TBD

## Results

TBD

## Residual Risk

TBD
EOF

    cat > "${cycle_dir}/05-retrospective.md" <<EOF
# ${cycle_id} Retrospective

Loop recommendation: continue

## Outcome

TBD

## What Improved

TBD

## What Remains

TBD

## Next Auditor

${reviewer}
EOF
}

create_cycle() {
    local auditor="$1"
    local slug="$2"
    local reviewer number created_at cycle_id cycle_dir

    if [[ -f "${CURRENT_FILE}" ]]; then
        die "an active cycle already exists: $(<"${CURRENT_FILE}")"
    fi

    reviewer="$(other_agent "${auditor}")"
    number="$(next_cycle_number)"
    created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cycle_id="${number}-$(date -u +%Y%m%dT%H%M%SZ)-${slug}"
    cycle_dir="${CYCLES_DIR}/${cycle_id}"

    mkdir -p "${cycle_dir}" "${LOOP_DIR}"
    cat > "${cycle_dir}/state.env" <<EOF
CYCLE_ID='${cycle_id}'
AUDITOR='${auditor}'
REVIEWER='${reviewer}'
CREATED_AT='${created_at}'
EOF
    printf '%s\n' "audit" > "${cycle_dir}/phase"
    : > "${cycle_dir}/events.log"
    CYCLE_DIR="${cycle_dir}"
    log_event "created auditor=${auditor} reviewer=${reviewer}"

    write_context "${cycle_dir}" "${cycle_id}" "${auditor}" "${reviewer}" "${created_at}"
    write_templates "${cycle_dir}" "${cycle_id}" "${auditor}" "${reviewer}"
    printf '%s\n' "${cycle_dir}" > "${CURRENT_FILE}"
}

agent_prompt_file() {
    local phase="$1"
    printf '%s/prompt-%s.md' "${CYCLE_DIR}" "${phase}"
}

write_agent_prompt() {
    local phase="$1"
    local prompt_file
    prompt_file="$(agent_prompt_file "${phase}")"

    case "${phase}" in
        audit)
            cat > "${prompt_file}" <<EOF
You are ${AUDITOR}, the auditor/planner for ${CYCLE_ID}.

Read AGENTS.md and ${CYCLE_DIR}/00-context.md.

Perform an adversarial audit of the repository. Identify exactly one deficiency
worth fixing next. Keep the scope small. Fill ${CYCLE_DIR}/01-audit-and-plan.md.
Do not implement anything.

If a deficiency exists, set:
  Audit outcome: deficiency
  Ready for adversarial review: yes

If you genuinely believe no meaningful deficiency remains, set:
  Audit outcome: no-deficiency
  Ready for adversarial review: yes

Do not change phase files. Do not run scripts/agent-loop.sh yourself.
EOF
            ;;
        review)
            cat > "${prompt_file}" <<EOF
You are ${REVIEWER}, the adversarial reviewer for ${CYCLE_ID}.

Read AGENTS.md, ${CYCLE_DIR}/00-context.md, and
${CYCLE_DIR}/01-audit-and-plan.md.

Review the plan as an adversary. Fill ${CYCLE_DIR}/02-adversarial-review.md.

Set exactly one decision:
  Review decision: approved
  Review decision: needs-revision
  Review decision: stop

Use "approved" only if the plan is small, clear, safe, and verifiable.
Use "needs-revision" if the plan should return to the auditor.
Use "stop" only if the auditor wrote "Audit outcome: no-deficiency" and you
agree the repository is aligned enough to stop the autonomous loop.

Do not implement anything. Do not change phase files. Do not run
scripts/agent-loop.sh yourself.
EOF
            ;;
        implement)
            cat > "${prompt_file}" <<EOF
You are ${AUDITOR}, the implementer for ${CYCLE_ID}.

Read AGENTS.md, ${CYCLE_DIR}/01-audit-and-plan.md, and
${CYCLE_DIR}/02-adversarial-review.md.

Implement only the approved fixed-scope plan. Do not add unrelated cleanup.
Fill ${CYCLE_DIR}/03-implementation.md and set:
  Implementation status: complete

If implementation is impossible or unsafe, explain why and set:
  Implementation status: blocked

Do not change phase files. Do not run scripts/agent-loop.sh yourself.
EOF
            ;;
        verify)
            cat > "${prompt_file}" <<EOF
You are ${REVIEWER}, the verifier for ${CYCLE_ID}.

Read AGENTS.md and all cycle files in ${CYCLE_DIR}. Verify the implemented
change with the smallest meaningful command set. Fill
${CYCLE_DIR}/04-verification.md and ${CYCLE_DIR}/05-retrospective.md.

Set:
  Verification status: passed

or:
  Verification status: failed

In the retrospective, set:
  Loop recommendation: continue

or:
  Loop recommendation: stop

Use "stop" only if both the implemented change is verified and no further
high-value fixed-scope deficiencies remain.

Do not change phase files. Do not run scripts/agent-loop.sh yourself.
EOF
            ;;
        *)
            die "unknown phase '${phase}'"
            ;;
    esac

    printf '%s\n' "${prompt_file}"
}

run_real_agent() {
    local agent="$1"
    local prompt_file="$2"
    local log_file="$3"

    if [[ "${agent}" == "codex" ]]; then
        if [[ -n "${AGENT_CODEX_CMD:-}" ]]; then
            (cd "${ROOT_DIR}" && bash -lc "${AGENT_CODEX_CMD}" < "${prompt_file}") > "${log_file}" 2>&1
        else
            command -v codex >/dev/null 2>&1 || die "codex command not found; set AGENT_CODEX_CMD"
            local model
            local effort
            local models="${AGENT_CODEX_MODEL:-gpt-5.5 gpt-5.4 gpt-5.3-codex gpt-5.2}"
            local efforts="${AGENT_CODEX_EFFORT:-max xhigh}"
            local attempt_log
            : > "${log_file}"
            for model in ${models}; do
                for effort in ${efforts}; do
                    attempt_log="${log_file}.${model}.${effort}.tmp"
                    {
                        echo "==> Trying Codex model: ${model} effort: ${effort}"
                        codex exec --full-auto -m "${model}" -c "model_reasoning_effort=\"${effort}\"" -C "${ROOT_DIR}" - < "${prompt_file}"
                    } > "${attempt_log}" 2>&1 || true
                    cat "${attempt_log}" >> "${log_file}"

                    if ! agent_log_has_runtime_error "${attempt_log}"; then
                        rm -f "${attempt_log}"
                        return 0
                    fi

                    echo "==> Codex model/effort failed, trying next fallback if available." >> "${log_file}"
                    rm -f "${attempt_log}"
                done
            done
            return 1
        fi
    elif [[ "${agent}" == "claude" ]]; then
        if [[ -n "${AGENT_CLAUDE_CMD:-}" ]]; then
            (cd "${ROOT_DIR}" && bash -lc "${AGENT_CLAUDE_CMD}" < "${prompt_file}") > "${log_file}" 2>&1
        else
            command -v claude >/dev/null 2>&1 || die "claude command not found; set AGENT_CLAUDE_CMD"
            local model
            local effort
            local models="${AGENT_CLAUDE_MODEL:-opus claude-opus-4-7}"
            local efforts="${AGENT_CLAUDE_EFFORT:-max}"
            local attempt_log
            : > "${log_file}"
            for model in ${models}; do
                for effort in ${efforts}; do
                    attempt_log="${log_file}.${model}.${effort}.tmp"
                    {
                        echo "==> Trying Claude model: ${model} effort: ${effort}"
                        claude -p --permission-mode auto --model "${model}" --effort "${effort}" < "${prompt_file}"
                    } > "${attempt_log}" 2>&1 || true
                    cat "${attempt_log}" >> "${log_file}"

                    if ! agent_log_has_runtime_error "${attempt_log}"; then
                        rm -f "${attempt_log}"
                        return 0
                    fi

                    echo "==> Claude model/effort failed, trying next fallback if available." >> "${log_file}"
                    rm -f "${attempt_log}"
                done
            done
            return 1
        fi
    else
        die "unknown agent '${agent}'"
    fi
}

agent_log_has_runtime_error() {
    local log_file="$1"
    grep -Eiq '(^ERROR:|invalid_request_error|requires a newer version|command not found|Authentication|rate limit|API Error|EACCES|EPERM)' "${log_file}"
}

write_rebound_prompt() {
    local phase="$1"
    local reason="$2"
    local prompt_file
    prompt_file="${CYCLE_DIR}/prompt-${phase}-rebound.md"

    cat > "${prompt_file}" <<EOF
You are repairing phase '${phase}' for cycle ${CYCLE_ID}.

The autonomous supervisor rejected the previous phase output for this reason:

${reason}

Read AGENTS.md plus the current cycle files in ${CYCLE_DIR}. Repair only the
artifact required for this phase. Do not broaden scope. Do not change phase
files. Do not run scripts/agent-loop.sh.

Required phase artifact rules:

- audit: ${CYCLE_DIR}/01-audit-and-plan.md must set "Ready for adversarial review: yes".
- review: ${CYCLE_DIR}/02-adversarial-review.md must set exactly one valid "Review decision".
- implement: ${CYCLE_DIR}/03-implementation.md must set "Implementation status: complete" or "blocked".
- verify: ${CYCLE_DIR}/04-verification.md must set "Verification status: passed" or "failed".
EOF

    printf '%s\n' "${prompt_file}"
}

run_rebound_phase() {
    local phase="$1"
    local agent="$2"
    local reason="$3"
    local fake_agents="$4"
    local attempt="$5"
    local prompt_file log_file

    prompt_file="$(write_rebound_prompt "${phase}" "${reason}")"
    log_file="${CYCLE_DIR}/agent-${phase}-${agent}-rebound-${attempt}.log"
    log_event "agent-rebound-start phase=${phase} agent=${agent} attempt=${attempt}"

    if [[ "${fake_agents}" == "true" ]]; then
        run_fake_agent "${phase}" "${agent}" "${log_file}"
    else
        if ! run_real_agent "${agent}" "${prompt_file}" "${log_file}"; then
            log_event "agent-error phase=${phase} agent=${agent} log=${log_file}"
            die "agent '${agent}' failed during phase '${phase}'; see ${log_file}"
        fi
        if agent_log_has_runtime_error "${log_file}"; then
            log_event "agent-runtime-error phase=${phase} agent=${agent} log=${log_file}"
            die "agent '${agent}' reported a runtime error during phase '${phase}'; see ${log_file}"
        fi
    fi

    log_event "agent-rebound-finish phase=${phase} agent=${agent} attempt=${attempt} log=${log_file}"
}

run_fake_agent() {
    local phase="$1"
    local agent="$2"
    local log_file="$3"

    case "${phase}" in
        audit)
            cat > "${CYCLE_DIR}/01-audit-and-plan.md" <<EOF
# ${CYCLE_ID} Audit And Plan

Auditor/planner: ${agent}
Reviewer: ${REVIEWER}
Status: ready
Audit outcome: deficiency

## Audit Scope

- Repository areas inspected: fake smoke test
- Org baseline material checked: fake smoke test
- Talos/Kubernetes best-practice material checked: fake smoke test
- Commands or evidence used: fake agent mode

## One Deficiency

The fake agent identified a test-only deficiency.

## Why It Matters

This proves autonomous phase handling without calling an LLM.

## Proposed Plan

- Files affected: none
- Behavior affected: none
- Verification: fake verification
- Rollback/safety: no repository edits

## Non-Goals

- No real implementation.

## Auditor Decision

Ready for adversarial review: yes
EOF
            ;;
        review)
            sed -i 's/^Review decision: pending$/Review decision: approved/' "${CYCLE_DIR}/02-adversarial-review.md"
            sed -i 's/^Status: pending$/Status: approved/' "${CYCLE_DIR}/02-adversarial-review.md"
            ;;
        implement)
            sed -i 's/^Implementation status: pending$/Implementation status: complete/' "${CYCLE_DIR}/03-implementation.md"
            sed -i 's/^Status: blocked until approve-plan$/Status: complete/' "${CYCLE_DIR}/03-implementation.md"
            ;;
        verify)
            sed -i 's/^Verification status: pending$/Verification status: passed/' "${CYCLE_DIR}/04-verification.md"
            sed -i 's/^Status: pending implementation$/Status: complete/' "${CYCLE_DIR}/04-verification.md"
            ;;
        *)
            die "unknown fake phase '${phase}'"
            ;;
    esac

    {
        echo "fake ${agent} completed phase ${phase}"
        echo "cycle=${CYCLE_ID}"
    } > "${log_file}"
}

run_agent_phase() {
    local phase="$1"
    local agent="$2"
    local fake_agents="$3"
    local prompt_file log_file

    prompt_file="$(write_agent_prompt "${phase}")"
    log_file="${CYCLE_DIR}/agent-${phase}-${agent}.log"
    log_event "agent-start phase=${phase} agent=${agent}"

    if [[ "${fake_agents}" == "true" ]]; then
        run_fake_agent "${phase}" "${agent}" "${log_file}"
    else
        if ! run_real_agent "${agent}" "${prompt_file}" "${log_file}"; then
            log_event "agent-rebound-error phase=${phase} agent=${agent} attempt=${attempt} log=${log_file}"
            die "agent '${agent}' failed during rebound for phase '${phase}'; see ${log_file}"
        fi
        if agent_log_has_runtime_error "${log_file}"; then
            log_event "agent-rebound-runtime-error phase=${phase} agent=${agent} attempt=${attempt} log=${log_file}"
            die "agent '${agent}' reported a runtime error during rebound for phase '${phase}'; see ${log_file}"
        fi
    fi

    log_event "agent-finish phase=${phase} agent=${agent} log=${log_file}"
}

ensure_phase_valid() {
    local phase="$1"
    local agent="$2"
    local fake_agents="$3"
    local max_phase_retries="$4"
    local attempt=0
    local reason=""

    while true; do
        case "${phase}" in
            audit)
                audit_ready && return 0
                reason="${CYCLE_DIR}/01-audit-and-plan.md was not marked 'Ready for adversarial review: yes'."
                ;;
            review)
                case "$(review_decision)" in
                    approved|needs-revision|stop) return 0 ;;
                    *) reason="${CYCLE_DIR}/02-adversarial-review.md did not set Review decision to approved, needs-revision, or stop." ;;
                esac
                ;;
            implement)
                case "$(implementation_status)" in
                    complete|blocked) return 0 ;;
                    *) reason="${CYCLE_DIR}/03-implementation.md did not set Implementation status to complete or blocked." ;;
                esac
                ;;
            verify)
                case "$(verification_status)" in
                    passed|failed) return 0 ;;
                    *) reason="${CYCLE_DIR}/04-verification.md did not set Verification status to passed or failed." ;;
                esac
                ;;
            *)
                die "unknown validation phase '${phase}'"
                ;;
        esac

        if ((attempt >= max_phase_retries)); then
            log_event "phase-invalid phase=${phase} reason=${reason}"
            die "phase '${phase}' stayed invalid after ${max_phase_retries} rebound attempt(s): ${reason}"
        fi

        attempt=$((attempt + 1))
        run_rebound_phase "${phase}" "${agent}" "${reason}" "${fake_agents}" "${attempt}"
    done
}

audit_ready() {
    contains_line "${CYCLE_DIR}/01-audit-and-plan.md" 'Ready for adversarial review:[[:space:]]*yes'
}

audit_outcome() {
    if contains_line "${CYCLE_DIR}/01-audit-and-plan.md" 'Audit outcome:[[:space:]]*no-deficiency'; then
        echo "no-deficiency"
    else
        echo "deficiency"
    fi
}

review_decision() {
    if contains_line "${CYCLE_DIR}/02-adversarial-review.md" 'Review decision:[[:space:]]*approved'; then
        echo "approved"
    elif contains_line "${CYCLE_DIR}/02-adversarial-review.md" 'Review decision:[[:space:]]*needs-revision'; then
        echo "needs-revision"
    elif contains_line "${CYCLE_DIR}/02-adversarial-review.md" 'Review decision:[[:space:]]*stop'; then
        echo "stop"
    else
        echo "pending"
    fi
}

implementation_status() {
    if contains_line "${CYCLE_DIR}/03-implementation.md" 'Implementation status:[[:space:]]*complete'; then
        echo "complete"
    elif contains_line "${CYCLE_DIR}/03-implementation.md" 'Implementation status:[[:space:]]*blocked'; then
        echo "blocked"
    else
        echo "pending"
    fi
}

verification_status() {
    if contains_line "${CYCLE_DIR}/04-verification.md" 'Verification status:[[:space:]]*passed'; then
        echo "passed"
    elif contains_line "${CYCLE_DIR}/04-verification.md" 'Verification status:[[:space:]]*failed'; then
        echo "failed"
    else
        echo "pending"
    fi
}

loop_recommendation() {
    if contains_line "${CYCLE_DIR}/05-retrospective.md" 'Loop recommendation:[[:space:]]*stop'; then
        echo "stop"
    else
        echo "continue"
    fi
}

complete_current_cycle() {
    local recommendation="$1"
    if [[ -f "${CYCLE_DIR}/05-retrospective.md" ]]; then
        sed -i "s/^Loop recommendation: .*$/Loop recommendation: ${recommendation}/" "${CYCLE_DIR}/05-retrospective.md"
    fi
    set_phase complete
    printf '%s\n' "${REVIEWER}" > "${NEXT_AUDITOR_FILE}"
    rm -f "${CURRENT_FILE}"
    log_event "completed recommendation=${recommendation} next-auditor=${REVIEWER}"
}

run_current_cycle() {
    local max_revisions="$1"
    local fake_agents="$2"
    local max_phase_retries="$3"
    local revisions=0
    local decision status recommendation

    load_current
    while true; do
        case "${PHASE}" in
            audit)
                run_agent_phase audit "${AUDITOR}" "${fake_agents}"
                ensure_phase_valid audit "${AUDITOR}" "${fake_agents}" "${max_phase_retries}"
                set_phase review
                ;;
            review)
                run_agent_phase review "${REVIEWER}" "${fake_agents}"
                ensure_phase_valid review "${REVIEWER}" "${fake_agents}" "${max_phase_retries}"
                decision="$(review_decision)"
                case "${decision}" in
                    approved)
                        if [[ "$(audit_outcome)" == "no-deficiency" ]]; then
                            die "review approved implementation but audit outcome is no-deficiency; expected Review decision: stop"
                        fi
                        set_phase implement
                        ;;
                    needs-revision)
                        revisions=$((revisions + 1))
                        if ((revisions > max_revisions)); then
                            die "plan exceeded max revisions (${max_revisions}); see ${CYCLE_DIR}"
                        fi
                        log_event "revision-request count=${revisions}"
                        set_phase audit
                        ;;
                    stop)
                        if [[ "$(audit_outcome)" != "no-deficiency" ]]; then
                            die "review requested stop without Audit outcome: no-deficiency"
                        fi
                        complete_current_cycle stop
                        echo "stop"
                        return
                        ;;
                    *)
                        die "review did not set a valid decision; see ${CYCLE_DIR}/02-adversarial-review.md"
                        ;;
                esac
                ;;
            implement)
                run_agent_phase implement "${AUDITOR}" "${fake_agents}"
                ensure_phase_valid implement "${AUDITOR}" "${fake_agents}" "${max_phase_retries}"
                status="$(implementation_status)"
                case "${status}" in
                    complete) set_phase verify ;;
                    blocked) die "implementation blocked; see ${CYCLE_DIR}/03-implementation.md" ;;
                    *) die "implementation did not complete; see ${CYCLE_DIR}/03-implementation.md" ;;
                esac
                ;;
            verify)
                run_agent_phase verify "${REVIEWER}" "${fake_agents}"
                ensure_phase_valid verify "${REVIEWER}" "${fake_agents}" "${max_phase_retries}"
                status="$(verification_status)"
                case "${status}" in
                    passed)
                        recommendation="$(loop_recommendation)"
                        complete_current_cycle "${recommendation}"
                        echo "${recommendation}"
                        return
                        ;;
                    failed)
                        die "verification failed; see ${CYCLE_DIR}/04-verification.md"
                        ;;
                    *)
                        die "verification did not set a valid status; see ${CYCLE_DIR}/04-verification.md"
                        ;;
                esac
                ;;
            complete)
                echo "$(loop_recommendation)"
                return
                ;;
            *)
                die "unknown phase '${PHASE}'"
                ;;
        esac
    done
}

command_start() {
    local auditor=""
    local slug="unspecified-deficiency"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --auditor)
                [[ $# -ge 2 ]] || die "--auditor requires a value"
                auditor="$(normalize_agent "$2")"
                shift 2
                ;;
            --slug)
                [[ $# -ge 2 ]] || die "--slug requires a value"
                slug="$(sanitize_slug "$2")"
                shift 2
                ;;
            *)
                die "unknown start argument '$1'"
                ;;
        esac
    done

    if [[ -z "${auditor}" ]]; then
        if [[ -f "${NEXT_AUDITOR_FILE}" ]]; then
            auditor="$(normalize_agent "$(<"${NEXT_AUDITOR_FILE}")")"
        else
            auditor="codex"
        fi
    fi

    create_cycle "${auditor}" "${slug}"
    echo "Started cycle ${CYCLE_ID}"
    echo "Auditor/planner: ${AUDITOR}"
    echo "Reviewer:        ${REVIEWER}"
    echo "Files:           ${CYCLE_DIR}"
    echo
    command_prompt audit
}

command_run() {
    local auditor=""
    local slug="autonomous"
    local max_cycles="${DEFAULT_MAX_CYCLES}"
    local max_revisions="${DEFAULT_MAX_REVISIONS}"
    local max_phase_retries="${DEFAULT_MAX_PHASE_RETRIES}"
    local fake_agents="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --auditor)
                [[ $# -ge 2 ]] || die "--auditor requires a value"
                auditor="$(normalize_agent "$2")"
                shift 2
                ;;
            --slug)
                [[ $# -ge 2 ]] || die "--slug requires a value"
                slug="$(sanitize_slug "$2")"
                shift 2
                ;;
            --max-cycles)
                [[ $# -ge 2 ]] || die "--max-cycles requires a value"
                max_cycles="$2"
                shift 2
                ;;
            --max-revisions)
                [[ $# -ge 2 ]] || die "--max-revisions requires a value"
                max_revisions="$2"
                shift 2
                ;;
            --max-phase-retries)
                [[ $# -ge 2 ]] || die "--max-phase-retries requires a value"
                max_phase_retries="$2"
                shift 2
                ;;
            --fake-agents)
                fake_agents="true"
                shift
                ;;
            *)
                die "unknown run argument '$1'"
                ;;
        esac
    done

    [[ "${max_cycles}" =~ ^[0-9]+$ ]] || die "--max-cycles must be numeric"
    [[ "${max_revisions}" =~ ^[0-9]+$ ]] || die "--max-revisions must be numeric"
    [[ "${max_phase_retries}" =~ ^[0-9]+$ ]] || die "--max-phase-retries must be numeric"
    ((max_cycles >= 1)) || die "--max-cycles must be at least 1"

    local cycle=1
    local recommendation="continue"

    while ((cycle <= max_cycles)); do
        if [[ ! -f "${CURRENT_FILE}" ]]; then
            if [[ -z "${auditor}" ]]; then
                if [[ -f "${NEXT_AUDITOR_FILE}" ]]; then
                    auditor="$(normalize_agent "$(<"${NEXT_AUDITOR_FILE}")")"
                else
                    auditor="codex"
                fi
            fi
            create_cycle "${auditor}" "${slug}"
        fi

        load_current
        echo "==> Autonomous cycle ${cycle}/${max_cycles}: ${CYCLE_ID}"
        echo "    auditor=${AUDITOR} reviewer=${REVIEWER} phase=${PHASE}"
        recommendation="$(run_current_cycle "${max_revisions}" "${fake_agents}" "${max_phase_retries}")"
        echo "==> Cycle ${CYCLE_ID} complete: ${recommendation}"

        if [[ "${recommendation}" == "stop" ]]; then
            echo "==> Stop condition reached."
            return
        fi

        auditor=""
        cycle=$((cycle + 1))
    done

    echo "==> Reached max cycles (${max_cycles})."
    if [[ -f "${NEXT_AUDITOR_FILE}" ]]; then
        echo "==> Next auditor: $(<"${NEXT_AUDITOR_FILE}")"
    fi
}

command_status() {
    if [[ ! -f "${CURRENT_FILE}" ]]; then
        echo "No active cycle."
        if [[ -f "${NEXT_AUDITOR_FILE}" ]]; then
            echo "Next auditor: $(<"${NEXT_AUDITOR_FILE}")"
        else
            echo "Next auditor: codex"
        fi
        return
    fi

    load_current
    echo "Active cycle: ${CYCLE_ID}"
    echo "Phase:        ${PHASE}"
    echo "Auditor:      ${AUDITOR}"
    echo "Reviewer:     ${REVIEWER}"
    echo "Directory:    ${CYCLE_DIR}"
    echo
    echo "Recent events:"
    tail -n 10 "${CYCLE_DIR}/events.log" 2>/dev/null || true
}

command_monitor() {
    command_status
    if [[ -f "${CURRENT_FILE}" ]]; then
        echo
        echo "Latest agent logs:"
        find "${CYCLE_DIR}" -maxdepth 1 -name 'agent-*.log' -type f -printf '%f\n' 2>/dev/null | sort | tail -n 5 || true
    fi
}

command_prompt() {
    local kind="${1:-}"
    if [[ -z "${kind}" ]]; then
        die "prompt requires one of: audit, review, implement, verify"
    fi
    load_current
    write_agent_prompt "${kind}"
}

command_audit_ready() {
    load_current
    require_phase audit
    set_phase review
    echo "Cycle ${CYCLE_ID} is ready for ${REVIEWER} review."
}

command_approve_plan() {
    load_current
    require_phase review
    set_phase implement
    echo "Cycle ${CYCLE_ID} is approved for implementation."
}

command_request_revision() {
    load_current
    require_phase review
    set_phase audit
    echo "Cycle ${CYCLE_ID} returned to ${AUDITOR} for plan revision."
}

command_implementation_done() {
    load_current
    require_phase implement
    set_phase verify
    echo "Cycle ${CYCLE_ID} is ready for verification."
}

command_complete() {
    load_current
    require_phase verify
    complete_current_cycle continue
    echo "Completed cycle ${CYCLE_ID}."
    echo "Next cycle auditor/planner: ${REVIEWER}"
}

main() {
    local command="${1:-help}"
    if [[ $# -gt 0 ]]; then
        shift
    fi

    case "${command}" in
        help|-h|--help) usage ;;
        run) command_run "$@" ;;
        start) command_start "$@" ;;
        status) command_status ;;
        monitor) command_monitor ;;
        prompt) command_prompt "$@" ;;
        audit-ready) command_audit_ready ;;
        approve-plan) command_approve_plan ;;
        request-revision) command_request_revision ;;
        implementation-done) command_implementation_done ;;
        complete) command_complete ;;
        *) die "unknown command '${command}'" ;;
    esac
}

main "$@"
