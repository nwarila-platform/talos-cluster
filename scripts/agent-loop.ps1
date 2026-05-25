#Requires -Version 5.1
<#
.SYNOPSIS
Autonomous Codex/Claude improvement loop for this Talos cluster repository.

.DESCRIPTION
Runs fresh-window Codex and Claude passes until MaxCycles, STOP file, verified
stop recommendation, bounded repair exhaustion, or fatal tool failure.

The loop is intentionally native PowerShell on Windows. It does not use WSL or
Git Bash. It resolves codex/claude .cmd/.exe shims, pipes prompts through stdin,
captures logs, validates structured JSON artifacts, and automatically rebounds
malformed phase output a bounded number of times.

.EXAMPLE
.\scripts\agent-loop.ps1 run

.EXAMPLE
.\scripts\agent-loop.ps1 run --max-cycles 5

.EXAMPLE
.\scripts\agent-loop.ps1 monitor

.EXAMPLE
.\scripts\agent-loop.ps1 run --fake-agents --max-cycles 2
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RawArgs
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Argument parsing accepts both PowerShell-ish and bash-ish flags so existing
# commands like ".\scripts\agent-loop.ps1 run --max-cycles 3" keep working.
# ---------------------------------------------------------------------------
$Command = 'run'
$MaxCycles = 0
$SleepSeconds = 30
$MaxPlanRevisions = 3
$MaxPhaseRetries = 2
$AutoRepairRetries = 1
$StopAfterNoChangesFor = 3
$CodexModels = @('gpt-5.5', 'gpt-5.4', 'gpt-5.3-codex', 'gpt-5.2')
$CodexReasoningEfforts = @('max', 'xhigh')
$ClaudeModels = @('opus', 'claude-opus-4-7')
$ClaudeEfforts = @('max')
$ClaudeMaxRetries = 2
$ClaudeRetryDelaySeconds = 30
$LogDir = ''
$StopFile = ''
$InitialAuditor = ''
$Slug = 'autonomous'
$ContinueOnCodexError = $false
$ContinueOnReviewError = $false
$ContinueOnImplementError = $false
$ContinueOnVerifyError = $false
$FakeAgents = $false

function Pop-ArgValue {
    param(
        [string[]]$ArgList,
        [ref]$Index,
        [string]$Name
    )
    if (($Index.Value + 1) -ge $ArgList.Count) {
        throw "$Name requires a value."
    }
    $Index.Value++
    return $ArgList[$Index.Value]
}

for ($i = 0; $i -lt $RawArgs.Count; $i++) {
    $arg = $RawArgs[$i]
    if ($i -eq 0 -and $arg -in @('run', 'status', 'monitor', 'help')) {
        $Command = $arg
        continue
    }

    switch -Regex ($arg) {
        '^(--max-cycles|-MaxCycles)$' { $MaxCycles = [int](Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg); continue }
        '^(--sleep-seconds|-SleepSeconds)$' { $SleepSeconds = [int](Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg); continue }
        '^(--max-plan-revisions|-MaxPlanRevisions)$' { $MaxPlanRevisions = [int](Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg); continue }
        '^(--max-phase-retries|-MaxPhaseRetries)$' { $MaxPhaseRetries = [int](Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg); continue }
        '^(--auto-repair-retries|-AutoRepairRetries)$' { $AutoRepairRetries = [int](Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg); continue }
        '^(--stop-after-no-changes-for|-StopAfterNoChangesFor)$' { $StopAfterNoChangesFor = [int](Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg); continue }
        '^(--codex-model|-CodexModel)$' { $CodexModels = @((Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg) -split '[, ]+' | Where-Object { $_ }); continue }
        '^(--codex-models|-CodexModels)$' { $CodexModels = @((Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg) -split '[, ]+' | Where-Object { $_ }); continue }
        '^(--codex-reasoning-effort|-CodexReasoningEffort)$' { $CodexReasoningEfforts = @((Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg) -split '[, ]+' | Where-Object { $_ }); continue }
        '^(--codex-reasoning-efforts|-CodexReasoningEfforts)$' { $CodexReasoningEfforts = @((Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg) -split '[, ]+' | Where-Object { $_ }); continue }
        '^(--claude-model|-ClaudeModel)$' { $ClaudeModels = @((Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg) -split '[, ]+' | Where-Object { $_ }); continue }
        '^(--claude-models|-ClaudeModels)$' { $ClaudeModels = @((Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg) -split '[, ]+' | Where-Object { $_ }); continue }
        '^(--claude-effort|-ClaudeEffort)$' { $ClaudeEfforts = @((Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg) -split '[, ]+' | Where-Object { $_ }); continue }
        '^(--claude-efforts|-ClaudeEfforts)$' { $ClaudeEfforts = @((Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg) -split '[, ]+' | Where-Object { $_ }); continue }
        '^(--claude-max-retries|-ClaudeMaxRetries)$' { $ClaudeMaxRetries = [int](Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg); continue }
        '^(--claude-retry-delay-seconds|-ClaudeRetryDelaySeconds)$' { $ClaudeRetryDelaySeconds = [int](Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg); continue }
        '^(--log-dir|-LogDir)$' { $LogDir = Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg; continue }
        '^(--stop-file|-StopFile)$' { $StopFile = Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg; continue }
        '^(--auditor|-Auditor)$' { $InitialAuditor = (Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg).ToLowerInvariant(); continue }
        '^(--slug|-Slug)$' { $Slug = Pop-ArgValue -ArgList $RawArgs -Index ([ref]$i) -Name $arg; continue }
        '^(--continue-on-codex-error|-ContinueOnCodexError)$' { $ContinueOnCodexError = $true; continue }
        '^(--continue-on-review-error|-ContinueOnReviewError)$' { $ContinueOnReviewError = $true; continue }
        '^(--continue-on-implement-error|-ContinueOnImplementError)$' { $ContinueOnImplementError = $true; continue }
        '^(--continue-on-verify-error|-ContinueOnVerifyError)$' { $ContinueOnVerifyError = $true; continue }
        '^(--fake-agents|-FakeAgents)$' { $FakeAgents = $true; continue }
        default { throw "Unknown argument: $arg" }
    }
}

if ($InitialAuditor -and $InitialAuditor -notin @('codex', 'claude')) {
    throw "Auditor must be codex or claude."
}

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$RunRoot = Join-Path $RepoRoot '.agent-loop\autonomous'
$CurrentRunFile = Join-Path $RunRoot 'current-run'
$NextAuditorFile = Join-Path $RunRoot 'next-auditor'
if ([string]::IsNullOrWhiteSpace($StopFile)) {
    $StopFile = Join-Path $RunRoot 'STOP'
} elseif (-not [System.IO.Path]::IsPathRooted($StopFile)) {
    $StopFile = Join-Path $RepoRoot $StopFile
}
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

function Write-Usage {
    @"
Usage:
  .\scripts\agent-loop.ps1 run [--max-cycles N] [--auditor codex|claude]
  .\scripts\agent-loop.ps1 status
  .\scripts\agent-loop.ps1 monitor

Useful flags:
  --max-cycles N              0 means forever. Default: 0
  --max-plan-revisions N      Default: 3
  --max-phase-retries N       Default: 2
  --auto-repair-retries N     Default: 1
  --stop-file PATH            Default: .agent-loop\autonomous\STOP
  --codex-models "A B"        Default: gpt-5.5 gpt-5.4 gpt-5.3-codex gpt-5.2
  --codex-reasoning-efforts   Default: max xhigh (xhigh is compatibility fallback)
  --claude-models "A B"       Default: opus claude-opus-4-7
  --claude-efforts "A B"      Default: max
  --fake-agents               Smoke-test the supervisor without real LLM calls
"@
}

function Add-ProcessGitConfig {
    param([string]$Key, [string]$Value)
    $count = 0
    if ($env:GIT_CONFIG_COUNT -match '^\d+$') {
        $count = [int]$env:GIT_CONFIG_COUNT
    }
    Set-Item -Path "Env:GIT_CONFIG_KEY_$count" -Value $Key
    Set-Item -Path "Env:GIT_CONFIG_VALUE_$count" -Value $Value
    $env:GIT_CONFIG_COUNT = [string]($count + 1)
}

function Resolve-Cli {
    param([string]$Name)
    foreach ($variant in @("$Name.cmd", "$Name.exe", $Name)) {
        $candidate = Get-Command $variant -ErrorAction SilentlyContinue
        if ($candidate -and $candidate.Source -notlike '*.ps1') {
            return $candidate.Source
        }
    }
    return $null
}

function Get-OtherAgent {
    param([string]$Agent)
    if ($Agent -eq 'codex') { return 'claude' }
    return 'codex'
}

function Get-NextAuditor {
    if ($InitialAuditor) { return $InitialAuditor }
    if (Test-Path -LiteralPath $NextAuditorFile) {
        $value = (Get-Content -LiteralPath $NextAuditorFile -Raw).Trim().ToLowerInvariant()
        if ($value -in @('codex', 'claude')) { return $value }
    }
    return 'codex'
}

function ConvertTo-Slug {
    param([string]$Value)
    $slugValue = $Value.ToLowerInvariant() -replace '[^a-z0-9]+', '-'
    $slugValue = $slugValue.Trim('-')
    if ([string]::IsNullOrWhiteSpace($slugValue)) { return 'autonomous' }
    return $slugValue
}

function Get-HeadSha {
    Push-Location -LiteralPath $RepoRoot
    try {
        $sha = & git rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { return $sha.Trim() }
        return ''
    } finally {
        Pop-Location
    }
}

function Get-WorktreeFingerprint {
    Push-Location -LiteralPath $RepoRoot
    try {
        $status = (& git status --porcelain=v1 --untracked-files=all -- . ':!.agent-loop' 2>$null) -join "`n"
        $diff = (& git diff --numstat -- . ':!.agent-loop' 2>$null) -join "`n"
        return "$status`n---diff---`n$diff"
    } finally {
        Pop-Location
    }
}

function Test-StopRequested {
    return (Test-Path -LiteralPath $StopFile)
}

function Test-AgentRuntimeError {
    param([string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $text = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
        if ($text -match '(?im)(^ERROR:|invalid_request_error|requires a newer version|Authentication|API Error|rate limit|EACCES|EPERM|command not found)') {
            return $true
        }
    }
    return $false
}

function Invoke-NativeWithPrompt {
    param(
        [string]$Exe,
        [string[]]$Arguments,
        [string]$PromptPath,
        [string]$StdoutPath,
        [string]$StderrPath
    )
    Remove-Item -LiteralPath $StdoutPath, $StderrPath -ErrorAction SilentlyContinue
    Push-Location -LiteralPath $RepoRoot
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        Get-Content -LiteralPath $PromptPath | & $Exe @Arguments 2>$StderrPath |
            Tee-Object -FilePath $StdoutPath |
            ForEach-Object { Write-Host $_ }
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
        Pop-Location
    }
}

function Invoke-Codex {
    param(
        [string]$PromptPath,
        [string]$FinalMessagePath,
        [string]$StdoutPath,
        [string]$StderrPath
    )
    if ($FakeAgents) { return 0 }
    if (-not $script:CodexExe) { throw 'codex CLI not found on PATH.' }

    $combinedStdout = $StdoutPath
    $combinedStderr = $StderrPath
    Remove-Item -LiteralPath $combinedStdout, $combinedStderr, $FinalMessagePath -ErrorAction SilentlyContinue

    foreach ($model in $CodexModels) {
        foreach ($effort in $CodexReasoningEfforts) {
            $attemptSlug = ConvertTo-Slug "$model-$effort"
            $attemptStdout = "$StdoutPath.$attemptSlug.tmp"
            $attemptStderr = "$StderrPath.$attemptSlug.tmp"
            $attemptFinal = "$FinalMessagePath.$attemptSlug.tmp"
            $args = @(
                'exec',
                '--full-auto',
                '--cd', $RepoRoot,
                '--model', $model,
                '--output-last-message', $attemptFinal
            )
            if ($effort) {
                $args += @('-c', "model_reasoning_effort=`"$effort`"")
            }
            $args += '-'

            "==> Trying Codex model: $model effort: $effort" | Add-Content -LiteralPath $combinedStdout
            $exit = Invoke-NativeWithPrompt -Exe $script:CodexExe -Arguments $args -PromptPath $PromptPath -StdoutPath $attemptStdout -StderrPath $attemptStderr
            if (Test-Path -LiteralPath $attemptStdout) { Get-Content -LiteralPath $attemptStdout | Add-Content -LiteralPath $combinedStdout }
            if (Test-Path -LiteralPath $attemptStderr) { Get-Content -LiteralPath $attemptStderr | Add-Content -LiteralPath $combinedStderr }

            $runtimeError = Test-AgentRuntimeError @($attemptStdout, $attemptStderr)
            if ($exit -eq 0 -and -not $runtimeError) {
                if (Test-Path -LiteralPath $attemptFinal) {
                    Move-Item -LiteralPath $attemptFinal -Destination $FinalMessagePath -Force
                }
                Remove-Item -LiteralPath $attemptStdout, $attemptStderr -ErrorAction SilentlyContinue
                return 0
            }

            "==> Codex model $model effort $effort failed; trying next fallback if available." | Add-Content -LiteralPath $combinedStdout
            Remove-Item -LiteralPath $attemptStdout, $attemptStderr, $attemptFinal -ErrorAction SilentlyContinue
        }
    }

    return 1
}

function Invoke-Claude {
    param(
        [string]$PromptPath,
        [string]$StdoutPath,
        [string]$StderrPath,
        [string]$PhaseName
    )
    if ($FakeAgents) { return 0 }
    if (-not $script:ClaudeExe) { throw 'claude CLI not found on PATH.' }

    $combinedStdout = $StdoutPath
    $combinedStderr = $StderrPath
    Remove-Item -LiteralPath $combinedStdout, $combinedStderr -ErrorAction SilentlyContinue

    foreach ($model in $ClaudeModels) {
        foreach ($effort in $ClaudeEfforts) {
            $attemptSlug = ConvertTo-Slug "$model-$effort"
            $attemptStdout = "$StdoutPath.$attemptSlug.tmp"
            $attemptStderr = "$StderrPath.$attemptSlug.tmp"
            $args = @(
                '--print',
                '--permission-mode', 'auto',
                '--add-dir', $RepoRoot
            )
            if ($model) { $args += @('--model', $model) }
            if ($effort) { $args += @('--effort', $effort) }

            $attempt = 0
            $maxAttempts = [Math]::Max(1, 1 + [Math]::Max(0, $ClaudeMaxRetries))
            while ($attempt -lt $maxAttempts) {
                $attempt++
                "==> Trying Claude model: $model effort: $effort attempt: $attempt/$maxAttempts" | Add-Content -LiteralPath $combinedStdout
                $exit = Invoke-NativeWithPrompt -Exe $script:ClaudeExe -Arguments $args -PromptPath $PromptPath -StdoutPath $attemptStdout -StderrPath $attemptStderr
                if (Test-Path -LiteralPath $attemptStdout) { Get-Content -LiteralPath $attemptStdout | Add-Content -LiteralPath $combinedStdout }
                if (Test-Path -LiteralPath $attemptStderr) { Get-Content -LiteralPath $attemptStderr | Add-Content -LiteralPath $combinedStderr }

                if ($exit -eq 0 -and -not (Test-AgentRuntimeError @($attemptStdout, $attemptStderr))) {
                    Remove-Item -LiteralPath $attemptStdout, $attemptStderr -ErrorAction SilentlyContinue
                    return 0
                }
                if ($attempt -ge $maxAttempts) { break }
                Write-Warning "$PhaseName failed or looked transient; retrying in ${ClaudeRetryDelaySeconds}s ($attempt/$maxAttempts)."
                if ($ClaudeRetryDelaySeconds -gt 0) { Start-Sleep -Seconds $ClaudeRetryDelaySeconds }
            }

            "==> Claude model $model effort $effort failed; trying next fallback if available." | Add-Content -LiteralPath $combinedStdout
            Remove-Item -LiteralPath $attemptStdout, $attemptStderr -ErrorAction SilentlyContinue
        }
    }
    return 1
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $trimmed = $raw.Trim()
        if ($trimmed.StartsWith('```')) {
            $trimmed = $trimmed -replace '^```(?:json)?\s*', ''
            $trimmed = $trimmed -replace '\s*```\s*$', ''
        }
        return $trimmed | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Write-JsonFile {
    param([string]$Path, [object]$Value)
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function New-CycleContext {
    param(
        [string]$CycleDir,
        [string]$CycleId,
        [string]$Auditor,
        [string]$Reviewer,
        [string]$Mode
    )
    $contextPath = Join-Path $CycleDir '00-context.md'
    $status = ''
    Push-Location -LiteralPath $RepoRoot
    try {
        $status = (& git status --short --branch 2>$null) -join "`n"
    } finally {
        Pop-Location
    }
    @"
# $CycleId Context

- Created: $(Get-Date -Format o)
- Mode: $Mode
- Auditor/planner/implementer: $Auditor
- Reviewer/verifier: $Reviewer
- Goal: one small fixed-scope improvement toward top 0.1% Talos repo quality

## Required Reading

- AGENTS.md
- CLAUDE.md when Claude is participating
- nwarila-platform/.github org baseline when the deficiency touches governance, docs, CI, dependency updates, or style

## Repository Snapshot

``````
$status
``````
"@ | Set-Content -LiteralPath $contextPath -Encoding UTF8
    return $contextPath
}

function Write-AuditPrompt {
    param(
        [string]$Path,
        [string]$CycleDir,
        [string]$CycleId,
        [string]$Auditor,
        [string]$Reviewer,
        [string]$AuditJson,
        [string]$Mode,
        [string]$ReviewerFollowup
    )
    @"
You are $Auditor, the auditor/planner for autonomous cycle $CycleId.

Read AGENTS.md and $CycleDir/00-context.md.

Mode: $Mode

If $ReviewerFollowup exists and says pending=true, read it before auditing. The
one deficiency for this cycle is the pending reviewer repair or plan revision
unless it is demonstrably stale.

Perform an adversarial audit of the repository and identify exactly one
deficiency worth fixing next. Keep scope small. Do not implement anything.

Write exactly one JSON object to:

$AuditJson

Schema:
{
  "audit_outcome": "deficiency | no-deficiency",
  "ready_for_review": true,
  "deficiency": "one concrete deficiency, or empty when no-deficiency",
  "why_it_matters": "why this matters for top 0.1% Talos repo quality",
  "plan": {
    "summary": "one-sentence plan",
    "files_affected": [],
    "behavior_affected": "",
    "verification": [],
    "rollback_or_safety": "",
    "non_goals": []
  },
  "risk_notes": [],
  "stop_reason": ""
}

Rules:
- Exactly one deficiency.
- No implementation.
- No broad cleanup.
- If no meaningful deficiency remains, use audit_outcome=no-deficiency and
  still set ready_for_review=true.
- Do not run scripts/agent-loop.ps1 or scripts/agent-loop.sh.
"@ | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Write-ReviewPrompt {
    param(
        [string]$Path,
        [string]$CycleDir,
        [string]$CycleId,
        [string]$Reviewer,
        [string]$AuditJson,
        [string]$ReviewJson
    )
    @"
You are $Reviewer, the adversarial reviewer for autonomous cycle $CycleId.

Read AGENTS.md, $CycleDir/00-context.md, and:

$AuditJson

Adversarially review the plan. Do not implement anything.

Write exactly one JSON object to:

$ReviewJson

Schema:
{
  "review_decision": "approved | needs_revision | stop",
  "rationale": "short reason",
  "required_revisions": [],
  "risk_notes": [],
  "stop_reason": "",
  "repairable": false,
  "next_worker_action": ""
}

Use approved only if the plan is one deficiency, small, safe, and verifiable.
Use needs_revision for plan defects that the auditor can repair.
Use stop only when audit_outcome=no-deficiency and you agree, or when continuing
would be unsafe without operator review.
"@ | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Write-ImplementationPrompt {
    param(
        [string]$Path,
        [string]$CycleDir,
        [string]$CycleId,
        [string]$Auditor,
        [string]$AuditJson,
        [string]$ReviewJson,
        [string]$ImplementationJson
    )
    @"
You are $Auditor, the implementer for autonomous cycle $CycleId.

Read AGENTS.md, $AuditJson, and $ReviewJson.

Implement only the approved fixed-scope plan. Do not add unrelated cleanup.
Run the smallest meaningful validation set for the files you changed.

Write exactly one JSON object to:

$ImplementationJson

Schema:
{
  "implementation_status": "complete | blocked",
  "summary": "what changed",
  "files_touched": [],
  "validation_run": [],
  "validation_result": "passed | failed | not-run",
  "deviations_from_plan": [],
  "blocked_reason": "",
  "needs_repair": false
}

If implementation is unsafe or impossible, do not force it. Set blocked and
explain the blocked_reason.
"@ | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Write-VerificationPrompt {
    param(
        [string]$Path,
        [string]$CycleDir,
        [string]$CycleId,
        [string]$Reviewer,
        [string]$VerificationJson
    )
    @"
You are $Reviewer, the verifier for autonomous cycle $CycleId.

Read AGENTS.md and all cycle artifacts in:

$CycleDir

Verify the implementation with the smallest meaningful checks. Inspect the diff.

Write exactly one JSON object to:

$VerificationJson

Schema:
{
  "verification_status": "passed | failed",
  "summary": "short verification summary",
  "commands_run": [],
  "residual_risk": [],
  "loop_recommendation": "continue | stop",
  "repairable": false,
  "next_worker_action": ""
}

Use failed for real correctness, safety, or validation failures.
Use repairable=true only when one bounded follow-up cycle can safely fix it.
Use loop_recommendation=stop only when no high-value fixed-scope deficiencies
remain or continuing would be unsafe.
"@ | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Write-ReboundPrompt {
    param(
        [string]$Path,
        [string]$CycleDir,
        [string]$Phase,
        [string]$Reason,
        [string]$TargetJson
    )
    @"
You are repairing malformed autonomous-loop phase output.

Phase: $Phase
Reason rejected by supervisor:
$Reason

Read AGENTS.md and the current cycle files in:

$CycleDir

Repair only this phase artifact:

$TargetJson

Do not broaden scope. Do not change source files unless this is the implement
phase and the approved plan requires it. Do not run scripts/agent-loop.ps1 or
scripts/agent-loop.sh.
"@ | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Test-AuditValid {
    param($Json)
    if ($null -eq $Json) { return $false }
    if (-not [bool]$Json.ready_for_review) { return $false }
    return ([string]$Json.audit_outcome) -in @('deficiency', 'no-deficiency')
}

function Test-ReviewValid {
    param($Json)
    if ($null -eq $Json) { return $false }
    return ([string]$Json.review_decision) -in @('approved', 'needs_revision', 'stop')
}

function Test-ImplementationValid {
    param($Json)
    if ($null -eq $Json) { return $false }
    return ([string]$Json.implementation_status) -in @('complete', 'blocked')
}

function Test-VerificationValid {
    param($Json)
    if ($null -eq $Json) { return $false }
    return ([string]$Json.verification_status) -in @('passed', 'failed')
}

function Invoke-PhaseAgent {
    param(
        [string]$Agent,
        [string]$Phase,
        [string]$PromptPath,
        [string]$CycleDir,
        [switch]$ContinueOnError
    )
    $stdout = Join-Path $CycleDir "agent-$Phase-$Agent.stdout"
    $stderr = Join-Path $CycleDir "agent-$Phase-$Agent.stderr"
    $final = Join-Path $CycleDir "agent-$Phase-$Agent.final.md"

    if ($FakeAgents) {
        "fake $Agent $Phase" | Set-Content -LiteralPath $stdout -Encoding UTF8
        return 0
    }

    if ($Agent -eq 'codex') {
        $exit = Invoke-Codex -PromptPath $PromptPath -FinalMessagePath $final -StdoutPath $stdout -StderrPath $stderr
    } else {
        $exit = Invoke-Claude -PromptPath $PromptPath -StdoutPath $stdout -StderrPath $stderr -PhaseName "$Agent $Phase"
    }

    if ($exit -ne 0 -and -not $ContinueOnError) {
        throw "$Agent failed during $Phase. See $stdout and $stderr"
    }
    return $exit
}

function Invoke-ValidatedPhase {
    param(
        [string]$Agent,
        [string]$Phase,
        [string]$PromptPath,
        [string]$TargetJson,
        [string]$CycleDir,
        [scriptblock]$Validator,
        [switch]$ContinueOnError
    )
    for ($attempt = 0; $attempt -le $MaxPhaseRetries; $attempt++) {
        $effectivePrompt = $PromptPath
        if ($attempt -gt 0) {
            $effectivePrompt = Join-Path $CycleDir "prompt-$Phase-rebound-$attempt.md"
            Write-ReboundPrompt -Path $effectivePrompt -CycleDir $CycleDir -Phase $Phase -Reason "The previous output was missing, invalid JSON, or failed schema validation." -TargetJson $TargetJson
        }

        [void](Invoke-PhaseAgent -Agent $Agent -Phase "$Phase-$attempt" -PromptPath $effectivePrompt -CycleDir $CycleDir -ContinueOnError:$ContinueOnError)

        if ($FakeAgents) {
            Write-FakePhaseOutput -Phase $Phase -Path $TargetJson
        }

        $json = Read-JsonFile $TargetJson
        if (& $Validator $json) {
            return $json
        }
    }
    throw "Phase '$Phase' remained invalid after $MaxPhaseRetries rebound attempt(s). Target: $TargetJson"
}

function Write-FakePhaseOutput {
    param([string]$Phase, [string]$Path)
    switch ($Phase) {
        'audit' {
            Write-JsonFile $Path ([ordered]@{
                audit_outcome = 'deficiency'
                ready_for_review = $true
                deficiency = 'fake smoke-test deficiency'
                why_it_matters = 'proves supervisor control flow'
                plan = [ordered]@{
                    summary = 'fake no-op plan'
                    files_affected = @()
                    behavior_affected = 'none'
                    verification = @('fake verification')
                    rollback_or_safety = 'no edits'
                    non_goals = @('real work')
                }
                risk_notes = @()
                stop_reason = ''
            })
        }
        'review' {
            Write-JsonFile $Path ([ordered]@{
                review_decision = 'approved'
                rationale = 'fake approval'
                required_revisions = @()
                risk_notes = @()
                stop_reason = ''
                repairable = $false
                next_worker_action = ''
            })
        }
        'implement' {
            Write-JsonFile $Path ([ordered]@{
                implementation_status = 'complete'
                summary = 'fake no-op implementation'
                files_touched = @()
                validation_run = @()
                validation_result = 'not-run'
                deviations_from_plan = @()
                blocked_reason = ''
                needs_repair = $false
            })
        }
        'verify' {
            Write-JsonFile $Path ([ordered]@{
                verification_status = 'passed'
                summary = 'fake verification passed'
                commands_run = @()
                residual_risk = @()
                loop_recommendation = 'continue'
                repairable = $false
                next_worker_action = ''
            })
        }
    }
}

function Write-ReviewerFollowup {
    param(
        [string]$Path,
        [string]$Source,
        [string]$Action
    )
    @"
pending: true
source: $Source

# Reviewer Follow-Up

$Action
"@ | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Show-Status {
    if (-not (Test-Path -LiteralPath $CurrentRunFile)) {
        Write-Host 'No active autonomous run recorded.'
        if (Test-Path -LiteralPath $NextAuditorFile) {
            Write-Host "Next auditor: $((Get-Content -LiteralPath $NextAuditorFile -Raw).Trim())"
        } else {
            Write-Host 'Next auditor: codex'
        }
        return
    }
    $runDir = (Get-Content -LiteralPath $CurrentRunFile -Raw).Trim()
    Write-Host "Current run: $runDir"
    if (Test-Path -LiteralPath (Join-Path $runDir 'events.log')) {
        Get-Content -LiteralPath (Join-Path $runDir 'events.log') -Tail 20
    }
}

function Run-AutonomousLoop {
    Add-ProcessGitConfig 'safe.directory' '*'
    Add-ProcessGitConfig 'core.autocrlf' 'false'
    Add-ProcessGitConfig 'core.safecrlf' 'false'

    $emptyExcludes = Join-Path $RunRoot 'empty-git-excludes'
    if (-not (Test-Path -LiteralPath $emptyExcludes)) {
        New-Item -ItemType File -Path $emptyExcludes | Out-Null
    }
    Add-ProcessGitConfig 'core.excludesfile' $emptyExcludes

    $script:CodexExe = Resolve-Cli 'codex'
    $script:ClaudeExe = Resolve-Cli 'claude'
    if (-not $FakeAgents) {
        if (-not $script:CodexExe) { throw 'codex CLI not found on PATH.' }
        if (-not $script:ClaudeExe) { throw 'claude CLI not found on PATH.' }
    }

    if ([string]::IsNullOrWhiteSpace($LogDir)) {
        $LogDirResolved = Join-Path $RunRoot (Get-Date -Format 'yyyy-MM-dd_HHmmss')
    } elseif ([System.IO.Path]::IsPathRooted($LogDir)) {
        $LogDirResolved = $LogDir
    } else {
        $LogDirResolved = Join-Path $RepoRoot $LogDir
    }
    New-Item -ItemType Directory -Force -Path $LogDirResolved | Out-Null
    Set-Content -LiteralPath $CurrentRunFile -Value $LogDirResolved -Encoding ASCII
    $eventsLog = Join-Path $LogDirResolved 'events.log'

    Write-Host '================================================================'
    Write-Host 'agent-loop.ps1'
    Write-Host "  repo:        $RepoRoot"
    Write-Host "  run dir:     $LogDirResolved"
    Write-Host "  codex CLI:   $(if ($script:CodexExe) { $script:CodexExe } else { '(fake)' })"
    Write-Host "  claude CLI:  $(if ($script:ClaudeExe) { $script:ClaudeExe } else { '(fake)' })"
    Write-Host "  codex models: $($CodexModels -join ', ')"
    Write-Host "  codex efforts: $($CodexReasoningEfforts -join ', ')"
    Write-Host "  claude models: $($ClaudeModels -join ', ')"
    Write-Host "  claude efforts: $($ClaudeEfforts -join ', ')"
    Write-Host "  max cycles:  $(if ($MaxCycles -gt 0) { $MaxCycles } else { 'forever' })"
    Write-Host "  stop file:   $StopFile"
    Write-Host '================================================================'

    $cycle = 0
    $noChangeCount = 0
    $planRevisionCount = 0
    $repairCount = 0
    $previousFingerprint = Get-WorktreeFingerprint
    $nextAuditor = Get-NextAuditor
    $reviewerFollowup = Join-Path $RunRoot 'reviewer-followup.md'

    while ($true) {
        if ($MaxCycles -gt 0 -and $cycle -ge $MaxCycles) {
            Write-Host "Reached MaxCycles=$MaxCycles. Stopping."
            break
        }
        if (Test-StopRequested) {
            Write-Host "Stop file detected at $StopFile. Stopping."
            break
        }

        $cycle++
        $auditor = $nextAuditor
        $reviewer = Get-OtherAgent $auditor
        $cycleId = ('{0:0000}-{1}-{2}' -f $cycle, (Get-Date -Format 'yyyyMMddTHHmmssZ'), (ConvertTo-Slug $Slug))
        $cycleDir = Join-Path $LogDirResolved $cycleId
        New-Item -ItemType Directory -Force -Path $cycleDir | Out-Null
        "cycle=$cycleId auditor=$auditor reviewer=$reviewer" | Add-Content -LiteralPath $eventsLog
        Write-Host ""
        Write-Host "==> Cycle $cycle : $cycleId"
        Write-Host "    auditor=$auditor reviewer=$reviewer"

        $mode = 'normal'
        if (Test-Path -LiteralPath $reviewerFollowup) {
            $followupText = Get-Content -LiteralPath $reviewerFollowup -Raw
            if ($followupText -match '(?im)^\s*pending:\s*true\s*$') { $mode = 'repair' }
        }

        [void](New-CycleContext -CycleDir $cycleDir -CycleId $cycleId -Auditor $auditor -Reviewer $reviewer -Mode $mode)
        $auditJson = Join-Path $cycleDir '01-audit-plan.json'
        $reviewJson = Join-Path $cycleDir '02-review-verdict.json'
        $implementationJson = Join-Path $cycleDir '03-implementation.json'
        $verificationJson = Join-Path $cycleDir '04-verification.json'

        $auditPrompt = Join-Path $cycleDir 'prompt-01-audit.md'
        Write-AuditPrompt -Path $auditPrompt -CycleDir $cycleDir -CycleId $cycleId -Auditor $auditor -Reviewer $reviewer -AuditJson $auditJson -Mode $mode -ReviewerFollowup $reviewerFollowup
        $audit = Invoke-ValidatedPhase -Agent $auditor -Phase 'audit' -PromptPath $auditPrompt -TargetJson $auditJson -CycleDir $cycleDir -Validator ${function:Test-AuditValid} -ContinueOnError:$ContinueOnCodexError

        $reviewPrompt = Join-Path $cycleDir 'prompt-02-review.md'
        Write-ReviewPrompt -Path $reviewPrompt -CycleDir $cycleDir -CycleId $cycleId -Reviewer $reviewer -AuditJson $auditJson -ReviewJson $reviewJson
        $review = Invoke-ValidatedPhase -Agent $reviewer -Phase 'review' -PromptPath $reviewPrompt -TargetJson $reviewJson -CycleDir $cycleDir -Validator ${function:Test-ReviewValid} -ContinueOnError:$ContinueOnReviewError

        $decision = [string]$review.review_decision
        if ($decision -eq 'stop') {
            Write-Host "Reviewer stop: $($review.rationale)"
            break
        }
        if ($decision -eq 'needs_revision') {
            $planRevisionCount++
            Write-Host "Plan revision requested ($planRevisionCount/$MaxPlanRevisions): $($review.rationale)"
            $revisionItems = @()
            if ($review.PSObject.Properties.Match('required_revisions') -and $null -ne $review.required_revisions) {
                $revisionItems = @($review.required_revisions)
            }
            $revisionText = if ($revisionItems.Count -gt 0) {
                "Required revisions:`n- " + ($revisionItems -join "`n- ")
            } else {
                'Required revisions: reread the reviewer verdict and resolve the plan objection.'
            }
            Write-ReviewerFollowup -Path $reviewerFollowup -Source $cycleId -Action @"
The reviewer requested a bounded plan revision before implementation.

Review rationale: $($review.rationale)

$revisionText

Read the previous audit plan at $auditJson and the reviewer verdict at
$reviewJson. Produce a revised one-deficiency plan that directly resolves these
objections. Do not implement until the revised plan is approved.
"@
            "cycle=$cycleId plan_revision_requested=$planRevisionCount verdict=$reviewJson" | Add-Content -LiteralPath $eventsLog
            if ($planRevisionCount -gt $MaxPlanRevisions) {
                throw "Plan revision budget exceeded. Last review: $reviewJson"
            }
            $nextAuditor = $auditor
            continue
        }
        $planRevisionCount = 0

        if ([string]$audit.audit_outcome -eq 'no-deficiency') {
            Write-Host 'Both agents agreed there is no meaningful deficiency to fix. Stopping.'
            break
        }

        $implementationPrompt = Join-Path $cycleDir 'prompt-03-implement.md'
        Write-ImplementationPrompt -Path $implementationPrompt -CycleDir $cycleDir -CycleId $cycleId -Auditor $auditor -AuditJson $auditJson -ReviewJson $reviewJson -ImplementationJson $implementationJson
        $implementation = Invoke-ValidatedPhase -Agent $auditor -Phase 'implement' -PromptPath $implementationPrompt -TargetJson $implementationJson -CycleDir $cycleDir -Validator ${function:Test-ImplementationValid} -ContinueOnError:$ContinueOnImplementError
        if ([string]$implementation.implementation_status -eq 'blocked') {
            throw "Implementation blocked: $($implementation.blocked_reason). See $implementationJson"
        }

        $verificationPrompt = Join-Path $cycleDir 'prompt-04-verify.md'
        Write-VerificationPrompt -Path $verificationPrompt -CycleDir $cycleDir -CycleId $cycleId -Reviewer $reviewer -VerificationJson $verificationJson
        $verification = Invoke-ValidatedPhase -Agent $reviewer -Phase 'verify' -PromptPath $verificationPrompt -TargetJson $verificationJson -CycleDir $cycleDir -Validator ${function:Test-VerificationValid} -ContinueOnError:$ContinueOnVerifyError

        if ([string]$verification.verification_status -eq 'failed') {
            if ([bool]$verification.repairable -and $repairCount -lt $AutoRepairRetries) {
                $repairCount++
                Write-ReviewerFollowup -Path $reviewerFollowup -Source $cycleId -Action ([string]$verification.next_worker_action)
                Write-Host "Verification failed but is repairable; scheduled bounded repair $repairCount/$AutoRepairRetries."
            } else {
                throw "Verification failed. See $verificationJson"
            }
        } else {
            $repairCount = 0
            @"
pending: false
source: $cycleId
"@ | Set-Content -LiteralPath $reviewerFollowup -Encoding UTF8
        }

        $currentFingerprint = Get-WorktreeFingerprint
        if ($currentFingerprint -eq $previousFingerprint) {
            $noChangeCount++
            Write-Host "No repository diff change detected (consecutive: $noChangeCount/$StopAfterNoChangesFor)."
            if ($StopAfterNoChangesFor -gt 0 -and $noChangeCount -ge $StopAfterNoChangesFor) {
                throw "No-change stall fuse tripped after $noChangeCount cycles."
            }
        } else {
            $noChangeCount = 0
            $previousFingerprint = $currentFingerprint
        }

        Write-JsonFile (Join-Path $cycleDir 'summary.json') ([ordered]@{
            cycle = $cycle
            cycle_id = $cycleId
            auditor = $auditor
            reviewer = $reviewer
            mode = $mode
            audit = $auditJson
            review = $reviewJson
            implementation = $implementationJson
            verification = $verificationJson
            loop_recommendation = [string]$verification.loop_recommendation
            head = Get-HeadSha
        })

        $nextAuditor = $reviewer
        Set-Content -LiteralPath $NextAuditorFile -Value $nextAuditor -Encoding ASCII

        if ([string]$verification.loop_recommendation -eq 'stop') {
            Write-Host "Verifier recommended stop: $($verification.summary)"
            break
        }

        if ($SleepSeconds -gt 0) {
            Write-Host "Sleeping ${SleepSeconds}s before next cycle. Create STOP file to stop gracefully."
            Start-Sleep -Seconds $SleepSeconds
        }
    }

    Write-Host ''
    Write-Host '================================================================'
    Write-Host "agent-loop.ps1 finished after $cycle cycle(s)."
    Write-Host "run dir: $LogDirResolved"
    Write-Host '================================================================'
}

if ($Command -eq 'help') {
    Write-Usage
    exit 0
}

if ($Command -eq 'status' -or $Command -eq 'monitor') {
    Show-Status
    exit 0
}

Run-AutonomousLoop
