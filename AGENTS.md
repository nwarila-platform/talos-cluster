# Agent Operating Contract

This repository is the source of truth for `TDNHQ-TALCL01`, a production Talos
Kubernetes cluster. Its long-term goal is to become and remain a top 0.1% Talos
cluster repository by correctness, security posture, operational clarity,
minimalism, and reviewability.

Every agent working here should treat the repository as resume-grade critical
infrastructure. Optimize for changes that would survive rigorous review by
industry experts, security-minded infrastructure engineers, and FAANG-level
hiring reviewers.

## North Star

Improve the repository incrementally until both Codex and Claude agree that it
is aligned with:

- the organization baseline in `nwarila-platform/.github`;
- Talos and Kubernetes community best practices;
- small, auditable operational scope;
- reproducible validation and recovery workflows;
- clear documentation that explains both what to do and why decisions were made.

This repository is intentionally not a generic template consumer. It may diverge
from template shape when Talos-cluster reality requires it, but every divergence
must be deliberate, documented, and easier to defend than the baseline.

## Baseline Alignment

Use `nwarila-platform/.github` as the organizational source of truth for shared
governance and style. In particular:

- ADRs follow the org Architecture Decision Record model. Org-level ADRs are
  mirrored under `docs/decision-records/org/`, template-level ADRs under
  `docs/decision-records/template/`, and repository-specific ADRs under
  `docs/decision-records/repo/`.
- Non-ADR documentation should follow Diataxis: `docs/tutorials/`,
  `docs/how-to/`, `docs/reference/`, and `docs/explanation/`.
- Source-control hygiene, dependency-update strategy, CI posture, Markdown
  style, and release conventions should be compared against the org baseline
  before inventing local conventions.
- Any local exception to an accepted org practice must be explained in a
  repository-specific ADR or in the implementing PR when the exception is
  clearly temporary.

## Iterative Improvement Loop

Work in one small fixed-scope improvement at a time. Do not batch unrelated
cleanup into a broad "quality pass."

Use `.\scripts\agent-loop.ps1 run` from Windows PowerShell to execute the loop
autonomously. The PowerShell supervisor is the primary automation entrypoint:
it resolves Codex and Claude CLIs directly, captures cycle state, uses
structured JSON gates, rebounds malformed phase output with bounded retries,
enforces plan-revision and no-change fuses, and records implementation,
verification, and retrospectives under `.agent-loop/`. The generated
`.agent-loop/` directory is local state and must not be committed.

The loop is quality-first by default. It must try the best available Codex
models first at maximum reasoning effort and run Claude on the best available
Opus path at maximum effort. Fallback models or lower effort are allowed only
when the installed CLI or model endpoint rejects the preferred option, and that
fallback must be visible in the cycle logs.

Operators can inspect the latest loop with `.\scripts\agent-loop.ps1 status`
or `.\scripts\agent-loop.ps1 monitor`. To stop a long run cleanly, create
`.agent-loop\autonomous\STOP`; the supervisor exits at the next cycle boundary.

Each improvement cycle is:

1. Perform an adversarial audit of the current repository state.
2. Identify exactly one deficiency worth fixing next.
3. Write a narrowly scoped plan that states:
   - the deficiency;
   - why it matters;
   - the proposed files and behavior affected;
   - the verification commands or evidence;
   - any rollback or safety consideration.
4. Have the other LLM perform an adversarial review of the plan.
   - If Codex wrote the audit and plan, Claude reviews it.
   - If Claude wrote the audit and plan, Codex reviews it.
5. Implement only after both agents agree the plan is sound, or after the plan
   is revised until the review objections are resolved.
6. Verify the change with the smallest meaningful validation set.
7. Record what changed and what remains risky.
8. On the next cycle, swap roles: the reviewer becomes the auditor/planner and
   the previous auditor/planner becomes the reviewer.

If the other LLM is unavailable in the current session, stop after producing the
audit and plan, then ask the user to run or provide the counterpart review. Do
not silently skip cross-review for production-affecting changes.

## Definition of a Good Change

A good change is:

- small enough to review in isolation;
- traceable to one deficiency;
- aligned with org conventions unless an exception is explicit;
- safer after the change than before it;
- verified by commands, CI, generated evidence, or a clear manual check;
- documented at the right level: README for immediate user workflow, Diataxis
  docs for durable guidance, ADR for significant decisions.

A bad change is:

- broad cleanup with no single accountable deficiency;
- cosmetic churn in files unrelated to the current cycle;
- operational behavior change without validation;
- new tooling without a maintenance story;
- documentation that claims a state the repo cannot prove.

## Talos Cluster Guardrails

- Never commit Talos secrets, kubeconfigs, talosconfigs, generated machine
  configs, S3 mirrors, or local credentials.
- Treat `cluster/config.env` as the version and inventory source of truth.
- Treat `cluster/patches/` as declarative Talos intent, not scratch space.
- Keep generated artifacts out of git unless an ADR explicitly says otherwise.
- Prefer deterministic, pinned, auditable tooling over mutable install flows.
- Changes to bootstrap, apply, upgrade, recovery, CI deployment, secret storage,
  or node identity are production-sensitive and require extra scrutiny.
- Operational scripts should fail closed, print enough context for an operator,
  and avoid hidden destructive behavior.

## Review Standard

Review as if this repository will be inspected by:

- a Talos maintainer;
- a Kubernetes platform engineer;
- a security engineer looking for supply-chain and secret-handling mistakes;
- a senior hiring manager assessing infrastructure judgment from git history.

The bar is not "works on my machine." The bar is that the repository makes the
correct thing the obvious thing, and makes dangerous actions explicit.
