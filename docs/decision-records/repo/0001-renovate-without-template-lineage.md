# ADR-0001: Adopt Renovate Without Type-Template Lineage

| Field          | Value                                    |
| -------------- | ---------------------------------------- |
| Status         | Accepted                                 |
| Date           | 2026-05-25                               |
| Authors        | Nick Warila (@NWarila)                   |
| Decision-maker | Nick Warila (sole portfolio maintainer)  |
| Consulted      | None.                                    |
| Informed       | None.                                    |
| Reversibility  | High                                     |
| Review-by      | N/A (Accepted)                           |

## TL;DR

This repository adopts the [ADR-0004](../org/0004-use-renovate-for-dependency-updates.md) Renovate baseline directly in `.github/renovate.json5`, without `extends: ["github>NWarila/<type-template>"]`, because no Talos-cluster type-template exists in the `nwarila-platform` portfolio at this time. ADR-0004 §Confirmation §2 explicitly allows this exception when a repository has no template lineage, provided the deviation is documented in a repo-specific superseding ADR. The inlined baseline matches the minimum shape ADR-0004 §Decision Outcome prescribes for a type-template; when a Talos-cluster type-template is later created, a follow-up PR will supersede this ADR, replace the inlined baseline with `extends: ["github>NWarila/<that-template>"]`, and reduce the local config to repo-specific overrides.

## Context and Problem Statement

ADR-0004 (Accepted, 2026-05-05) mandates that every adopting repository contain `.github/renovate.json5` (§Confirmation §1). It further mandates that every adopting consumer's `renovate.json5` include exactly one `github>NWarila/<type-template>` entry in its `extends` array, identifying the stack template the consumer derives from (§Confirmation §2). The same section provides an explicit exception path: "A consumer that does not derive from a type-template (e.g. the type-template repos themselves, or a one-off repo with no template lineage) MUST document its exception in a repo-specific superseding ADR."

`talos-cluster` is the first and only Talos-Kubernetes-cluster repository in the portfolio at the time of writing. No `NWarila/talos-cluster-template` (or equivalent) repository exists. Without a template to extend, ADR-0004 §Confirmation §2's main path is unavailable. The MUST NOT clause for `.github/dependabot.yml` (ADR-0004 §Decision Outcome) was closed in the preceding cycle; the §Confirmation §1 MUST EXIST clause for `.github/renovate.json5` remains open. This ADR resolves that gap.

## Decision Drivers

1. **ADR-0004 compliance.** §Confirmation §1 must be satisfied; §Confirmation §2 must be satisfied via the documented exception path because the main path is not available.
2. **No fictional infrastructure.** Extending `github>NWarila/talos-cluster-template` when that repository does not exist would produce a Renovate config that fails at evaluation time and would commit a false dependency on a phantom upstream.
3. **Migration discipline.** Whatever baseline is adopted now must be shaped so a future migration to a real Talos-cluster type-template is a substitution rather than a redesign.
4. **Talos-cluster surface coverage.** The baseline must cover the update surfaces that already exist in this repository (GitHub Actions in workflows) and must not over-promise coverage of surfaces that require custom managers (regex-managed version literals in `cluster/config.env`, the `pre-commit` manager beyond `config:recommended` defaults) that have not yet been authored.

## Considered Options

1. **Extend a non-existent type-template URL.** Author `renovate.json5` with `extends: ["github>NWarila/talos-cluster-template"]` even though that repository does not exist.
2. **Author the Talos-cluster type-template in this same cycle.** Create `NWarila/talos-cluster-template`, populate its `renovate.json5`, and extend it from this repo.
3. **Inline the ADR-0004 baseline locally and document the exception in this ADR.** Author `.github/renovate.json5` as a self-contained config that mirrors the shape ADR-0004 prescribes for a type-template.
4. **Skip Renovate adoption entirely until a type-template exists.** Leave §Confirmation §1 unsatisfied indefinitely.

## Decision Outcome

Chosen option: **Option 3, inline the ADR-0004 baseline locally and document the exception in this ADR.**

`.github/renovate.json5` is authored as a self-contained config that satisfies the minimum baseline ADR-0004 §Decision Outcome specifies for a type-template: `extends: ["config:recommended"]`, `:dependencyDashboard`, weekly `schedule`, `semanticCommits: "enabled"`, `prConcurrentLimit: 5`, and a `packageRules` entry mapping `github-actions` updates to `ci(deps): ...` Conventional Commit prefixes with `pinDigests: true`. This repository also keeps release-age quarantine guards (`minimumReleaseAge: "7 days"`, `internalChecksFilter: "strict"`) in its local inlined baseline. Stack-specific managers (custom regex for `cluster/config.env` version literals, additional `pre-commit` coverage) are intentionally deferred so this cycle remains narrow; they MAY be added in follow-up cycles to this file or, preferably, to a future Talos-cluster type-template.

When a `NWarila/talos-cluster-template` (or equivalently named Talos-cluster type-template) is created, this repository MUST open a follow-up PR that (a) adds `extends: ["github>NWarila/<that-template>"]` to `.github/renovate.json5` and removes inlined settings the template now supplies, (b) authors a superseding repo-specific ADR in `docs/decision-records/repo/` and links it from this ADR's `Superseded by` field, and (c) retains only repo-specific overrides in `.github/renovate.json5`.

## Pros and Cons of the Options

### Option 1: Extend a non-existent type-template URL

- **Bad, because** the `extends` target would fail to resolve at Renovate evaluation time, producing no PRs and a confusing failure mode.
- **Bad, because** committing a reference to a non-existent upstream is a form of false documentation that misleads any future reader inspecting the config.

### Option 2: Author the Talos-cluster type-template in this same cycle

- **Good, because** it would close ADR-0004 §Confirmation §2's main path properly.
- **Bad, because** authoring a new portfolio repository is itself a multi-PR effort that exceeds the scope of a single narrow improvement cycle.
- **Bad, because** a type-template authored to serve a single consumer encodes design choices that may not survive the second consumer; the template is better deferred until a second Talos-cluster repository is in scope.

### Option 3: Inline the ADR-0004 baseline locally and document the exception (chosen)

- **Good, because** it satisfies ADR-0004 §Confirmation §1 immediately via §Confirmation §2's explicit exception path.
- **Good, because** the inlined baseline is the same shape ADR-0004 prescribes for type-templates, so a future migration is a substitution rather than a redesign.
- **Good, because** Renovate begins covering the GitHub Actions update surface in this repository at the next scheduled evaluation.
- **Neutral, because** the baseline does not yet cover custom-regex update surfaces (`cluster/config.env` version literals); those can be added as a follow-up without disturbing this ADR.
- **Bad, because** the inlined baseline can drift from a future Talos-cluster type-template's canonical baseline until the migration PR is opened. The superseding-ADR requirement in this ADR's §Confirmation §4 constrains that risk to the moment the template is created.

### Option 4: Skip Renovate adoption entirely until a type-template exists

- **Bad, because** ADR-0004 §Confirmation §1 remains unsatisfied indefinitely.
- **Bad, because** the previous cycle removed `.github/dependabot.yml` per ADR-0004 §Decision Outcome; declining to add `renovate.json5` would leave the repository with no automated dependency-update coverage at all until a Talos-cluster type-template is built.

## Confirmation

Adherence to this ADR is confirmed by the following mechanisms. The wording `MUST`, `SHOULD`, and `MAY` follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) conventions.

1. **Presence check.** `.github/renovate.json5` MUST exist in this repository.
2. **No-template-extends check.** `.github/renovate.json5` MUST NOT contain a `github>NWarila/<type-template>` entry in `extends` while this ADR remains Accepted. The exception is sanctioned by this ADR per ADR-0004 §Confirmation §2.
3. **Baseline-shape check.** `.github/renovate.json5` MUST include the minimum baseline ADR-0004 §Decision Outcome describes for a type-template: `config:recommended` extension, `:dependencyDashboard` extension, weekly `schedule`, `semanticCommits: "enabled"`, `prConcurrentLimit: 5`, a `packageRules` entry for `github-actions` with `pinDigests: true` and a `ci(deps)` semantic-commit mapping, plus the local release-age guards (`minimumReleaseAge: "7 days"` and `internalChecksFilter: "strict"`).
4. **Migration trigger.** Creation of a Talos-cluster type-template MUST be followed by a migration PR in this repository that supersedes this ADR, refactors `.github/renovate.json5` to extend that template, and removes inlined settings the template now supplies.

## Consequences

### Positive

- ADR-0004 §Confirmation §1 is closed for this repository via the documented exception path in §Confirmation §2.
- Renovate begins covering the GitHub Actions update surface at the next scheduled evaluation; `pinDigests: true` brings workflow `uses:` lines into the SHA-pin format ADR-0004 §Confirmation §3 expects.
- The same shape ADR-0004 prescribes for type-template baselines is encoded here, so a future migration is a substitution rather than a redesign.

### Negative

- The inlined baseline can drift from a future Talos-cluster type-template's canonical baseline until the migration PR is opened. The superseding-ADR requirement in §Confirmation §4 constrains this risk to the moment the template is created.
- Stack-specific update surfaces (`cluster/config.env` version literals, expanded `pre-commit` coverage) are not yet covered. Each is a separate follow-up decision.

### Neutral

- The Renovate GitHub App is already installed at the `nwarila-platform` organization level, so no per-repo installation is required.
- The first batch of Renovate PRs against this repository will include SHA-pin rewrites for workflow `uses:` lines that currently use floating major tags. Each PR is subject to CODEOWNERS review and the normal `main`-branch protections.

## Assumptions

This decision rests on the following assumptions. If any becomes false, this ADR should be revisited:

1. No `NWarila/talos-cluster-template` (or equivalently named Talos-cluster type-template) exists in the portfolio at the time this ADR is accepted.
2. The Renovate GitHub App remains installed against the `nwarila-platform` organization (or against this repository specifically).
3. The Renovate config schema continues to accept the keys this ADR mandates (`minimumReleaseAge`, `internalChecksFilter`, `pinDigests`, `semanticCommitType`, `semanticCommitScope`).

## Supersedes

None. This is the inaugural repository-specific ADR for `talos-cluster`.

## Superseded by

None (current). The migration PR that introduces `extends: ["github>NWarila/<talos-cluster-template>"]` MUST author a superseding repo-specific ADR and link it here.

## Implementing PRs

The PR that introduces this ADR also introduces `.github/renovate.json5`, the `.gitignore` allowlist entries for both new files, and the `docs/decision-records/README.md` repository-specific ADR index entry.

## Related ADRs

- [ADR-0004 (org)](../org/0004-use-renovate-for-dependency-updates.md) — establishes the Renovate-with-per-template-baselines org policy and the §Confirmation §2 exception path this ADR invokes.
- [ADR-0003 (org)](../org/0003-use-deny-all-gitignore-strategy.md) — establishes the deny-all `.gitignore` strategy; `.github/renovate.json5` and this ADR are added to the allowlist per ADR-0003.

## Compliance Notes

This ADR sanctions a documented deviation from ADR-0004 §Confirmation §2's main path, not a deviation from the underlying intent (every repo runs Renovate with a per-stack baseline). The org supply-chain control for SHA-pin retention is preserved via `pinDigests: true`; release-age quarantine via `minimumReleaseAge: "7 days"` and `internalChecksFilter: "strict"` is retained as a local hardening guard in the inlined baseline.

| Framework              | Control / Practice ID                                              | Potential Evidence Contribution                                                                                            |
| ---------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| NIST SP 800-53 Rev. 5  | SI-2 (Flaw Remediation)                                            | Renovate's automated update PRs contribute to timely patch application across the GitHub Actions supply chain used by CI. |
| NIST SP 800-53 Rev. 5  | CM-3 (Configuration Change Control)                                | The inlined baseline records this repository's dependency-management policy in source control with PR review history.      |
| NIST SP 800-218 (SSDF) | PW.4 (Reuse Existing, Well-Secured Software When Feasible)         | Release-age quarantine and SHA-pin retention preserve the supply-chain integrity posture for reused Actions.               |
