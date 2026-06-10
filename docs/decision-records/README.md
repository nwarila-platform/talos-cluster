# Architecture Decision Records

This directory defines the portfolio's Architecture Decision Record (ADR) baseline. Each ADR records one architecturally significant decision: the problem being solved, the decision that was made, the alternatives that were considered, and the consequences to expect.

The directory is named `decision-records` because the full name is more readable to contributors, reviewers, and auditors who may not already know the acronym.

This directory is this repository's local ADR index. It mirrors accepted
org-baseline ADRs under `docs/decision-records/org/`, reserves
`docs/decision-records/template/` for any type-template ADRs that this
repository may adopt later, and reserves `docs/decision-records/repo/` for
Talos-cluster-specific decisions.

1. mirrors the master org ADRs into its own `docs/decision-records/org/` directory (byte-identical content) — the same set in every adopting repo regardless of stack;
2. mirrors any **type-template** ADRs from its type-template repository (for example `NWarila/terraform-runner-template` for a Terraform consumer) into its own `docs/decision-records/template/` directory (byte-identical content) — the same set across every consumer of that template, but different across templates;
3. may add its own `docs/decision-records/repo/` ADRs for repository-scoped decisions.

The three scopes use independent four-digit numbering namespaces and the same MADR 4.0-aligned format. See [ADR-0001](org/0001-use-architecture-decision-records.md) for the authoritative model.

ADRs may begin as `Proposed` while a decision is being discussed. Once accepted, an ADR becomes part of the repository's permanent historical record. Accepted ADRs are not substantively rewritten; later decisions supersede earlier ones through new ADRs. Post-acceptance edits are limited to status updates, supersession links, implementing-PR links, and editorial fixes that do not change the decision itself.

## What is an ADR?

An Architecture Decision Record is a short Markdown document that answers three questions about a single architectural choice:

1. **What is the problem?** What forces drove the decision?
2. **What was decided?** Concretely, what will we do?
3. **Why?** What alternatives were considered, and what trade-offs are we accepting?

A reader who knows nothing about the codebase should be able to open any ADR and understand why a particular design exists. A reviewer evaluating the repository should be able to reconstruct the project's architectural reasoning without a synchronous conversation. An auditor in a regulated environment should be able to trace important design choices to source-controlled artifacts.

The format used here is established by [ADR-0001](org/0001-use-architecture-decision-records.md). It is MADR 4.0-aligned, uses a visible Markdown metadata table instead of YAML front matter, and adds fields for reversibility, traceability, and conservative compliance mapping.

## Index

### Org-mirrored ADRs

| #                                                      | Title                                                          | Status   | Date       | Summary                                                                                        |
| ------------------------------------------------------ | -------------------------------------------------------------- | -------- | ---------- | ---------------------------------------------------------------------------------------------- |
| [0001](org/0001-use-architecture-decision-records.md)      | Use Architecture Decision Records to Document Design Rationale | Accepted | 2026-04-22 | Adopt ADRs as the documentation format for architecturally significant decisions.              |
| [0002](org/0002-adopt-diataxis-documentation-framework.md) | Adopt Diátaxis as the Documentation Framework                  | Accepted | 2026-04-24 | Adopt the Diátaxis four-quadrant framework for non-ADR documentation in adopting repositories. |
| [0003](org/0003-use-deny-all-gitignore-strategy.md)        | Use a Deny-All `.gitignore` Strategy                           | Accepted | 2026-04-25 | Adopt deny-all `.gitignore` with explicit allowlist as the default tracking strategy for adopting repositories. |
| [0004](org/0004-use-renovate-for-dependency-updates.md)    | Use Renovate for Dependency Updates with Per-Template Baselines | Accepted | 2026-05-05 | Adopt Renovate org-wide; each type-template owns a self-contained `renovate.json5`; consumers extend their type-template only. No org-level Renovate config. Replaces Dependabot. |
| [org/0005](org/0005-keep-github-control-planes-namespace-local.md) | Keep GitHub Control Planes Namespace-Local | Accepted | 2026-06-02 | Use the owning namespace control plane for governance, ADRs, repo hygiene, and reusable workflow callers. |

### Repository-specific ADRs

| #                                                              | Title                                          | Status   | Date       | Summary                                                                                                                            |
| -------------------------------------------------------------- | ---------------------------------------------- | -------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| [0001](repo/0001-renovate-without-template-lineage.md)         | Adopt Renovate Without Type-Template Lineage   | Accepted | 2026-05-25 | Inline the ADR-0004 baseline in `.github/renovate.json5` because no Talos-cluster type-template exists yet (ADR-0004 §Confirmation §2). |
| [0002](repo/0002-use-short-talos-hostnames.md)                 | Use Short Talos Hostnames (`cp1`–`w3`)         | Accepted | 2026-05-25 | Hostnames, patch filenames, and `cluster/config.env` keys use the short forms `cp1`…`w3` that the live cluster has run on for ≥51 days. Asset-style names (`TDNHQ-TLO*`) are retained as cross-reference in `systems`. |
| [0003](repo/0003-repo-as-cluster-source-of-truth.md)           | Treat Repo as Cluster Source of Truth          | Accepted | 2026-05-25 | This repository is the declarative source of truth for the cluster. Out-of-band changes require a back-fill PR within 7 days. Drift-detection CI is committed as a follow-up. |
| [0004](repo/0004-capture-longhorn-volume-config-in-talos.md)   | Capture Longhorn Volume Config in Talos        | Accepted | 2026-05-25 | `cluster/patches/volumes.yaml` declares the EPHEMERAL `VolumeConfig` and the Longhorn `UserVolumeConfig`; `scripts/generate.sh` appends them to every per-node config so `make apply` doesn't drop production storage. |
| [0005](repo/0005-kubelet-csr-approver.md)                      | Use postfinance/kubelet-csr-approver           | Accepted | 2026-05-25 | Deploy postfinance/kubelet-csr-approver Helm chart to auto-approve `kubernetes.io/kubelet-serving` CSRs. Precondition for re-enabling `rotate-server-certificates` in `common.yaml`. Provider regex + IP prefix scope approval to the 6 known nodes / management subnet. |
| [0006](repo/0006-etcd-snapshot-automation.md)                  | Daily etcd Snapshots to S3 for Cluster Recovery | Accepted | 2026-05-26 | Daily `talosctl etcd snapshot` via GitHub Actions, uploaded KMS-encrypted to `s3://.../etcd-snapshots/`. Combined with `secrets/secrets.yaml` this is the cluster-recovery primitive. Restore-drill is a follow-up ADR. |
| [0007](repo/0007-capture-longhorn-as-managed-addon.md)         | Capture Longhorn as Managed Addon              | Accepted | 2026-05-26 | `addons/longhorn/values.yaml` captures the seven non-default values applied to the live Longhorn 1.11.1 release. Pays ADR-0004 §5's debt. Backup target + RecurringJobs are a follow-up cycle. |
| [0008](repo/0008-gitops-via-flux.md)                           | GitOps via Flux for Cluster-Level Reconciliation | Accepted | 2026-05-26 | Flux v2.8.8 reconciles `clusters/talos-cluster/` from this repo. SSH deploy-key auth. First migration: `kubelet-csr-approver` HelmRelease. Subsequent cycles migrate metrics-server, ingress-nginx, Longhorn, Cilium. Image Automation is a separate future cycle. |
| [0009](repo/0009-stig-cis-compliance-baseline.md)              | STIG / CIS Benchmark as the Compliance Baseline | Accepted | 2026-05-26 | DISA Kubernetes STIG (primary) + CIS Kubernetes Benchmark v1.10.x (secondary). STIG wins conflicts. Every future PR carries STIG/CIS impact assessment. kube-bench deployment is the next follow-up cycle. Accepted deviations tracked inline. |
| [0010](repo/0010-adopt-kyverno-policy-engine.md)               | Adopt Kyverno as the Cluster Policy Engine      | Accepted | 2026-05-27 | Install Kyverno via Flux as the policy engine for image signature verification, SBOM/attestation checks, and future tenant guardrails. |
| [0011](repo/0011-auto-discover-deploy-repositories.md)         | Auto-Discover Deploy Repositories by Convention | Accepted | 2026-06-01 | Generate tenant-scoped Flux wiring for `deploy-*` repositories that expose the standard Talos overlay, so app repos own future workload/image changes. |
| [0012](repo/0012-vault-kms-auto-unseal-credential-delivery.md) | Vault KMS Auto-Unseal — AWS Credential Delivery, Egress, and Key Model | Accepted | 2026-06-02 | Deliver AWS creds to Vault's `awskms` seal via an IAM Roles Anywhere serve-mode sidecar (no image change); dedicated single-purpose CMK; SOPS workload cert in `apps/vault-aws-access/`; recovery bundle SSM-only. |
| [0013](repo/0013-use-dedicated-vault-longhorn-storageclass.md) | Use a Dedicated Vault Longhorn StorageClass      | Accepted | 2026-06-10 | Add the `longhorn-vault` StorageClass for new Vault PVCs: 3 replicas with replica node anti-affinity, without raising the cluster-wide Longhorn default. |

## Status Lifecycle

An ADR moves through the following statuses. Every ADR in the Index above shows its current status.

- **Proposed.** The ADR has been drafted and is under discussion. The decision has not yet been made. A `Review-by` date should be set; if the ADR is not Accepted or Rejected by that date, it should be revisited or closed.
- **Accepted.** The ADR represents an active decision. The code in the repository should reflect it. This is the working state of most ADRs.
- **Rejected.** The ADR was considered and decided against. It remains in the repository as a historical record so future readers can see that the option was evaluated.
- **Superseded by ADR-NNNN.** The decision was valid at the time but has been replaced by a later ADR. Both ADRs remain in the repository. The superseded ADR points forward to the newer one in its `Superseded by` section, and the newer ADR points back in its `Supersedes` section.
- **Deprecated.** The ADR describes a decision that is no longer in force but has not been explicitly replaced. This status should be rare and should usually be followed by a superseding ADR that explains what changed.

An Accepted ADR may still receive non-substantive maintenance updates, but any change that alters the decision, its scope, or its rationale requires a superseding ADR.

## How to Contribute a New ADR

1. Decide whether the change is architecturally significant. The four tests are in [ADR-0001](org/0001-use-architecture-decision-records.md) under `Decision Outcome`. When in doubt, err toward writing the ADR; a short record is cheaper than reconstructing the reasoning later.
2. Decide the **scope**:
   - **Org-baseline** — the decision applies across the `nwarila-platform` organization, regardless of stack. Author the ADR in this `nwarila-platform/.github` repository at `docs/decision-records/NNNN-short-kebab-title.md`. After it is accepted, mirror it into every adopting child repository's `docs/decision-records/org/` directory in a follow-up sync PR per repo.
   - **Type-template** — the decision applies to every consumer of a particular type-template (e.g. every Terraform consumer derived from `NWarila/terraform-runner-template`). Author the ADR in the appropriate type-template repository at `docs/decision-records/NNNN-short-kebab-title.md`. After it is accepted, mirror it into every consumer of that template's `docs/decision-records/template/` directory in a follow-up sync PR per consumer.
   - **Repository-specific** — the decision affects only one repository. Author the ADR in that repository at `docs/decision-records/repo/NNNN-short-kebab-title.md`. Do not mirror it elsewhere.
3. Copy [ADR-0001](org/0001-use-architecture-decision-records.md) to the new file. `NNNN` is the next unused four-digit number in the chosen scope's directory. Numbers are allocated monotonically and never reused. The org, template, and repo namespaces are independent (ADR `org/0001`, `template/0001`, and `repo/0001` can coexist in different directories).
4. Strip the template-instruction HTML comment block at the top of the copied file.
5. Replace the metadata values and every section body with content specific to the new decision. Keep the section headings in the order shown. For sections that genuinely do not apply, write "None." or "N/A (reason)." rather than deleting the heading. A missing heading reads as "I forgot"; an explicit "None." reads as "I considered this and there is nothing to record."
6. Update the appropriate index. For org-baseline ADRs, update the upstream Index in `nwarila-platform/.github` first and mirror it here with the accepted ADR. For repository-specific ADRs, update this repository's `docs/decision-records/README.md`.
7. Open a pull request in the repository where the new ADR lives. The new ADR and the index update belong in the same PR.

## Conventions

- **Directory layout.** Org-baseline ADRs live in `nwarila-platform/.github/docs/decision-records/` as master copies and in this repository's `docs/decision-records/org/` as mirrored copies. Type-template ADRs live in their owning type-template repository's `docs/decision-records/` (master) and in `docs/decision-records/template/` (mirrored copies in every consumer of that template). Repository-specific ADRs live in `docs/decision-records/repo/` in their owning repository only. Every adopting child repository carries the full skeleton (`docs/decision-records/{org,template,repo}/.gitkeep`) so the layout is visible even when individual scopes are empty.
- **Directory naming.** Use `decision-records` as the directory name so the purpose is obvious even to readers who do not know the acronym.
- **Filenames.** `NNNN-short-kebab-title.md`, where `NNNN` is a four-digit zero-padded number and the title is a present-tense verb phrase in kebab case. Example: `0004-pin-github-actions-by-commit-sha.md`.
- **Numbering.** Monotonic. Gaps are allowed. Numbers are never reused, even if a proposed ADR is later abandoned.
- **Titles.** Start with a present-tense imperative verb. Prefer `Pin GitHub Actions by Commit SHA` over `GitHub Actions Pinning Policy`. The title is also the H1 of the file, prefixed with `ADR-NNNN:`.
- **Metadata fields.** The table at the top of every ADR records `Status`, `Date`, `Authors`, `Decision-maker`, `Consulted`, `Informed`, `Reversibility`, and `Review-by`. `Consulted` and `Informed` follow RACI-style conventions: people whose input was actively sought versus people who were kept in the loop. `Reversibility` is an ease-of-change estimate: `Low` means hard to reverse (deeply committed), `Medium` means reversal is possible but involves meaningful migration or rework, and `High` means easy to reverse. `Review-by` is the date by which a `Proposed` ADR should be accepted or rejected; it is typically `N/A (Accepted)` once the ADR is Accepted.
- **Editing.** Accepted ADRs are append-only for substantive meaning. Allowed post-acceptance updates are Status changes, `Supersedes` and `Superseded by` links, `Implementing PRs`, and editorial corrections that do not alter the decision.

## Further Reading

Readers unfamiliar with ADRs as a genre may find the following useful. None of these is required; they are provided for context.

- **Michael Nygard, [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions.html) (2011).** The original post that introduced the ADR concept.
- **[MADR](https://adr.github.io/madr/) (Markdown Architectural Decision Records).** The community template that this baseline aligns with.
- **Joel Parker Henderson, [`architecture-decision-record`](https://github.com/joelparkerhenderson/architecture-decision-record).** A widely referenced collection of ADR formats and examples.
- **ThoughtWorks Technology Radar, [Lightweight Architecture Decision Records](https://www.thoughtworks.com/radar/techniques/lightweight-architecture-decision-records) (Adopt, November 2017).** Recommends keeping ADRs in source control instead of a wiki or website.
