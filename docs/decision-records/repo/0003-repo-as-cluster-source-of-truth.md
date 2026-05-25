# ADR-0003: Treat This Repository as the Cluster's Source of Truth, Backed by Drift Detection

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-05-25                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | High                                    |
| Review-by      | 2026-08-25                              |

## TL;DR

This repository is the declarative source of truth for `TDNHQ-TALCL01`. Cluster state — node count, hostnames, install disks, Talos and Kubernetes versions, machine-config patches — is changed by editing this repository and applying via `make apply` / `make upgrade`. Out-of-band changes (direct `talosctl apply-config` from an operator workstation, manual `kubectl edit` of node-level state, ad-hoc scale-out without a PR) are NOT permitted, with the single exception of break-glass incidents that MUST be back-filled into this repository within seven days of the incident. To make this enforceable, a follow-up cycle (out of scope for this ADR) MUST add CI-side drift detection that compares the running cluster against the regenerated machine configs in this repository.

## Context and Problem Statement

On 2026-05-25, a routine credential test against the live cluster surfaced material drift between this repository and reality. The repository declared a 2 CP + 2 worker topology; the cluster had been running 3 CP + 3 worker for ≥38 days (node ages: cp1/cp3/w2/w3 = 51 days; cp2/w1 = 38 days). The repository declared `KUBERNETES_VERSION="v1.32.2"`; the cluster ran v1.35.2 across all nodes. The repository's per-node patches said install disk `/dev/sda` for two of the four declared nodes; every live node had system disk `/dev/nvme0n1`. The repository used asset-style hostnames `TDNHQ-TLOMGT0N`; the live cluster used short names `cp1`…`w3`.

None of these divergences was visible to the existing CI: [.github/workflows/validate.yaml](../../../.github/workflows/validate.yaml) validates the patches as Talos config schema (it does not contact the cluster), and [.github/workflows/security.yaml](../../../.github/workflows/security.yaml) audits the patches for embedded secrets and VIP consistency (it also does not contact the cluster). The repository validated as a consistent declarative artifact while being silently wrong about every node count, name, disk, and Kubernetes version.

A repository that claims to be the source of truth for a production cluster but cannot tell when it isn't is more dangerous than a repository with no such claim, because operators (and AI agents) take its declared state at face value. The 38-day gap implies at least one scale-out (the second CP and the second worker were added 13 days after the original three) occurred outside the repository's PR flow. The Kubernetes-version gap implies at least one rolling upgrade was performed without bumping `cluster/config.env`. Without a fix, the next operator who runs `make apply` from a fresh checkout downgrades Kubernetes by three minor versions and reboots cp1/w2 onto a disk that is no longer their system disk.

## Decision Drivers

1. **Operator trust.** Anyone reading this repository — human or agent — should be able to assume that `cluster/config.env` and `cluster/patches/` describe the live cluster. The cost of breaking that assumption silently is paid in production incidents.
2. **No surprise downgrades.** The next `make apply` MUST NOT roll Kubernetes, Talos, or any node's install disk backward.
3. **Detectability over manners.** A "everybody agrees to PR changes" policy is uneforceable in a single-maintainer portfolio; the policy needs an automated detector.
4. **Reversibility cost.** Choosing a too-strict policy (e.g., reject all out-of-band operator action) blocks legitimate incident response and erodes trust in the rule. The policy must explicitly allow break-glass operations with a back-fill SLA.

## Considered Options

1. **Declare repo authoritative + add drift-detection CI now.**
2. **Declare repo authoritative + add drift-detection CI in a follow-up cycle.**
3. **Declare repo authoritative; rely on operator discipline alone.**
4. **Drop the source-of-truth claim; document the repo as a starting-point template only.**

## Decision Outcome

Chosen option: **Option 2, declare repo authoritative and commit to drift detection in a follow-up cycle.**

This ADR (a) records that the repository IS the source of truth for cluster declarative state, (b) records the break-glass back-fill SLA, and (c) explicitly commits to a follow-up cycle that authors a drift-detection workflow. Bundling the drift-detection implementation into this ADR would force one of two unhealthy compromises: either the ADR PR balloons in scope and reviewability suffers, or the drift detector ships rushed and produces false positives that get muted before they're trusted.

Drift detection is sketched here, not authored: a CI job runs `make generate` against a throwaway secrets bundle, then runs `talosctl --talosconfig <prod> diff` against each live node and posts the diff as a PR comment / scheduled-job artifact. The same job asserts that `kubectl version --output=json` on the cluster reports a server `gitVersion` whose major.minor matches `KUBERNETES_VERSION` in `cluster/config.env`. Anything non-empty fails the job. Implementation details (where the talosconfig credential comes from in CI, whether the job runs on a self-hosted runner with network access to the VIP, how often the scheduled job fires) belong in the follow-up ADR-and-PR.

## Pros and Cons of the Options

### Option 1: Authoritative + detection now

- **Good, because** the policy is enforced from day one.
- **Bad, because** the detection workflow needs design choices (credential surface, runner network access, false-positive handling) that are themselves multi-step decisions. Cramming both into one PR yields a worse detector and a worse ADR.

### Option 2: Authoritative + detection in follow-up (chosen)

- **Good, because** the policy is captured immediately so reviewers can cite it.
- **Good, because** the detector gets its own design pass without being on the critical path of this reconciliation.
- **Bad, because** the policy is unenforced between this ADR and the follow-up. The gap is bounded by the explicit `Review-by` date in the metadata table.

### Option 3: Authoritative + operator discipline

- **Bad, because** operator discipline is exactly the property that failed for ≥38 days before this ADR. Repeating the policy without adding detection re-creates the same failure mode.

### Option 4: Drop the source-of-truth claim

- **Bad, because** the repository's entire automation surface (`make generate`, `make apply`, `make upgrade`, the CI validate and security workflows) is built on the assumption that the patches describe the cluster. Renouncing source-of-truth status would require deleting most of that automation.

## Confirmation

Adherence to this ADR is confirmed by the following mechanisms. The wording `MUST`, `SHOULD`, and `MAY` follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) conventions.

1. **Out-of-band changes prohibited.** Direct `talosctl apply-config`, `talosctl upgrade`, manual `kubectl edit` of node-level state, and scale-out / scale-in performed outside a PR to this repository MUST NOT be the normal mode of operation.
2. **Break-glass exception.** During an active incident, an operator MAY apply out-of-band changes if they materially shorten the time to restore service. The operator MUST back-fill the change into this repository within seven days of the incident, in a PR that links the incident write-up and explains why the in-repo path was not used.
3. **Drift-detection follow-up.** A repo-tier follow-up ADR and implementing PR MUST author CI-side drift detection (a `talosctl diff` job and a server-version assertion) before the `Review-by` date in this ADR's metadata table. If the follow-up has not landed by that date, this ADR is re-opened.
4. **Version pin discipline.** `cluster/config.env` `TALOS_VERSION` and `KUBERNETES_VERSION` MUST be updated in the same PR that bumps the live cluster. The PR that runs the upgrade and the PR that updates the pin MAY be the same PR (the upgrade workflow's manual approval gate is the change-management point).
5. **Reconciliation precedent.** The reconciliation PR that introduces this ADR is the recorded precedent for how drift is closed when discovered: regenerate locally, `talosctl validate --strict` on the regenerated configs, `talosctl diff` against the live cluster, then merge.

## Consequences

### Positive

- Reviewers and agents have an explicit rule to cite when an out-of-band change is proposed.
- Future drift will be detected by CI rather than by accident during credential testing.
- The break-glass exception is named explicitly, so operators are not forced to choose between policy violation and slower incident response.

### Negative

- The policy is unenforced between this ADR and the follow-up implementation. The `Review-by` date bounds that gap.
- Drift-detection CI requires the cluster's talosconfig in a CI runner that can reach the VIP, which is a new credential-handling surface. The follow-up ADR will address that risk explicitly.
- Operators must remember to file a back-fill PR within seven days of a break-glass action; the policy relies on individual discipline at exactly the moment that discipline is hardest to maintain.

### Neutral

- The repository today already does most of the source-of-truth work; this ADR formalizes it rather than introducing it.

## Assumptions

This decision rests on the following assumptions. If any becomes false, this ADR should be revisited:

1. `talosctl --talosconfig <prod> diff --nodes <ip>` returns an empty diff when the local generated config matches the running machine config. (Held true for Talos 1.12 in practice; confirm before authoring the drift workflow.)
2. A CI runner can be configured with network access to the cluster VIP without exposing the talosconfig more broadly than the existing `make apply` workflow does. (The current `deploy.yaml` workflow already requires a self-hosted runner on the management network; the drift workflow can re-use it.)
3. The portfolio remains single-maintainer, so the "PR review" gate is a self-review. Adding a second maintainer is itself a process change that may justify revisiting this ADR.

## Supersedes

None.

## Superseded by

None (current). A follow-up ADR will be authored when the drift-detection workflow is implemented; that ADR refines but does not supersede this one.

## Implementing PRs

The PR that introduces this ADR also implements the reconciliation that surfaced the drift (renaming patches to short names per [ADR-0002](0002-use-short-talos-hostnames.md), adding cp3/w3 to the inventory, bumping `KUBERNETES_VERSION` to v1.35.2, and correcting install disks to `/dev/nvme0n1`).

## Related ADRs

- [ADR-0001 (org)](../org/0001-use-architecture-decision-records.md) — defines the ADR format used here.
- [ADR-0002 (repo)](0002-use-short-talos-hostnames.md) — captures one of the four divergences this ADR is responding to.

## Compliance Notes

This ADR records a process control rather than a technical one. The associated drift-detection workflow (follow-up) is the technical enforcement.

| Framework              | Control / Practice ID                              | Potential Evidence Contribution                                                                                                            |
| ---------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| NIST SP 800-53 Rev. 5  | CM-2 (Baseline Configuration)                      | The repository is named as the baseline configuration of record for the cluster.                                                           |
| NIST SP 800-53 Rev. 5  | CM-3 (Configuration Change Control)                | The "out-of-band changes prohibited" rule and the break-glass back-fill SLA define the change-control process.                              |
| NIST SP 800-53 Rev. 5  | CM-6 (Configuration Settings)                      | Version pins and per-node patches in this repository are the authoritative configuration settings; drift is monitored by the follow-up CI. |
