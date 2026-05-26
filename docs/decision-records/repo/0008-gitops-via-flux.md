# ADR-0008: GitOps via Flux for Cluster-Level Reconciliation

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-05-26                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

This cluster adopts [Flux](https://fluxcd.io/) as its GitOps engine. Four controllers (`source-controller`, `kustomize-controller`, `helm-controller`, `notification-controller`) at version `v2.8.8` run in `flux-system` and reconcile the cluster against the `clusters/talos-cluster/` directory of this repository's `feat/sync-org-adrs-and-deny-all-gitignore` branch (and later, `main`). Authentication is via an SSH deploy key (`flux-bootstrap`, read+write, deploy key ID `152623809`) on the repository, with the private half stored as `flux-system/flux-system` Secret in the cluster. `HelmRelease` resources under `clusters/talos-cluster/apps/<addon>/` replace one-shot `helm install` operator commands; chart versions are pinned and Renovate-managed. The first addon migrated is `kubelet-csr-approver` (commit `4ee1faa`) as the proof of the take-over pattern. Image Automation controllers (`image-reflector-controller`, `image-automation-controller`) are NOT installed in this ADR; they are a follow-up cycle once there are container images this repo wants to auto-track.

## Context and Problem Statement

Until this ADR, every addon in `addons/` was installed by the operator running `helm install` commands from the README runbook against the live cluster. That model worked while the cluster was small and changes were rare, but it has three structural problems that have surfaced in this branch already:

1. **Drift between repo and live release**. Longhorn was running in `longhorn-system` for 51 days before [ADR-0007](0007-capture-longhorn-as-managed-addon.md) finally captured its values in the repo. There was no mechanism that would have *prevented* the gap, only one that *detected* it after the fact ([scripts/drift-check.sh](../../../scripts/drift-check.sh)). Even drift detection covers only Talos machine config, not Helm release state.

2. **Install order is encoded in operator memory**. The README walks through Cilium → kubelet-csr-approver → metrics-server → ingress-nginx → local-path-provisioner → Longhorn → poc. Get the order wrong and the cluster boots partially functional. There is no mechanism for "the right thing happens regardless of what the operator runs first."

3. **Renovate-merged chart bumps don't deploy themselves**. Renovate PRs a chart-version bump, the PR merges, and the cluster keeps running the old version until an operator remembers to `helm upgrade`. The drift detector would surface it, but only after the fact.

[Flux](https://fluxcd.io/) is the standard answer for these in the Talos ecosystem (Sidero's docs recommend it; canonical reference repos `onedr0p/cluster-template` and `bjw-s/home-ops` both use it). It works by watching a Git repository for changes and reconciling resources in the cluster to match — without an operator running commands.

## Decision Drivers

1. **Continuous reconciliation, not point-in-time install**. The cluster should converge to what the repo says, every 10 minutes (default `HelmRelease.spec.interval`), without operator action.
2. **One commit landing should equal one deployment**. Renovate's chart-bump PR merge → Flux upgrades the release. No human-in-the-loop after merge.
3. **Take-over of existing releases must be idempotent**. The cluster already has Cilium, ingress-nginx, metrics-server, local-path-provisioner, Longhorn, and kubelet-csr-approver installed via `helm install`. Adopting Flux must not require uninstalling and reinstalling them.
4. **No secrets in git**. Flux's GitRepository authenticates via SSH deploy key (Secret in cluster), not a committed Personal Access Token.
5. **Tightly-scoped permissions for the bootstrap key**. The deploy key is per-repo, with read+write access (write needed for future Image Automation cycles that commit tag updates back to the repo). It cannot be used against any other repository or org-level operation.

## Considered Options

1. **Flux** (CNCF graduated GitOps engine; multi-controller architecture).
2. **Argo CD** (CNCF graduated GitOps engine; UI-first, application-CRD model).
3. **Helmfile or terraform-helm-provider running from CI**.
4. **Stay on the manual `helm install` model.**

## Decision Outcome

Chosen option: **Option 1, Flux.**

`flux bootstrap git` is the install path; an SSH deploy key with read+write is the auth surface; the cluster directory structure is:

```
clusters/talos-cluster/
├── kustomization.yaml              # top-level: includes flux-system + apps
├── flux-system/
│   ├── gotk-components.yaml        # the 4 Flux controllers (CRDs, Deployments, RBAC)
│   ├── gotk-sync.yaml              # GitRepository + Kustomization reconciling THIS dir
│   └── kustomization.yaml          # file index
└── apps/
    ├── kustomization.yaml          # apps aggregator
    └── kubelet-csr-approver/
        ├── helmrepository.yaml     # postfinance chart index
        ├── helmrelease.yaml        # the declarative release definition
        └── kustomization.yaml      # file index
```

Reconciliation cadence:
- `GitRepository.spec.interval: 1m` — poll Git for new commits every minute.
- `Kustomization.spec.interval: 10m` — re-apply the cluster Kustomization every 10 minutes.
- `HelmRelease.spec.interval: 10m` — re-reconcile each Helm release every 10 minutes.
- `HelmRepository.spec.interval: 1h` — poll the upstream chart index every hour.

Subsequent cycles will migrate the remaining addons one at a time, in increasing-risk order:
1. `kubelet-csr-approver` (this ADR's proof — smallest, simplest).
2. `metrics-server` (small, no persistent state).
3. `ingress-nginx` (medium, no persistent state).
4. `local-path-provisioner` (currently installed via raw manifests, may need conversion).
5. `Longhorn` (large, holds persistent state — most cautious migration).
6. `Cilium` (CNI — most invasive migration; reconciliation glitches can break cluster networking).

## Pros and Cons of the Options

### Option 1: Flux (chosen)

- **Good, because** native HelmRelease + Kustomization CRDs cover both the existing `helm install` addons and any raw-manifest addons in the same reconciliation loop.
- **Good, because** chart versions stay pinned in YAML; Renovate-driven bumps merge as PRs and apply via Flux without operator action.
- **Good, because** the architecture is well-documented and the install path (`flux bootstrap git`) takes ~2 minutes end-to-end.
- **Good, because** Flux's take-over of existing Helm releases is non-disruptive: helm-controller sees an existing release with matching `version`, `releaseName`, `targetNamespace`, and `values`, and skips the upgrade. Verified 2026-05-26 against the live `kubelet-csr-approver` release: pods unchanged (15h age preserved), release revision bumped 1→2 but rendered manifests identical.
- **Good, because** secrets-in-git is a separable concern: Flux works fine without SOPS/sealed-secrets for now, and adopting either is a future cycle.
- **Bad, because** four new controllers in `kube-system` (well, `flux-system`) add ~150 MiB of memory and a small RBAC footprint. Acceptable for a 6-node cluster.
- **Bad, because** Flux's `clusters/<name>/flux-system/gotk-components.yaml` is 6400+ lines of generated manifest that Renovate cannot bump (no version pattern Renovate recognizes). Flux upgrades are a manual `flux install --export > clusters/talos-cluster/flux-system/gotk-components.yaml` + commit. Acceptable: Flux releases roughly monthly, and the manual file regeneration is one command.

### Option 2: Argo CD

- **Good, because** mature UI for visualizing application state, useful for larger teams.
- **Bad, because** the Application CRD model maps less cleanly to "this directory is the cluster" than Flux's Kustomization-of-a-directory pattern.
- **Bad, because** Argo's `Application` resources tend to live IN-cluster as long-running CRDs, not as files in git. This is an inversion of source-of-truth: applications appear in the cluster without a corresponding file change.
- **Neutral**: Argo and Flux are roughly equivalent on raw capability; the choice comes down to the Talos community's preference for Flux and the simpler bootstrap.

### Option 3: Helmfile or terraform-helm from CI

- **Good, because** zero new in-cluster components.
- **Bad, because** CI-driven Helm runs are not continuous — they reconcile only when CI fires, not when the live cluster drifts.
- **Bad, because** the failure mode of "CI ran but nothing's reconciling now" is invisible from inside the cluster; whereas Flux's controller status is observable via `flux get all` from anywhere with kubeconfig access.

### Option 4: Manual `helm install`

- **Good, because** zero new tooling.
- **Bad, because** every problem from §"Context and Problem Statement" persists. The Longhorn discovery (51-day gap before the Helm side was captured) is the empirical evidence this option fails for this cluster's pace of change.

## Confirmation

Adherence to this ADR is confirmed by the following mechanisms. The wording `MUST`, `SHOULD`, and `MAY` follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) conventions.

1. **Controller presence.** All four `flux-system` deployments (`source-controller`, `kustomize-controller`, `helm-controller`, `notification-controller`) MUST report Ready in `kubectl get deploy -n flux-system`.
2. **Reconciliation health.** `flux get all` MUST report every GitRepository, HelmRepository, HelmRelease, and Kustomization as `READY: True`. A scheduled CI check MAY assert this on every drift-detection workflow run.
3. **No drift-by-helm-install.** Every release in `kubectl get hr -A` MUST have a corresponding `HelmRelease` manifest under `clusters/talos-cluster/apps/`. Operators MUST NOT run `helm install` or `helm upgrade` directly against the cluster for any addon under Flux management. The exception is during incident response, in which case the back-fill rule from [ADR-0003](0003-repo-as-cluster-source-of-truth.md) applies (back-fill within 7 days).
4. **Chart-version pinning.** Every `HelmRelease.spec.chart.spec.version` MUST be an exact version (`1.2.14`), never a range or `*`. Renovate manages bumps.
5. **Values colocation.** When an addon has both a human-readable `addons/<name>/values.yaml` (for the README install command and historical reference) AND a `HelmRelease.spec.values`, they MUST stay in sync. A future cycle MAY extend `scripts/drift-check.sh` to assert equality; until then, the rule is enforced by reviewer attention.
6. **Bootstrap key scope.** The SSH deploy key `flux-bootstrap` (ID `152623809`) MUST remain repo-scoped (single repository) with read+write access only. It MUST NOT be promoted to an organization-level secret or shared across repos.

## Consequences

### Positive

- One commit landing on the branch (after the next 1-minute GitRepository poll) reconciles the cluster automatically.
- Renovate's chart-version bump PRs land and deploy themselves on merge — no operator action.
- The cluster directory layout `clusters/<cluster-name>/` lets future multi-cluster support drop in naturally (a hypothetical `clusters/talos-cluster-2/` would have its own `flux-system/` pointing at the same repo).
- The path to Image Automation is one cycle away: install `image-reflector-controller` + `image-automation-controller`, write an `ImageRepository` + `ImagePolicy` + `ImageUpdateAutomation` per app that wants auto-tag-tracking.

### Negative

- A new failure class: Flux controllers themselves can be misconfigured or crash-loop. The `notification-controller` is the early-warning channel (it can send to Slack/Discord/email); no notification provider is configured in this ADR. Operators see Flux issues via `flux get all` or via the next drift-detection workflow run.
- The `gotk-components.yaml` file is huge (6437 lines) and not Renovate-trackable. Flux upgrades require a manual `flux install --export` + commit. Acceptable but documented.
- Bootstrap auth via a deploy key means rotating the key requires another `gh repo deploy-key add` + `flux bootstrap --recreate` cycle. Acceptable; the key is per-repo and write-only, the blast radius of a leak is bounded.

### Neutral

- `kustomize build clusters/talos-cluster/` works as a dry-run of what Flux would apply. Useful in CI as a validation step (future cycle could add this).
- The first reconciliation of an existing Helm release bumps the release revision (Helm always does on `upgrade`) but does not touch the actual workload pods if rendered manifests are identical. Verified for `kubelet-csr-approver` on 2026-05-26.

## Assumptions

This decision rests on the following assumptions. If any becomes false, this ADR should be revisited:

1. Flux v2 remains the upstream-supported GitOps engine for Kubernetes. (Flux v1 was deprecated in 2022; v2 has been the canonical version since then. No competing CNCF-graduated successor on the horizon.)
2. The cluster has continuous network reach to GitHub from `flux-system` (port 22 outbound). If a future network policy default-deny ([another candidate cycle](../../../README.md)) cuts this, Flux stops reconciling and `notification-controller` cannot reach external alerting.
3. `helm-controller`'s take-over of an existing `helm install`-installed release continues to be idempotent when values and chart version match. This is the documented behavior in Flux v2 docs; verified on this cluster for kubelet-csr-approver.

## Supersedes

None.

## Superseded by

None (current). A future ADR may adopt Image Automation (additional controllers + `ImageRepository`/`ImagePolicy`/`ImageUpdateAutomation` CRDs). That decision is its own concern (registry policy, semver constraint, what counts as an automatable bump).

## Implementing PRs

The PR that introduces this ADR also introduces:
- `clusters/talos-cluster/flux-system/` (bootstrap manifests; committed in c5c55b2)
- `clusters/talos-cluster/apps/kubelet-csr-approver/` (HelmRelease + HelmRepository; committed in 4ee1faa)
- `clusters/talos-cluster/kustomization.yaml` + `clusters/talos-cluster/apps/kustomization.yaml`
- `.gitignore` allowlist entries
- README "Step X: Bootstrap Flux" section (added in the same commit as this ADR)
- This ADR + index entry

The deploy key `flux-bootstrap` (ID 152623809) was added to the repository via `gh repo deploy-key add` on 2026-05-26 with read+write access.

### Out-of-band cleanup (2026-05-26)

The cluster previously had an ArgoCD installation (chart `argo-cd-9.4.17`,
namespace `argocd`, 8 pods + 3 CRDs + 2 ClusterRoles + 1 ApplicationSet
+ 3 AppProjects + 1 Application) running in parallel with Flux. The
ArgoCD-managed `deploy-whoami` workload's source repo had been deleted
upstream, so ArgoCD had been failing to sync since 2026-05-15.

Per this ADR's selection of Flux as the single GitOps engine, the
ArgoCD installation was removed cluster-side on 2026-05-26:

1. Removed `deploy-whoami` Application's resources-finalizer (while
   argocd-application-controller was still alive to clean it).
2. Deleted the `tenant-apps` ApplicationSet, `deploy-whoami` Application,
   all 3 AppProjects.
3. `helm uninstall argocd -n argocd` (removed Deployments, RBAC, leftover
   helm-managed resources). CRDs were retained by Helm's resource-policy
   annotation and deleted explicitly afterwards.
4. Deleted the 3 ArgoCD CRDs (`applications.argoproj.io`,
   `applicationsets.argoproj.io`, `appprojects.argoproj.io`).
5. Deleted the `argocd` namespace.
6. Deleted the orphaned `deploy-whoami` namespace (orphan workload with
   no upstream source).

Rollback path: fresh etcd snapshot taken before cleanup at
`s3://793496711039-terraform/nwarila-platform/talos-cluster/etcd-snapshots/2026-05-26/snapshot-222614Z.db`.

Post-cleanup state: 7 namespaces (cilium-secrets, default, flux-system,
kube-node-lease, kube-public, kube-system, longhorn-system), 67 Running
pods (down from 77). Kubescape SARIF findings dropped from 222 to 179
(43-finding reduction, ~19%) since the ArgoCD pods carried multiple
restricted-PSS violations.

## Related ADRs

- [ADR-0003 (repo)](0003-repo-as-cluster-source-of-truth.md) — establishes the source-of-truth invariant Flux now continuously enforces.
- [ADR-0004 (repo)](0004-capture-longhorn-volume-config-in-talos.md) — captures Talos-side Longhorn config; future Flux migration cycle will move Longhorn's Helm side under `clusters/talos-cluster/apps/longhorn/`.
- [ADR-0005 (repo)](0005-kubelet-csr-approver.md) — the addon migrated as Flux's proof-of-concept.
- [ADR-0007 (repo)](0007-capture-longhorn-as-managed-addon.md) — captures the Helm-side Longhorn values; future Flux migration cycle will turn those into a HelmRelease.

## Compliance Notes

This ADR formalizes the cluster's continuous-reconciliation model. Combined with [ADR-0003](0003-repo-as-cluster-source-of-truth.md) (source of truth) and [ADR-0006](0006-etcd-snapshot-automation.md) (recoverability), it constitutes the cluster's full configuration-management posture.

| Framework              | Control / Practice ID                              | Potential Evidence Contribution                                                                                              |
| ---------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| NIST SP 800-53 Rev. 5  | CM-2 (Baseline Configuration)                      | The cluster's runtime state is continuously reconciled against the declarative baseline in git.                              |
| NIST SP 800-53 Rev. 5  | CM-3 (Configuration Change Control)                | Configuration changes flow through PR review + Renovate; changes apply automatically post-merge with no out-of-band actions. |
| NIST SP 800-53 Rev. 5  | CM-6 (Configuration Settings)                      | All addon Helm values are version-controlled YAML in `clusters/talos-cluster/apps/<addon>/helmrelease.yaml`.                   |
| NIST SP 800-53 Rev. 5  | AU-2 (Event Logging)                               | helm-controller logs every reconciliation event; `flux events` provides an audit trail of every applied change.              |
