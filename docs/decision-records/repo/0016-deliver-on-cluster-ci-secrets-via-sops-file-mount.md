# ADR-0016: Deliver On-Cluster CI Secrets via SOPS File Mount

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-17                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | Step 107 TASK.md, PLAN credential-delivery architecture, ADR-0011, ADR-0015, imported Vault ADR-0005, current `sync-deploy-repos` workflow |
| Informed       | future platform operators, future deploy-* maintainers |
| Reversibility  | Medium                                  |
| Review-by      | 2026-12-17                              |

## TL;DR

Deliver on-cluster CI control-plane secrets through a dedicated, isolated ARC
runner that receives a SOPS-encrypted, Flux-decrypted Kubernetes Secret as a
read-only file mount. The first consumer is the `nwarila-repo-sync` GitHub App
private key (App ID `4080021`), used by `sync-deploy-repos` to mint a short-lived
`nwarila-repo-sync[bot]` token for generated pull requests. This keeps the
long-lived GitHub App signing key out of GitHub Actions secrets while matching
the existing `nwarila-runner-registrar` in-cluster SOPS precedent.

This is the D3 design: SOPS file mount now, with a deliberate migration seam for
a future D1 design where Vault mints the GitHub token directly. This ADR records
the decision only. It does not add the namespace, runner, Secret, workflow
cutover, smoke test, or any live cluster change.

## Context and Problem Statement

ADR-0011 makes `deploy-*` repositories the application deployment surface and
uses `sync-deploy-repos` to open generated wiring pull requests in this
repository. The workflow currently runs only on a schedule and manual dispatch,
discovers deploy repositories with `secrets.DEPLOY_REPO_DISCOVERY_TOKEN ||
github.token`, and opens or updates the generated pull request with
`github.token`.

That token is the gap. Pull requests authored by `github.token` do not trigger
the normal `pull_request` validation path, so an automation-authored wiring PR
cannot satisfy required checks without a human-authored replacement commit or a
different authoring principal. The desired principal is the `nwarila-repo-sync`
GitHub App, which can mint short-lived installation tokens scoped to the
repository work it performs.

There is no keyless GitHub App authentication path for this use case. Minting a
GitHub App installation token requires signing a JWT with the App private key.
The architectural question is therefore where the long-lived signing key should
live until a stronger token-minting service exists.

Storing the key as a GitHub Actions secret would be the first GitHub-stored App
signing key in this cluster control plane. That would break the precedent set by
`nwarila-runner-registrar`, whose App private key is stored in-cluster as a
SOPS-encrypted Secret and decrypted by Flux. It would also move a platform CI
control-plane credential into the same SaaS control plane that the key authorizes
against.

ADR-0015 accepts Vault Secrets Operator for ordinary workload secrets, but it
explicitly excludes platform CI control-plane credentials from the first VSO
migration. This credential is not a low-risk tenant app secret. It authorizes
cluster-source pull request creation and belongs in the protected platform
boundary until Vault can own the token minting flow safely.

Vault is also internal-only by design in imported Vault ADR-0005. A
GitHub-hosted runner cannot fetch the key from Vault unless Vault is exposed,
which remains rejected for this class of plumbing. The Talos cluster repository
also does not have a working GitHub OIDC-to-AWS path for this workflow, and
adding AWS Secrets Manager or KMS signing would fight the portfolio's
minimize-AWS and sovereignty posture.

## Decision Drivers

1. Keep the long-lived GitHub App signing key out of GitHub Actions secrets.
2. Preserve the existing SOPS-in-cluster precedent for GitHub control-plane App
   keys.
3. Keep Vault as the intended long-term secret authority without forcing a
   premature VSO migration for platform CI credentials.
4. Isolate the credential-bearing runner from ordinary CI and from untrusted
   pull request code.
5. Make the future Vault-mints-token design a local swap, not a redesign of the
   deploy-repo sync workflow.
6. Keep the cluster repo changes scoped to a platform capability and trust
   boundary, consistent with ADR-0011's trust-root split.
7. Avoid expanding the portfolio's AWS dependency surface for a GitHub control
   plane problem.

## Considered Options

1. **D3: SOPS-encrypted Kubernetes Secret mounted into a dedicated on-cluster
   ARC runner.**
2. **GitHub Actions secret containing the App PEM.**
3. **GitHub OIDC to AWS Secrets Manager or KMS signing.**
4. **GitHub-hosted runner retrieves the key from Vault.**
5. **D1: Vault GitHub secrets engine mints a short-lived GitHub token.**
6. **D2: Vault Secrets Operator syncs the App PEM into Kubernetes.**

## Decision Outcome

Chosen option: **Option 1, D3 SOPS file mount into a dedicated on-cluster ARC
runner.**

The implementation path is:

1. The owner provisions a GitHub runner group named `nwarila-repo-sync-ci`,
   scoped to selected repositories with only `nwarila-platform/talos-cluster`
   selected. This is an out-of-band org-admin action. It is feasible through the
   `nwarila-runner-registrar` app's `organization_self_hosted_runners: write`
   permission, but it is not modeled in this repository today. The
   `github-terraform-framework` repository is repository-scoped and has no
   runner-group resource or matching runner-group model at this decision point,
   so managing org runner groups as IaC is a deferred framework enhancement.
2. Add a dedicated namespace, `arc-runners-repo-sync`, for the repo-sync runner
   control plane.
3. Add a dedicated runner ServiceAccount in that namespace. It is intentionally
   present even before Vault integration because it is the stable identity seam
   for a future D1 or D2 migration.
4. Add namespace guardrails: restricted Pod Security labels, a Kyverno guard for
   dangerous interactive or privilege-expanding operations, default-deny
   networking, DNS egress, and GitHub-only egress for the runner pods.
5. Add a dedicated ARC scale set, `nwarila-repo-sync-arc-ci`, with
   `maxRunners: 1`, hardened pod security context, and a distinct
   `arc.nwarila.io/role: repo-sync-runner` label.
6. Store the `nwarila-repo-sync` App private key as a SOPS-encrypted Kubernetes
   Secret. Flux decrypts it in-cluster. The runner mounts it as a read-only
   Secret volume, not an environment variable.
7. Update `sync-deploy-repos` to run on the dedicated runner and use
   `actions/create-github-app-token@v3` to mint a short-lived
   `nwarila-repo-sync[bot]` token from the mounted PEM for the pull request
   creation step.
8. Keep repository discovery on the current low-privilege path unless and until
   a separate private-repository discovery decision introduces a read-only
   `nwarila-repo-reader` token.

The isolation layers are load-bearing:

1. **Runner group isolation.** The `nwarila-repo-sync-ci` runner group is scoped
   only to `nwarila-platform/talos-cluster`.
2. **Workflow trigger isolation.** `sync-deploy-repos` remains schedule and
   `workflow_dispatch` only. It does not run pull request or fork code.
3. **Namespace isolation.** The runner lives in its own PSA-restricted namespace.
4. **Policy isolation.** Kyverno policy denies interactive access and
   privilege-expansion primitives for the runner namespace while excluding Flux
   and the ARC controller operations that must create runner pods.
5. **Pod hardening.** Runner pods use non-root execution, dropped capabilities,
   `automountServiceAccountToken: false`, and a read-only secret mount for the
   App key.
6. **Network isolation.** Runner pods have default-deny networking with only DNS
   and GitHub egress allowed.
7. **At-rest isolation.** The App key is SOPS-encrypted in Git and decrypted only
   by Flux into the cluster runtime Secret.

This ADR does not claim any of those resources exist yet. They are the accepted
implementation direction for the subsequent capability steps.

### Staged Trajectory

D3 is not the final ideal. It is the smallest design that preserves the
portfolio's current trust posture without blocking on a larger Vault token
issuer.

The future D1 design is: Vault owns the GitHub App private key and its GitHub
secrets engine, plugin, or equivalent broker mints short-lived scoped GitHub
tokens for the runner. In that model, the PEM never reaches the runner. The
runner authenticates to Vault through the dedicated namespace and runner
ServiceAccount, then receives only the short-lived token needed for the PR step.

The future D2 bridge is: Vault Secrets Operator syncs the App PEM into a
namespace-local Kubernetes Secret instead of SOPS owning the Secret value. This
still delivers a PEM to Kubernetes and is weaker than D1, but it can reduce Git
secret rewrites after Vault is ready to own this credential class.

Both D1 and D2 target the same namespace and ServiceAccount created for D3. The
single workflow swap point is the token-minting step before
`peter-evans/create-pull-request`. Everything downstream still consumes a
short-lived GitHub token.

## Pros and Cons of the Options

### Option 1: D3 SOPS file mount into a dedicated ARC runner (chosen)

- **Good, because** it keeps the GitHub App signing key out of GitHub Actions
  secrets.
- **Good, because** it mirrors the already-deployed `nwarila-runner-registrar`
  SOPS/Flux Secret model.
- **Good, because** it is implementable with current cluster primitives and does
  not require exposing Vault.
- **Good, because** the dedicated namespace and ServiceAccount are the future
  Vault auth seam.
- **Bad, because** the PEM reaches the runner filesystem, so the runner becomes
  a credential-bearing trust boundary.
- **Bad, because** SOPS rotation still requires a Git secret rewrite until D1 or
  D2 replaces the source.

### Option 2: GitHub Actions secret containing the App PEM

- **Good, because** it is mechanically simple and works with GitHub-hosted
  runners.
- **Bad, because** it would create the portfolio's first GitHub-stored App
  signing key for this cluster control plane.
- **Bad, because** a leaked PEM can mint fresh installation tokens until the key
  is manually revoked or rotated.
- **Bad, because** it breaks the existing in-cluster SOPS precedent for GitHub
  control-plane App keys.

### Option 3: GitHub OIDC to AWS Secrets Manager or KMS signing

- **Good, because** it avoids storing the PEM directly in GitHub Actions
  secrets.
- **Bad, because** this workflow does not currently have a working
  GitHub OIDC-to-AWS path in talos-cluster.
- **Bad, because** it expands AWS dependency for a GitHub control-plane problem,
  conflicting with the portfolio's minimize-AWS and sovereignty posture.
- **Bad, because** it still does not make Vault the source of truth.

### Option 4: GitHub-hosted runner retrieves the key from Vault

- **Good, because** Vault would be the secret authority.
- **Bad, because** Vault is internal-only by imported Vault ADR-0005.
- **Bad, because** making this work from a GitHub-hosted runner would require
  exposing Vault or adding a new access plane, which is explicitly out of scope
  and rejected here.

### Option 5: D1 Vault mints the GitHub token

- **Good, because** the PEM never reaches the runner.
- **Good, because** the runner receives only the short-lived token it needs.
- **Bad, because** it requires additional Vault-side design, auth, policy,
  implementation, and recovery review before it can be safely used for platform
  CI control-plane credentials.
- **Neutral, because** it remains the preferred future endpoint rather than a
  rejected direction.

### Option 6: D2 VSO syncs the App PEM

- **Good, because** it would move the source value into Vault after VSO is ready
  for this credential class.
- **Bad, because** it still materializes the PEM as a Kubernetes Secret and
  therefore does not improve the runner-side exposure compared with D3.
- **Bad, because** ADR-0015 deliberately excludes this credential from the first
  VSO migration; forcing it now would be premature churn.

## Confirmation

This decision is confirmed when:

1. The GitHub runner group `nwarila-repo-sync-ci` exists and is scoped only to
   `nwarila-platform/talos-cluster`.
2. `arc-runners-repo-sync` exists with restricted Pod Security labels,
   default-deny network policy, DNS egress, GitHub-only runner egress, and the
   dedicated runner ServiceAccount.
3. The Kyverno namespace guard blocks exec/attach, direct Secret access, and
   tenant-side ServiceAccount or RBAC mutation without blocking the ARC
   controller from creating runner pods.
4. The repo-sync App PEM is SOPS-encrypted in Git, decrypted by Flux, and mounted
   read-only into `nwarila-repo-sync-arc-ci` runner pods.
5. A smoke workflow proves `actions/create-github-app-token@v3` can mint a
   `nwarila-repo-sync[bot]` token from the mounted file without printing the key.
6. `sync-deploy-repos` runs on the dedicated runner, opens or updates the
   generated PR with the App token, and that PR triggers the normal required
   checks.
7. No GitHub Actions secret contains the repo-sync App private key.

## Consequences

### Positive

- The generated deploy-repo wiring PRs can be authored by a principal that
  triggers normal pull request checks.
- The long-lived repo-sync App signing key stays out of GitHub Actions secrets.
- The pattern becomes a reusable "deliver a secret to an on-cluster CI job"
  capability for future platform workflows.
- The design keeps ordinary app secret delivery separate from platform CI
  control-plane credentials, preserving ADR-0015's boundary.
- The namespace and ServiceAccount created for D3 are the unchanged migration
  target for future Vault-backed D1 or D2 delivery.

### Negative

- The dedicated runner is a new credential-bearing trust boundary and must be
  maintained as such.
- Implementing this decision requires a second namespace copy of the
  `nwarila-runner-registrar` Secret so ARC can register the new scale set from
  `arc-runners-repo-sync`; registrar rotation will touch both the existing
  `arc-runners` copy and the repo-sync namespace copy.
- SOPS remains a static secret delivery mechanism until the future Vault-backed
  design replaces it.
- The owner must provision and maintain the GitHub runner group out of band until
  org runner-group management is added to the Terraform framework.

### Neutral

- This is a platform capability and trust-boundary change in `talos-cluster`,
  not an ordinary application onboarding change.
- The first implementation remains intentionally staged: ADR, inert namespace
  and network policy, ServiceAccount, Kyverno guard, SOPS Secret, scale set,
  smoke test, workflow cutover, and cleanup are separate reviewable steps.
- Private deploy-repository discovery remains a separate future problem; this
  ADR only changes the PR authoring credential path.

## Assumptions

1. The `nwarila-repo-sync` GitHub App remains the intended principal for
   generated deploy-repo wiring pull requests.
2. The repo-sync workflow remains schedule and `workflow_dispatch` only before
   it receives any mounted App key.
3. The ARC chart continues to support template volume and volumeMount pass
   through for the dedicated runner scale set.
4. The `nwarila-runner-registrar` app can register the additional scale set once
   the owner-created runner group exists.
5. Vault remains internal-only until a separate ADR changes its exposure model.

## Supersedes

None.

## Superseded by

None (current).

## Implementing PRs

- This ADR is capability step 0 and records the decision only.
- Follow-on steps add the inert namespace and network policy, dedicated runner
  ServiceAccount, Kyverno guard, SOPS-encrypted repo-sync Secret, dedicated ARC
  scale set, smoke workflow, `sync-deploy-repos` cutover, and cleanup.

## Related ADRs

- [ADR-0011](0011-auto-discover-deploy-repositories.md) - defines the
  deploy-repo sync workflow and the `deploy-*` trust-root split.
- [ADR-0015](0015-use-vault-secrets-operator-for-workload-secrets.md) - accepts
  VSO for ordinary workload secrets while excluding platform CI control-plane
  credentials from the first migration.
- [ADR-0012](0012-vault-kms-auto-unseal-credential-delivery.md) - records the
  SOPS/Flux delivery model for protected bootstrap credential material.
- [Org ADR-0003](../org/0003-use-deny-all-gitignore-strategy.md) - requires
  explicit allowlisting for new tracked files.
- [Imported Vault ADR-0005](vault/0005-internal-only-before-gateway-exposure.md)
  - keeps Vault internal-only before any Gateway exposure.

## Compliance Notes

| Framework | Control / Practice ID | Evidence Contribution |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5 | AC-6, IA-5 | The repo-sync App key is isolated to a dedicated runner boundary and used to mint short-lived installation tokens. |
| NIST SP 800-53 Rev. 5 | SC-28 | The long-lived signing key remains SOPS-encrypted at rest in Git and is not stored as a GitHub Actions secret. |
| NIST SP 800-190 | 4.1, 4.4 | CI credential delivery uses a hardened on-cluster runner and Kubernetes Secret mount rather than embedding credentials in images or workflow logs. |
| SSDF | PO.5, PS.3 | Records a reviewable credential-delivery architecture and the rejected alternatives before implementing the control-plane change. |
