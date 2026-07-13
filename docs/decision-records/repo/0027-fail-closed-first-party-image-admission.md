# ADR-0027: Fail Closed for First-Party Image Admission

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-13                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | High                                    |
| Review-by      | N/A (Accepted)                          |

## TL;DR

First-party image verification is split out of the Audit-only Kyverno
`verify-image-signatures` ClusterPolicy into
`verify-image-signatures-enforced`: a dedicated first-party policy with
`webhookConfiguration.failurePolicy: Fail` and API-server CEL
`matchConditions` that match pods carrying `ghcr.io/nwarila/*`,
`ghcr.io/nwarila-platform/*`, or `ghcr.io/the-hero-wars-guys/*` images. This
closes the live fail-open hole where an unverifiable first-party image was
admitted with only a warning despite rule-level `failureAction: Enforce`.

## Context and Problem Statement

The original `verify-image-signatures` policy mixed Audit-only third-party
rules with Enforce first-party rules while setting
`spec.webhookConfiguration.failurePolicy: Ignore`. A live server-side dry-run
on 2026-07-13 proved the result: when Kyverno could not verify an image, the
API server admitted the pod with only a warning. Rule-level
`failureAction: Enforce` blocked verifiable signature violations, but it did not
make webhook-call, registry, credential, or Rekor failures fail closed.

The owner decision on 2026-07-13 is binding for this repository: first-party
image verification fails closed wherever the Kyverno webhook applies. There is
no carve-out for `deploy-vault`; Vault is protected by the same rule as the
tenant workload.

### Why not per-policy namespaceSelector

Kyverno v1.18 ClusterPolicy does not expose a per-policy namespace selector.
`spec.webhookConfiguration` exposes `failurePolicy`, `matchConditions`, and
`timeoutSeconds`. Any design that depends on a local
`webhookConfiguration.namespaceSelector` is not implementable in this schema.

### Why not a bare Fail flip

The existing image verification rules are registered as pod mutating admission
webhooks. A policy with `failurePolicy: Fail` and empty `matchConditions` joins
Kyverno's shared cluster-wide fail webhook for mutate or `verifyImages` rules.
During a Kyverno outage, that would block pod creation in every namespace not
excluded by Kyverno's global chart-default namespace selector, even for images
that are not first-party. It would also make Audit-only third-party families
part of a fail-closed admission dependency without changing their Audit rule
outcome.

With non-empty `matchConditions`, Kyverno emits a dedicated fine-grained webhook
for the policy and copies the policy's conditions into that webhook. The API
server then calls the fail-closed first-party webhook only for pods whose raw
Pod spec carries a first-party image prefix.

## Decision Drivers

1. Close the live fail-open path for unverifiable first-party images.
2. Keep the admission availability blast radius bounded to pods that actually
   carry first-party image refs.
3. Preserve Audit-only posture for third-party families until
   [TD-0001](../../tech-debt.md) and the Flux deferral are deliberately closed.
4. Keep recovery possible by respecting Kyverno's inherited exclusion of
   `kube-system` and `kyverno`.
5. Make the API-server CEL scope mechanically coupled to the first-party
   `imageReferences` set so future changes cannot silently shrink the webhook.

## Considered Options

1. **Split Audit and Enforced policies, with Fail plus matchConditions for
   first-party images** (chosen).
2. **Flip the original mixed policy from Ignore to Fail**.
3. **Use a per-policy namespaceSelector**.
4. **Move immediately to Kyverno ImageValidatingPolicy**.

## Decision Outcome

Chosen option: **Option 1.**

- `verify-image-signatures` remains Audit-only with `failurePolicy: Ignore` for
  Flux, Cilium, Kyverno, and Vault Secrets Operator images.
- `verify-image-signatures-enforced` carries the first-party rules for
  `ghcr.io/nwarila/*`, `ghcr.io/nwarila-platform/*`, and
  `ghcr.io/the-hero-wars-guys/*`, with rule-level `failureAction: Enforce`,
  `required: true`, and `mutateDigest: false`.
- The enforced policy sets `failurePolicy: Fail` and one Pod-shaped CEL
  `matchConditions` expression covering `containers`, `initContainers`, and
  `ephemeralContainers`.
- Both policies keep `pod-policies.kyverno.io/autogen-controllers: none`, so
  the CEL is evaluated against Pod admission objects rather than controller
  shapes.
- Fail closed means every namespace where Kyverno's inherited webhook
  namespace selector applies. That excludes `kube-system` and `kyverno`, which
  is required for recoverability because Kyverno cannot gate its own recovery
  path.

The guard `scripts/check-image-signature-enforcement.py` now locks this shape:
Enforce `verifyImages` policies must set `failurePolicy: Fail`, must use the
exact canonical first-party CEL generated from the first-party prefix list, and
must only Enforce first-party image references. It also rejects fail-closed
mutate or `verifyImages` policies with empty `matchConditions`, first-party
images declared in `kube-system` or `kyverno`, and Kyverno Helm values that set
`config.defaultRegistry` to anything other than `docker.io`.

### Attack closed

An attacker who can revoke or expire the `ghcr-pull` credential, partition or
DoS Kyverno, GHCR, or Rekor, or reference an image whose signature cannot be
fetched can no longer get an unverifiable first-party image admitted. Before
this decision, those cases admitted with only a warning.

## Pros and Cons of the Options

### Option 1: split policy with Fail plus matchConditions (chosen)

- **Good, because** first-party verification now fails closed on verifier,
  registry, credential, or Rekor failure.
- **Good, because** unrelated third-party and non-first-party pod creation is
  not placed behind the first-party fail-closed webhook.
- **Good, because** the CEL superset invariant is generated and checked from
  the same first-party prefix source as the Kyverno image glob invariant.
- **Bad, because** the design couples first-party pod restart to Kyverno,
  GHCR, and public sigstore availability until the owned mirror-and-re-sign
  path in TD-0001 lands.
- **Bad, because** it relies on a duplicated glob-vs-CEL model: Kyverno matches
  normalized image strings, while the API-server CEL sees raw Pod image strings.

### Option 2: bare Fail on the original mixed policy

- **Bad, because** it would put every pod create in every non-excluded
  namespace behind the shared fail webhook during a Kyverno outage.
- **Bad, because** it would make Audit-only third-party families fail closed on
  webhook-call failure without producing rule-level enforcement.
- **Good, because** it is mechanically simple. That simplicity hides the
  cluster-wide admission availability risk.

### Option 3: per-policy namespaceSelector

- **Bad, because** Kyverno v1.18 ClusterPolicy does not provide that field.
- **Bad, because** namespace carve-outs are the wrong boundary for this
  decision: the owner's chosen boundary is first-party image refs, not a list of
  namespaces.

### Option 4: ImageValidatingPolicy

- **Good, because** `imagevalidatingpolicies.policies.kyverno.io` colocates
  match constraints, match conditions, failure policy, match image references,
  and CEL image extractors in one object, which would collapse the glob-vs-CEL
  divergence class.
- **Bad, because** on this cluster it is a beta CRD, storage version `v1beta1`,
  with zero instances today. Moving the crown-jewel image gate onto that path
  in the same change that closes a live fail-open hole is a worse risk trade.

## Confirmation

1. `kubectl kustomize clusters/talos-cluster/` renders both ClusterPolicies:
   `verify-image-signatures` with `failurePolicy: Ignore` and the four
   third-party rules, and `verify-image-signatures-enforced` with
   `failurePolicy: Fail`, non-empty `matchConditions`, and the three
   first-party rules.
2. `scripts/check-image-signature-enforcement.py` passes on the repository and
   its selftest proves the new invariants fail when injected defects are
   present, including the original fail-open shape.
3. `scripts/check-doc-links.py` passes with this ADR linked from the ADR index.
4. Live post-merge verification must assert the generated fine-grained webhook
   exists, carries the matchConditions, has no reconcile errors in
   `kyverno-admission-controller` logs, denies an unverifiable first-party image
   in server-side dry-run, and still admits the real Vault and tenant images.

## Consequences

### Positive

- Unverifiable first-party images now fail closed instead of admitting with a
  warning.
- The fail-closed admission dependency is bounded to first-party Pod specs by
  API-server CEL.
- The guard now tests the failurePolicy and matchConditions class that allowed
  the original bug to survive.

### Negative

- While Kyverno (three replicas), GHCR, or sigstore/Rekor is unreachable,
  first-party pods such as Vault and tenant workloads cannot be created or
  restarted. Running pods are unaffected because admission is create-time, and
  Kyverno's image-verify cache (`useCache`, default-on, 60 minute TTL) absorbs a
  restart of an already verified digest.
- Break-glass is to delete the generated fine-grained
  `MutatingWebhookConfiguration` entry. That is emergency-only, not a routine
  operational path.
- During the reconcile that moves rules between the two policies, there is a
  brief window that fails open rather than closed. This is acceptable for the
  single-PR migration.
- `kube-system` and `kyverno` are excluded by Kyverno's inherited chart-default
  namespace selector. This is required for recoverability and matches the
  existing fail-closed validation policies. No first-party image runs there
  today; guard I5 keeps GitOps-delivered first-party images out of those
  namespaces.
- Kyverno glob matching is case- and port-sensitive on the normalized image
  string. Exotic raw forms such as `GHCR.IO/nwarila/evil:v1` or
  `ghcr.io:443/the-hero-wars-guys/evil:v1` match neither the glob nor the CEL.
  That is not a new hole from this change, but it is not closed here.
- The chart value `--forceFailurePolicyIgnore` would force policies back to
  Ignore and silently disable this control. Live state was verified as false;
  this ADR records the dependency.
- The superset property depends on Kyverno `config.defaultRegistry` staying
  `docker.io`. The guard pins that coupling because changing the default
  registry to `ghcr.io` could make Kyverno normalize a raw image into a
  first-party GHCR string that the API-server CEL never saw.

### Neutral

- The intended successor is Kyverno ImageValidatingPolicy once it is proven on
  this cluster. It can express the admission match, image reference match, and
  image extraction contract in one object and should be revisited after the live
  fail-open hole is closed.
- Third-party Flux, Cilium, Kyverno, and Vault Secrets Operator image families
  remain Audit-only in this change. Promoting them is deliberately out of scope.

## Assumptions

1. Kubernetes continues to evaluate admission `matchConditions` against the raw
   Pod admission object before calling the webhook.
2. Kyverno v1.18 continues to create a dedicated fine-grained webhook for
   policies with non-empty `matchConditions`.
3. Kyverno's global chart-default namespace selector continues to exclude
   `kube-system` and `kyverno`.
4. `config.defaultRegistry` remains unset or `docker.io`.

## Supersedes

None.

## Related ADRs

- [ADR-0010](0010-adopt-kyverno-policy-engine.md) - adopts Kyverno and records
  the original image verification posture.
- [ADR-0023](0023-nwarila-signed-image-for-dr-restore-driver.md) - defines the
  first-party signed-image contract for a future restore driver.
- [ADR-0024](0024-two-layer-enforcement-of-restore-validator-boundary.md) -
  records the guard plus runtime-policy pattern this change follows.
- [TD-0001](../../tech-debt.md) - tracks the mirror-and-re-sign path for
  third-party image families that are still Audit-only.

## Compliance Notes

| Framework             | Control / Practice ID                                  | Potential Evidence Contribution |
| --------------------- | ------------------------------------------------------ | ------------------------------- |
| NIST SP 800-53 Rev. 5 | SI-7 (Software, Firmware, and Information Integrity)   | First-party workload images require valid keyless signatures and fail closed when verification is unavailable. |
| NIST SP 800-53 Rev. 5 | CM-7 (Least Functionality)                             | The fail-closed webhook is scoped to pods carrying first-party image prefixes rather than all pod admission. |
| NIST SP 800-53 Rev. 5 | SC-16 (Transmission of Security and Privacy Attributes) | Signature identity attributes from GitHub OIDC and Rekor are enforced for first-party image admission. |
