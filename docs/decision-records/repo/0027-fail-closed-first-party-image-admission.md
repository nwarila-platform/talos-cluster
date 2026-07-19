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

> **⚠️ READ THE 2026-07-18/19 AMENDMENTS AT THE END OF THIS FILE FIRST.** The
> MECHANISM described below has moved twice since this ADR was accepted. The
> DECISION (first-party images fail closed at admission) still holds, but
> enforcement no longer runs on the `verify-image-signatures-enforced`
> ClusterPolicy described here — it runs on a single merged
> `ImageValidatingPolicy/verify-first-party`, which is TRANSIENTLY at
> `[Audit]`/`Ignore` for the merge-cutover canary. The TL;DR and Consequences
> sections below are written in the present tense and describe the ORIGINAL
> mechanism; treat them as historical.

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
4. Keep recovery possible by respecting Kyverno's inherited exemption surface,
   while documenting the namespaces where Kyverno does not evaluate these rules.
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
- The enforced policy sets `failurePolicy: Fail`, `timeoutSeconds: 30`, and one
  Pod-shaped CEL `matchConditions` expression covering `containers`,
  `initContainers`, and `ephemeralContainers`.
- Both policies keep `pod-policies.kyverno.io/autogen-controllers: none`, so
  the CEL is evaluated against Pod admission objects rather than controller
  shapes.
- Fail closed means every namespace where Kyverno admission is not exempted. On
  this cluster, Kyverno's effective exemption surface is `kube-system` and
  `kyverno` from the inherited webhook namespace selector, plus `kube-public`
  and `kube-node-lease` from Kyverno `resourceFilters`. Resources in those four
  namespaces are admitted without these `verifyImages` rules being evaluated.

The guard `scripts/check-image-signature-enforcement.py` now locks this shape:
Enforce `verifyImages` policies must set `failurePolicy: Fail`, must use the
exact canonical first-party CEL generated from the first-party prefix list, and
must only Enforce first-party image references. It also rejects fail-closed
mutate or `verifyImages` policies with empty `matchConditions`, first-party
images declared in Kyverno-exempt namespaces, Kyverno policy YAMLs omitted from
the local policy `kustomization.yaml`, and Kyverno Helm values that set
`config.defaultRegistry` to anything other than `docker.io`.

### Guard coverage

The guard also pins the Kyverno rule body for the first-party Enforce rules.
For each canonical first-party org glob, it requires the exact keyless
`issuer`, `subjectRegExp`, and `rekor.url` tuple recorded in the guard, plus
`required: true`. Weakening any trust anchor now requires an explicit guard edit
instead of a one-line policy-only change.

The guard rejects rule-level scope shrink on Enforce rules: `exclude:`,
`preconditions:`, and any `match` shape other than the unnarrowed Pod form
`match.any[].resources.kinds == ["Pod"]` fail CI. It also pins both
image-signature policies to `background: true` and
`pod-policies.kyverno.io/autogen-controllers: none` so background PolicyReport
detection stays enabled and Kyverno does not generate controller-shaped rules
from Pod-shaped CEL.

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

1. `kubectl kustomize clusters/talos-cluster/apps/kyverno/policies` renders both
   image-signature ClusterPolicies:
   `verify-image-signatures` with `failurePolicy: Ignore` and the four
   third-party rules, and `verify-image-signatures-enforced` with
   `failurePolicy: Fail`, `timeoutSeconds: 30`, non-empty `matchConditions`, and
   the three first-party rules.
2. `kubectl kustomize clusters/talos-cluster/` remains a root regression check
   for the Flux wrapper graph, but it does not render the child
   `kyverno-policies` Kustomization contents and must not be used as evidence
   that the policy directory itself renders.
3. `scripts/check-image-signature-enforcement.py` passes on the repository and
   its selftest proves the new invariants fail when injected defects are
   present, including the original fail-open shape.
4. `scripts/check-doc-links.py` passes with this ADR linked from the ADR index.
5. Live post-merge verification must assert the generated fine-grained webhook
   exists, carries the matchConditions, has no reconcile errors in
   `kyverno-admission-controller` logs, denies an unverifiable first-party image
   in server-side dry-run, and still admits the real Vault and tenant images.

## Consequences

### Positive

- Unverifiable first-party images now fail closed instead of admitting with a
  warning.
- The fail-closed admission dependency is bounded to first-party Pod specs by
  API-server CEL.
- The guard now tests the failurePolicy, matchConditions, and rule-body classes
  that allowed the original bug and later structural bypasses to survive.

### Negative

- While Kyverno (three replicas), GHCR, or sigstore/Rekor is unreachable,
  first-party pods such as Vault and tenant workloads cannot be created or
  restarted. Running pods are unaffected because admission is create-time. The
  enforced webhook uses the Kubernetes maximum `timeoutSeconds: 30` to reduce
  cold-cache false denials, but slow GHCR or Rekor verification is still enough
  to deny an otherwise valid first-party pod once the API server timeout expires.
- Kyverno's image-verify cache (`useCache`, default-on, 60 minute TTL) is
  per-replica and in-memory across the three admission replicas. It absorbs a
  restart of an already verified digest only when the serving replica already
  has that digest cached.
- Break-glass while Kyverno is healthy is to suspend the Flux Kustomization
  `kyverno-policies` in `flux-system`, then delete
  `ImageValidatingPolicy/verify-first-party` for a first-party IVP incident.
  SUSPEND BEFORE DELETING: that Kustomization reconciles every 10m with
  `prune: true`, so deleting the policy first just lets Flux re-apply it and the
  incident resumes. The `flux` CLI is not installed on every operator
  workstation; the kubectl equivalent is
  `kubectl patch kustomizations.kustomize.toolkit.fluxcd.io kyverno-policies -n
  flux-system --type=merge -p '{"spec":{"suspend":true}}'` (use the fully
  qualified kind — `kustomization` alone is ambiguous on this cluster).
  The full procedure with commands is in
  `docs/runbooks/bootstrap-out-of-band.md`; keep the two in sync.
  If the incident is in the legacy `verifyImages` path, delete
  `ClusterPolicy/verify-image-signatures-enforced` instead. Flux would otherwise
  re-apply the policy. Deleting only the generated fine-grained
  `MutatingWebhookConfiguration` does not work while Kyverno's webhook
  controller runs with `autoUpdateWebhooks=true`, because Kyverno recreates it.
  The chart-level kill switch `--forceFailurePolicyIgnore=true` can force
  policies back to fail-open behavior, but it is a broad emergency rollback
  switch rather than routine operations. ⚠️ That flag was documented for
  `ClusterPolicy`; whether it reaches `policies.kyverno.io/v1beta1`
  ImageValidatingPolicies is UNVERIFIED. Do not rely on it as the kill switch
  for the merged IVP until it has been proven — suspend-and-delete above is the
  path that is known to work.
- During the reconcile that moves rules between the two policies, there is a
  brief window that fails open rather than closed. This is acceptable for the
  single-PR migration.
- `kube-system`, `kyverno`, `kube-public`, and `kube-node-lease` are outside the
  effective Kyverno enforcement surface for this control. The first two are
  excluded by the inherited chart-default webhook namespace selector; the latter
  two are skipped by Kyverno `resourceFilters`. No first-party image runs there
  today; guard I5 keeps GitOps-delivered first-party images out of those
  namespaces, including kustomize `namespace:` overlays.
- Kyverno's default `excludeGroups: system:nodes` means kubelet-created static or
  mirror pods bypass Kyverno admission entirely. This is a third bypass axis,
  separate from the webhook namespace selector and `resourceFilters`, and is not
  closed by this ADR.
- Kyverno glob matching is case- and port-sensitive on the normalized image
  string. Exotic raw forms such as `GHCR.IO/nwarila/evil:v1` or
  `ghcr.io:443/the-hero-wars-guys/evil:v1` match neither the glob nor the CEL.
  That is not a new hole from this change, but it is not closed here.
- `ghcr.io/nwarila-platform/*` and `ghcr.io/nwarila/*` image packages must stay
  anonymously readable or the corresponding rules must gain
  `imageRegistryCredentials` before private packages are deployed. New GHCR
  packages default to private; without credentials Kyverno cannot fetch the
  signature and `failurePolicy: Fail` denies the pod. The `ghcr-pull` Secret in
  the `kyverno` namespace is now an availability dependency for
  `ghcr.io/the-hero-wars-guys/*` tenant pod creation because those packages are
  private.
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
3. Kyverno's effective exemption surface remains `kube-system`, `kyverno`,
   `kube-public`, and `kube-node-lease`.
4. `config.defaultRegistry` remains unset or `docker.io`.
5. Kyverno continues to exclude `system:nodes`; kubelet-created static and
   mirror pods remain outside this control.

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

## Amendment — 2026-07-18 (mechanism changed; decision stands)

**Status remains Accepted: the decision — fail closed for first-party image admission — still holds.**
What changed is the MECHANISM this ADR describes.

The `verify-image-signatures-enforced` ClusterPolicy this ADR decides on (documented in the sections
ABOVE) is **no longer the enforcing mechanism**.

⚠️ **Two DISTINCT incidents, not one** (an earlier draft of this amendment wrongly merged them):
- **2026-07-14** — keyless verification against `rekor.url` made an ONLINE Rekor query on the admission hot
  path; a Rekor outage window fail-closed first-party pod creation. Fixed by the offline pins (#333).
- **#335 (2026-07-17)** — Kyverno v1.18.2 miscategorises a legacy `verifyImages` policy carrying
  `spec.webhookConfiguration.matchConditions` (the brick-safety scoping this ADR chose), so its mutating
  image-verification never runs and every signed first-party pod is denied at Enforce.

The second defect is structural and unfixed upstream, so first-party enforcement moved to one merged
`ImageValidatingPolicy`, `verify-first-party`. The merge was forced by two Kyverno v1.18.2 IVP defects:
annotation clobber between per-org outcome entries and autogen slot collision under the shared
`defaults`/`cronjobs` slots. The merged IVP is currently live as a non-blocking merge-cutover canary at
`validationActions: [Audit]` + `failurePolicy: Ignore`; the steady-state target remains
`validationActions: [Deny]` + `failurePolicy: Fail` in the follow-up PR. The ClusterPolicy stays
non-blocking (Audit) and is retired by PR-C2.

**Known defect in the IVP mechanism (do not read this ADR as "solved"):** IVP on Kyverno v1.18.2 uses a
mutate→annotate→validate handoff (the mutating webhook does the cosign work and writes
`kyverno.io/image-verification-outcomes`; the validating webhook evaluates the result read back). A missing
entry yields `"policy not evaluated"` ⇒ RuleFail. At the steady-state [Deny]/Fail posture this denies; during
the current [Audit]/Ignore canary it is non-blocking telemetry. On 2026-07-18 this intermittently
false-denied a genuinely signed image in the hwg tenant. The fail direction is CLOSED once the steady-state
posture is restored, so this ADR's security property still depends on that follow-up; the canary harm is
limited to availability telemetry. Root cause is under diagnosis. As of 2026-07-18 no
Kyverno release carries even the related status-controller fix (PR #15754 is merged to
main only — `git tag --contains 7b31196` returns zero tags, and release-1.18 branched
before it), so an upgrade is not an available remedy today.

See `cp1_offline_verify_decision`, PLAN §10 (2026-07-18 retraction entry), and PR #346.
