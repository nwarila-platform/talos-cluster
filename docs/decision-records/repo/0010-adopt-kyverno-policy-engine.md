# ADR-0010: Adopt Kyverno as the Cluster Policy Engine

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-05-27                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | Kyverno upstream documentation          |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Install Kyverno as the cluster's Kubernetes policy engine using the official
Helm chart through Flux. Kyverno is the policy substrate for the Step 8
supply-chain work: image signature verification, SBOM/attestation checks, and
future tenant guardrails that PodSecurity admission cannot express.

This ADR intentionally lands the engine before landing image verification
policies. Kyverno CRDs and webhooks must be healthy first; audit/enforce image
policies are follow-up PRs.

Current image verification posture is intentionally scoped: nwarila-platform
images are enforced, while Flux, Cilium, and Kyverno remain in Audit. The split
reflects the actual image references, signature formats, and verification paths
Kyverno can consume safely today.

## Context and Problem Statement

ADR-0009 records image signature verification as an accepted compliance gap
against STIG V-242414. The cluster has PodSecurity admission, Flux, SOPS, daily
scanning, and host firewalling, but it does not yet have an admission policy
layer capable of verifying container image signatures or attestations.

The Step 8 goal is broader than installing a controller. It ultimately needs:

- an admission policy engine;
- image signature verification;
- SBOM or provenance attestation validation;
- an operational path from audit to enforce without breaking existing system
  workloads.

Trying to land all of that in one PR is too risky. Image verification policies
can fail closed, cause registry lookups during admission, and need exact
attestor rules per image family. The first defensible slice is to install the
policy engine, prove it is healthy, and then add audit-mode policies once the
CRDs and reports are available.

## Decision Drivers

1. **Compliance gap.** ADR-0009 explicitly calls out image signature
   verification as not configured.
2. **Operational safety.** Admission webhooks are production-sensitive; their
   availability and namespace exclusions must be understood before enforcement.
3. **GitOps fit.** Policies should be Kubernetes resources reconciled through
   the same Flux tree as the rest of the cluster.
4. **Future tenant controls.** The tenant template needs policy-as-code
   controls beyond PodSecurity and NetworkPolicy over time.
5. **Reviewability.** The controller install and the first verification policy
   should be separate PRs so failures have a single cause.

## Considered Options

1. **Kyverno via HelmRelease.**
2. **Sigstore policy-controller.**
3. **OPA Gatekeeper plus external image verification integration.**
4. **No admission policy engine yet.**

## Decision Outcome

Chosen option: **Option 1, Kyverno via HelmRelease.**

Kyverno is installed as a Flux-managed Helm release in a dedicated `kyverno`
namespace. The chart is pinned to version `3.8.1` (app version `v1.18.1` at
adoption), with controller replicas configured for high availability:

- admission controller: 3 replicas;
- background controller: 2 replicas;
- cleanup controller: 2 replicas;
- reports controller: 2 replicas.

The HelmRelease is configured to install and upgrade Kyverno CRDs through Flux:

- `install.crds: Create`
- `upgrade.crds: CreateReplace`

The Flux shape is staged: the parent cluster Kustomization creates the
`kyverno` Namespace and a child Flux Kustomization, and the child Kustomization
then applies the namespace-scoped HelmRepository and HelmRelease. This avoids
first-reconcile dry-run failures where namespace-scoped resources are validated
before their Namespace exists.

The `kyverno` namespace enforces the restricted Pod Security profile. Upstream
documents Kyverno pods as conforming to restricted PSS, including non-root,
non-privileged containers, dropped capabilities, read-only root filesystems,
and probes.

The first implementation PR does **not** add image verification policies.
Follow-up PRs will add audit-mode policies first, inspect PolicyReports, then
move specific image families to enforce only after the current cluster images
are proven signed and exceptions are documented.

## Image Verification Follow-up Status

The Step 8 image-verification follow-ups proved that one global Enforce setting
is not currently correct for this cluster. The policy now uses per-rule
`failureAction` values:

- nwarila-platform (`ghcr.io/nwarila-platform/*`) is `Enforce`.
- Flux (`ghcr.io/fluxcd/*`), Cilium (`quay.io/cilium/*`), and Kyverno
  (`ghcr.io/kyverno/*`) remain `Audit`.
- All four `verifyImages` entries use `mutateDigest: false`.
- The top-level `validationFailureAction` stays `Audit`; per-rule
  `failureAction: Enforce` on nwarila-platform is the scoped override.

Root cause: Kyverno's `verifyImages` signature verifier consumes the legacy
co-located `sha256-<digest>.sig` signature layout. nwarila-platform images have
a verification path that works with that verifier and were proven safe in Audit
before promotion. Flux images also have a usable signature path, but the live
Flux controller Pods use tag-only refs and `mutateDigest: false`, so Enforce
denied them with `missing digest`. Enabling tag-to-digest resolution requires
`mutateDigest: true`, which Kyverno only permits with Enforce and which carries
a GitOps self-heal deadlock risk for the reconciler itself; re-evaluate that
path deliberately before enforcing Flux again. Cilium publishes OCI referrer
signatures in `quay.io`, and Kyverno publishes signatures through
`ghcr.io/kyverno/signatures` as digest-keyed Sigstore bundle tags. Those
referrer/bundle signature formats are not consumable by Kyverno `verifyImages`
as signatures.

Egress was not the cause. The Step 47 investigation proved the Kyverno webhook
could reach the Sigstore services it needed; the remaining Cilium/Kyverno
behavior is a signature-format/tooling mismatch, not a network-policy failure.

The newer Kubernetes `ImageValidatingPolicy` path did not provide a clean
replacement. Step 49 found that Kyverno's `SigstoreBundle` support in
ImageValidatingPolicy is for attestations, not image signatures. Step 50 then
tested the attestation route: Cilium publishes SPDX SBOM attestations with
predicate type `https://spdx.dev/Document` and cosign-sign attestations, but no
SLSA provenance; Kyverno publishes SLSA v0.2 provenance signed by the
`slsa-framework/slsa-github-generator` identity. In this deployment, the
in-cluster ImageValidatingPolicy/SigstoreBundle path emitted no results, even
for a sanity policy that should always fail, so it is not a functional
enforcement path yet.

Future options to revisit full coverage:

1. Debug the ImageValidatingPolicy/ValidatingAdmissionPolicy path until a
   trivial policy emits results, then use it for Kyverno SLSA v0.2 provenance
   and Cilium SBOM attestation checks.
2. Re-sign or mirror Cilium and Kyverno images into an internal registry using
   legacy co-located `.sig` signatures Kyverno `verifyImages` can consume.
3. Move Cilium and Kyverno signatures to Enforce if a future Kyverno release
   adds signature verification for referrer/bundle formats.

## Pros and Cons of the Options

### Option 1: Kyverno via HelmRelease (chosen)

- **Good, because** Kyverno supports image verification with Cosign, digest
  mutation/verification, attestations, and policy reports.
- **Good, because** policies are plain Kubernetes resources and fit the Flux
  reconciliation model.
- **Good, because** the same engine can later cover tenant label, registry,
  resource, and namespace guardrails.
- **Bad, because** Kyverno is a broad controller with meaningful RBAC and
  admission-webhook blast radius.
- **Bad, because** image verification policy design still requires careful
  per-image attestor decisions.

### Option 2: Sigstore policy-controller

- **Good, because** it is purpose-built for Sigstore verification.
- **Bad, because** it is narrower than the tenant and compliance policy surface
  this cluster is building toward.
- **Bad, because** adopting it now could still leave the cluster needing a
  second policy engine for non-image controls.

### Option 3: OPA Gatekeeper plus image verification integration

- **Good, because** Gatekeeper is mature for admission policy and audit.
- **Bad, because** image signature and attestation verification are not as
  direct a fit as Kyverno's native image verification rules.
- **Bad, because** Rego adds a policy language where this repo currently
  prefers YAML-native Kubernetes resources.

### Option 4: No admission policy engine yet

- **Good, because** it avoids webhook risk.
- **Bad, because** it leaves ADR-0009's image-signature verification gap
  completely unaddressed.

## Confirmation

This decision is confirmed when:

1. Flux reconciles the Kyverno HelmRelease successfully.
2. Kyverno controller pods are Ready in the `kyverno` namespace.
3. Kyverno webhook configurations exist.
4. The cluster remains healthy after installation (`kubectl get nodes`, Flux
   Ready=True).
5. A follow-up PR adds audit-mode image verification policy and records the
   initial PolicyReport findings.

## Consequences

### Positive

- The cluster gains the policy engine needed for image signing, SBOM, and
  tenant guardrail work.
- Policy decisions become reviewable, GitOps-managed Kubernetes resources.
- ADR-0009's supply-chain gap now has a concrete implementation path.

### Negative

- Kyverno introduces admission webhooks; misconfiguration can affect API
  writes.
- The cluster now carries another HA control-plane-adjacent component.
- Image verification is not complete until follow-up policies land.

### Neutral

- Cilium and Talos host firewall remain the network/control-plane security
  mechanisms. Kyverno is an admission/policy layer, not a network firewall.

## Assumptions

1. Kyverno chart `3.8.1` remains compatible with Kubernetes `v1.36.0`.
2. Flux helm-controller can install and update the Kyverno CRDs safely using
   the configured CRD lifecycle settings.
3. Existing system workloads should not be subject to image verification
   enforcement until their signing posture is inventoried.

## Supersedes

None.

## Superseded by

None (current).

## Implementing PRs

- Step 8a: Install Kyverno policy engine via Flux (PR #59, hotfix PR #60).
- Step 8b: Add audit-mode keyless cosign verification ClusterPolicy covering
  Flux (`ghcr.io/fluxcd/*`), Cilium (`quay.io/cilium/*`), Kyverno
  (`reg.kyverno.io/kyverno/*`), and public nwarila-platform GHCR images
  (`ghcr.io/nwarila-platform/*`). Audit-only, no admission impact. Wired
  through a sibling Flux Kustomization `kyverno-policies` with
  `dependsOn: [kyverno]` so policies apply only after the engine HelmRelease is
  Ready.
- Step 8b follow-up: Cilium verification is restricted to the observed Cilium
  release workflows. The signed Cilium 1.19.4 components verify through GitHub
  Actions OIDC and Rekor, but `certgen`, `hubble-ui-backend`, `hubble-ui`, and
  `startup-script` are not discoverably signed at their chart-pinned digests,
  so they are narrow audit-mode exceptions until upstream signs them or the
  cluster moves to signed replacements. Kyverno chart images are switched from
  `reg.kyverno.io` to the signed `ghcr.io/kyverno/*` source and verified via the
  upstream signature repository `ghcr.io/kyverno/signatures`; the
  `reg.kyverno.io` v1.18.1 mirrors returned `no signatures found` under cosign.
- Step 8b convergence follow-up: Kyverno `v1.18.1` component signatures
  (`kyverno`, `kyvernopre`, `kyverno-cli`, `background-controller`,
  `cleanup-controller`, `reports-controller`) are in
  `ghcr.io/kyverno/signatures`, not co-located with the component repositories.
  The first convergence attempt put `repository` on the attestor entry, but
  Kyverno expects the signature repository on the `verifyImages` item beside
  `imageReferences` and `attestors`; entry-level placement was ignored and
  Kyverno fell back to co-located lookup. The corrected policy keeps the exact
  Kyverno component references and places
  `repository: ghcr.io/kyverno/signatures` at item level.
- Step 8b Cilium follow-up: Cilium release images are verified by family
  (`quay.io/cilium/*`) instead of by per-digest allowlist so signed operator or
  release digest rotation does not require a policy edit. Trust remains scoped
  to the two observed upstream GitHub Actions subjects:
  `cilium/cilium/.github/workflows/build-images-releases.yaml@refs/tags/v...`
  and
  `cilium/proxy/.github/workflows/build-envoy-images-release-base.yaml@refs/heads/v...`.
  The explicit Cilium exceptions remain the unsigned helper families
  `certgen`, `hubble-ui-backend`, `hubble-ui`, and `startup-script`; revisit
  them on every Cilium chart bump or when upstream starts publishing signatures
  for those images.
- Step 8b mutateDigest follow-up: live admission logs showed signed Cilium and
  Kyverno tag references failing with `no signatures found` because
  `mutateDigest: false` prevented Kyverno from resolving tags to immutable
  digests before cosign lookup. Cosign signatures are digest-keyed, so the
  policy now sets `mutateDigest: true` on the signed image rules. Kyverno
  resolves the admitted Pod image to its digest, verifies the digest-keyed
  signature, and pins the admitted Pod image reference to the digest. The
  policy also disables Pod-controller autogen with
  `pod-policies.kyverno.io/autogen-controllers: none` so Helm/Flux-managed
  Deployments, StatefulSets, and DaemonSets are not rewritten by admission
  mutation; controller-created Pods still match the Pod rule at admission.
- Step 8c controlled-enforce follow-up: Kyverno rejects the otherwise desired
  `mutateDigest: true` plus `failureAction: Audit` combination with
  `mutateDigest must be set to false for 'Audit' failure action`. Tag-to-digest
  resolution is required for the signed Cilium and Kyverno tag references, so
  the valid combination is `failureAction: Enforce` with `mutateDigest: true`.
  The policy therefore promotes all four signed image rules, plus the top-level
  `validationFailureAction`, to `Enforce` while keeping the image scope, Cilium
  helper `skipImageReferences`, and
  `pod-policies.kyverno.io/autogen-controllers: none` unchanged. Post-merge,
  the matched running images are canaried with server-side dry-runs before
  trusting live enforcement; rollback is reverting this promotion to the last
  audit policy if any matched image is blocked unexpectedly.
- Step 8c rollback follow-up: full Enforce was attempted and rolled back after
  the live canary showed the admission engine denying real Kyverno and Cilium
  images with `no signatures found`, even though cosign verifies the images.
  Flux and nwarila-platform images verified cleanly. The policy returns to
  Audit with `mutateDigest: false` so it is accepted by Kyverno and stops
  blocking admission while preserving the corrected attestors, Kyverno
  item-level signature `repository`, Cilium helper skips, and autogen disable.
  Follow-up investigation proved reachability was not the cause; the durable
  cause is that Cilium and Kyverno publish referrer/bundle signatures Kyverno
  `verifyImages` cannot consume as signatures.
- Step 47 investigation: Sigstore egress from the Kyverno admission path was
  proven reachable, so the Cilium/Kyverno failures were not caused by network
  policy or registry egress.
- Step 49 investigation: Kyverno's newer ImageValidatingPolicy
  `SigstoreBundle` support is attestation-oriented and does not add
  referrer/bundle image signature verification for the Cilium/Kyverno case.
- Step 50 attestation spike: Cilium publishes SPDX SBOM and cosign-sign
  attestations but no SLSA provenance; Kyverno publishes SLSA v0.2 provenance
  under the `slsa-framework/slsa-github-generator` identity. The in-cluster
  ImageValidatingPolicy/SigstoreBundle path did not emit results, including for
  an always-false sanity policy, so it is not a viable enforcement mechanism in
  this deployment yet.
- Step 51 scoped-enforce follow-up: the policy promotes only Flux and
  nwarila-platform image verification to `failureAction: Enforce`, leaves
  Cilium and Kyverno at `failureAction: Audit`, keeps all four rules at
  `mutateDigest: false`, and leaves the top-level
  `validationFailureAction: Audit` as the default. This closes the portion that
  is canary-proven enforceable without falsely claiming full upstream coverage.
- Step 53 Flux rollback follow-up: the live scoped-enforce canary found all
  four Flux controller Pods denied under Enforce because the live refs are
  tag-only and `mutateDigest: false` leaves no digest for Kyverno to verify.
  Flux is the GitOps reconciler, so keeping that rule in Enforce risks
  deadlocking self-heal during Pod recreation. The policy pulls Flux back to
  `Audit` while keeping nwarila-platform in `Enforce`; resulting state is
  nwarila-platform `Enforce`, Flux/Cilium/Kyverno `Audit`, and all four rules
  `mutateDigest: false`.

## Compliance Notes

| Framework             | Control / Practice ID | Evidence Contribution |
| --------------------- | --------------------- | --------------------- |
| DISA Kubernetes STIG  | V-242414              | Provides the admission policy engine required for image signature verification follow-up. |
| CIS Kubernetes        | 5.7.x                 | Adds policy-as-code capability for image provenance and workload guardrails. |
| NIST SP 800-190       | 4.1, 4.5              | Precondition for runtime admission controls over image provenance and integrity. |
| NIST SP 800-218 SSDF  | PS.3, RV.1            | Establishes the control plane for verifying artifact provenance and reporting policy violations. |
