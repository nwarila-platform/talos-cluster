# ADR-0010: Adopt Kyverno as the Cluster Policy Engine

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-05-27                              |
| Authors        | Nick Warila (@NWarila), Codex           |
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
  `ghcr.io/kyverno/signatures`, not co-located with the component repositories,
  so the policy pins exact component references and puts the alternate
  repository on the attestor entry. Cilium `1.19.4` release images
  (`cilium`, `cilium-envoy`, `operator-*`, `hubble-relay`,
  `clustermesh-apiserver`) are signed co-located at their chart-pinned digests.
  The explicit Cilium exceptions remain `certgen`, `hubble-ui-backend`,
  `hubble-ui`, and `startup-script`; revisit them on every Cilium chart bump or
  when upstream starts publishing signatures for those images.
- Step 8c (follow-up): Promote verified image families from audit to enforce
  once PolicyReports show consistent `pass` across all matched images and any
  unsignable exceptions are documented.

## Compliance Notes

| Framework             | Control / Practice ID | Evidence Contribution |
| --------------------- | --------------------- | --------------------- |
| DISA Kubernetes STIG  | V-242414              | Provides the admission policy engine required for image signature verification follow-up. |
| CIS Kubernetes        | 5.7.x                 | Adds policy-as-code capability for image provenance and workload guardrails. |
| NIST SP 800-190       | 4.1, 4.5              | Precondition for runtime admission controls over image provenance and integrity. |
| NIST SP 800-218 SSDF  | PS.3, RV.1            | Establishes the control plane for verifying artifact provenance and reporting policy violations. |
