# ADR-0005: Use postfinance/kubelet-csr-approver for Kubelet Serving-Cert Rotation

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-05-25                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | High                                    |
| Review-by      | N/A (Accepted)                          |

## TL;DR

This cluster deploys `postfinance/kubelet-csr-approver` (Helm chart, version 1.2.14 at adoption) into `kube-system` to auto-approve CSRs of signer `kubernetes.io/kubelet-serving`. The approver is the precondition for re-enabling `machine.kubelet.extraArgs.rotate-server-certificates: "true"` (which was tested on w1 on 2026-05-25 and reverted because, without an approver, every kubelet serving CSR went Pending and immediately invalidated the node's serving cert). The approver enforces three independent guardrails before signing: (1) the requestor must be `system:node:<X>` and match an allowlist regex `^(cp[1-3]|w[1-3])$`; (2) every SAN IP must fall inside `10.69.112.0/24`; (3) the requestor-vs-CN identity match is enforced. DNS-based SAN verification is bypassed because the cluster's short hostnames (`cp1`–`w3`) are not in DNS.

## Context and Problem Statement

K8s kubelet has two operating modes for its serving certificate (the cert presented on port 10250 to clients like metrics-server, `kubectl logs/exec/port-forward`, and node-exporter):

1. **Self-signed.** Default in K8s 1.x. kubelet signs its own serving cert with an in-memory key; clients that validate the cert (metrics-server, Prometheus kubelet scraper, OpenTelemetry collectors) must be configured with `--kubelet-insecure-tls` or equivalent. At ADR adoption, this was what the cluster ran; `addons/metrics-server/values.yaml` carried the insecure-tls workaround. That file was later removed as vestigial after the Flux HelmRelease moved to chart defaults and no longer set `--kubelet-insecure-tls`.

2. **Cluster-CA-signed via the CSR API.** Enabled by `kubelet --rotate-server-certificates`. On startup and ~80% through expiry, kubelet creates a CSR for signer `kubernetes.io/kubelet-serving` and waits for a `system:masters`-level approver to sign it. Once signed, kubelet uses the cert (validated by the cluster CA, which every in-cluster client trusts). Eliminates the `--insecure-tls` workaround.

The CSR-based mode requires an approver. K8s does NOT ship a built-in kubelet-serving CSR approver (only the kubelet *client*-cert approver runs by default). Without one, CSRs sit Pending and an operator has to `kubectl certificate approve <name>` every CSR. With six nodes rotating annually, that's two CSRs per node × six nodes = 12 manual approvals/year minimum, plus every node-restart CSR.

On 2026-05-25, this repository's prior `cluster/patches/common.yaml` declared `rotate-server-certificates: "true"` without the approver in place; on a test apply to w1, CSR `csr-hj9h9` went Pending immediately and w1 lost its valid serving cert. The setting was reverted (commit `3030d9c`) pending an approver decision recorded in this ADR.

## Decision Drivers

1. **Eliminate the `--kubelet-insecure-tls` exception** formerly carried in `addons/metrics-server/values.yaml` and any future scraper that wants to validate kubelet's serving cert. The metrics-server addon values file was later removed as vestigial after this exception was dropped.
2. **Zero manual operator action** for routine kubelet cert rotation. Manual `kubectl certificate approve` is a known operational pain point that, when missed, silently breaks metrics-server.
3. **Defense in depth on the approval policy**. A bad approver that signs any CSR is worse than no approver at all (it would let a compromised pod with kubelet-style credentials request certs for other nodes). The chosen approver must verify (a) the requestor's identity, (b) the requested SANs are scoped to that requestor.
4. **Minimal new attack surface**. The approver itself must run unprivileged and as few replicas as gives HA.

## Considered Options

1. **Adopt `postfinance/kubelet-csr-approver` (Helm).**
2. **Adopt `alex1989hu/kubelet-serving-cert-approver` (the predecessor/forked controller).**
3. **Hand-roll an approver as a custom controller.**
4. **Stay on self-signed kubelet serving certs + `--kubelet-insecure-tls`.**

## Decision Outcome

Chosen option: **Option 1, postfinance/kubelet-csr-approver Helm chart.**

`addons/kubelet-csr-approver/values.yaml` configures the chart with the three guardrails listed in the TL;DR. The chart is installed into `kube-system` (where Cilium and other system controllers live) via:

```bash
helm repo add postfinance https://postfinance.github.io/kubelet-csr-approver
helm upgrade --install -n kube-system \
  --version 1.2.14 \
  -f addons/kubelet-csr-approver/values.yaml \
  kubelet-csr-approver postfinance/kubelet-csr-approver
```

A follow-up cycle re-adds `machine.kubelet.extraArgs.rotate-server-certificates: "true"` to `cluster/patches/common.yaml` and rolls it out node-by-node. The follow-up cycle MUST verify approver readiness before flipping the kubelet flag — if the approver is unhealthy when kubelet creates its first rotated CSR, the node loses its serving cert.

## Pros and Cons of the Options

### Option 1: postfinance/kubelet-csr-approver (chosen)

- **Good, because** it is the current de-facto standard in the K8s community for this problem (the `alex1989hu` controller has stalled; postfinance is the active fork).
- **Good, because** its allowlist policy is configured via Helm values (`providerRegex`, `providerIpPrefixes`), avoiding hand-rolled approval logic.
- **Good, because** the chart bundles ClusterRole, ClusterRoleBinding, ServiceAccount, and ServiceMonitor — no manual RBAC plumbing.
- **Good, because** the controller runs unprivileged (`runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`, `capabilities: drop: [ALL]`) by chart default.
- **Neutral, because** it adds a small (~50 MiB memory, 10–100m CPU) controller to `kube-system`. Two replicas at <200 MiB total.
- **Bad, because** introduces an external Helm chart whose major-version compatibility with future K8s API changes is not under this repo's control. Renovate will surface upgrades; an ADR-tier change is required only if the upstream changes its approval semantics.

### Option 2: alex1989hu/kubelet-serving-cert-approver

- **Good, because** functionally equivalent to postfinance at adoption time.
- **Bad, because** the repository has had minimal activity since 2023; postfinance forked it specifically to continue maintenance. Choosing the stalled fork would set up a future migration ADR.

### Option 3: Hand-roll a custom controller

- **Good, because** total control over the approval policy.
- **Bad, because** a CSR approver is a piece of cluster-trust-rooted code; getting it wrong (approving a CSR for the wrong node) is a silent privilege-escalation. The two off-the-shelf options have been audited; a hand-rolled one is a new attack surface for marginal benefit.

### Option 4: Stay on `--kubelet-insecure-tls`

- **Good, because** zero operational overhead.
- **Bad, because** kubelet serving certs are self-signed and clients cannot validate the kubelet's identity. Any actor on the network between a scraper and kubelet can MITM the metrics/logs stream without detection.
- **Bad, because** it forecloses any future addition of stricter cluster-internal mTLS posture (e.g., a service mesh that wants cluster-CA-signed certs everywhere).

## Confirmation

Adherence to this ADR is confirmed by the following mechanisms. The wording `MUST`, `SHOULD`, and `MAY` follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) conventions.

1. **Presence check.** `addons/kubelet-csr-approver/values.yaml` MUST exist and configure (a) `providerRegex` to a value that names every legitimate node and rejects everything else, (b) `providerIpPrefixes` containing exactly the management subnet, (c) `bypassDnsResolution: true`, (d) `bypassHostnameCheck: false`, and (e) `ignoreNonSystemNode: true`.
2. **Deploy check.** A `helm list -n kube-system` MUST show `kubelet-csr-approver` with `STATUS: deployed` whenever `rotate-server-certificates: "true"` is set in `cluster/patches/common.yaml`.
3. **Order-of-operations check.** A PR that enables `rotate-server-certificates: "true"` in `cluster/patches/common.yaml` MUST NOT be applied unless the approver is already deployed and healthy. The `cluster/patches/common.yaml` deferral comment is the operator-facing reminder; CI does not enforce this (and probably cannot without contacting the live cluster).
4. **Pin discipline.** The Helm chart version in the install command MUST be a specific version (e.g., `1.2.14`), not `latest` or unbounded. Renovate manages chart bumps via PRs; merging a chart bump is an architectural decision deserving a brief PR description even though it does not require a superseding ADR unless approval semantics change.
5. **Image registry trust.** The `image.repository` field MUST remain `ghcr.io/postfinance/kubelet-csr-approver` (the upstream publication address). A switch to a mirror or internal registry is a superseding ADR.

## Consequences

### Positive

- `rotate-server-certificates: "true"` becomes safe to enable in a follow-up cycle; kubelet serving certs rotate automatically and are signed by the cluster CA.
- The then-existing `addons/metrics-server/values.yaml` could drop `--kubelet-insecure-tls` (separate follow-up cycle). That vestigial file was later removed after the Flux HelmRelease used chart defaults.
- Future addons that scrape kubelet (Prometheus, OpenTelemetry, Sysdig, etc.) can validate kubelet's identity with the cluster CA rather than needing per-addon insecure-TLS exceptions.

### Negative

- A new controller in `kube-system` to monitor. If the approver pod is OOMKilled / image-pull-fails / leader-election-broken at the moment a kubelet creates a CSR, that kubelet loses its serving cert. Mitigated by `replicas: 2` and the chart's standard liveness/readiness probes; severity is bounded (serving cert is independent of node Ready status — the node continues to host pods).
- Renovate will produce a periodic Helm chart bump PR for this controller. Maintenance overhead exists but is small.

### Neutral

- The chart's RBAC binds the existing built-in `system:certificates.k8s.io:kubelet-serving-approver` ClusterRole to its ServiceAccount. No new ClusterRole is created.

## Assumptions

This decision rests on the following assumptions. If any becomes false, this ADR should be revisited:

1. `postfinance/kubelet-csr-approver` remains actively maintained. If it stalls (as `alex1989hu/...` did), a migration ADR is needed.
2. Kubernetes upstream continues to use the CSR API (`certificates.k8s.io/v1`) for kubelet serving cert provisioning, and the `kubernetes.io/kubelet-serving` signer name remains stable.
3. Talos's `KubeletConfig` schema continues to honour `kubelet.extraArgs.rotate-server-certificates`. Talos has historically passed `--rotate-server-certificates` directly to the kubelet binary; a future Talos that abstracts this would prompt a revision.
4. The node-name pattern `^(cp[1-3]|w[1-3])$` matches the live cluster's hostnames per [ADR-0002](0002-use-short-talos-hostnames.md). If the naming convention changes, this ADR's `providerRegex` must change in lockstep.

## Supersedes

None.

## Superseded by

None (current).

## Implementing PRs

The PR that introduces this ADR also introduces `addons/kubelet-csr-approver/values.yaml`, runs the `helm upgrade --install` against the live cluster, and updates `.gitignore` + the README to add the install command alongside Cilium / metrics-server / ingress-nginx.

A follow-up PR will re-add `kubelet.extraArgs.rotate-server-certificates: "true"` to `cluster/patches/common.yaml`, regenerate, and roll the change out node-by-node per the rolling-apply pattern.

## Related ADRs

- [ADR-0002 (repo)](0002-use-short-talos-hostnames.md) — establishes the `cp1`–`w3` naming pattern that this ADR's `providerRegex` locks down.
- [ADR-0003 (repo)](0003-repo-as-cluster-source-of-truth.md) — establishes that the repository is the cluster's declarative source of truth; this addon belongs in `addons/` because it is part of the cluster's steady-state configuration.

## Compliance Notes

This ADR records a kubelet-side TLS hardening decision. Once `rotate-server-certificates` is re-enabled and `--kubelet-insecure-tls` is dropped from metrics-server (separate follow-up), every in-cluster scraper validating kubelet's identity does so against the cluster CA — a measurable improvement in lateral-movement detection posture.

| Framework              | Control / Practice ID                              | Potential Evidence Contribution                                                                                              |
| ---------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| NIST SP 800-53 Rev. 5  | SC-12 (Cryptographic Key Establishment)            | Kubelet serving keys are rotated automatically against the cluster CA rather than self-signed and reused indefinitely.        |
| NIST SP 800-53 Rev. 5  | SC-17 (Public Key Infrastructure Certificates)     | All kubelet serving certificates trace to the cluster's controlled CA, enabling automated trust validation by scrapers.       |
| NIST SP 800-53 Rev. 5  | AC-3 (Access Enforcement)                          | The approver's `providerRegex` and `providerIpPrefixes` constraints prevent a compromised kubelet from minting certs for peers. |
