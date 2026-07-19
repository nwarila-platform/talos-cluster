# First-party container inventory

The canonical list of the platform's **home-built / first-party container images** —
what exists, what's planned, and what's *wanted but not yet created*. This is the
single source that replaces reconstructing the picture from the supply-chain plan,
ADRs, and the GHCR orgs each time.

**Scope:** first-party images under `ghcr.io/nwarila/*` and `ghcr.io/nwarila-platform/*`
(the namespaces we own the signing identity for, covered by the single
`verify-first-party` ImageValidatingPolicy at fail-closed `[Deny]`/`Fail`). Third-party images we consume directly
are summarized in the appendix for context; the authority for converting unsigned
third-party → signed first-party is `_handoff/SUPPLY-CHAIN-INTEGRITY-PLAN.md`
(the fold-in program, **deferred to immediate-post-talos-cluster**).

**Sign status legend:** ✍️ cosign-keyless first-party signature (admission-enforced by the current `verify-first-party` `[Deny]`/`Fail` IVP) · 🧱 base/template
(not a runtime image) · ⏳ will be first-party-signed once built · 🪞 mirror-and-sign
(copy of a signed upstream, not a rebuild).

---

## 1. Built & deployed (first-party, live)

| Image | Build repo | Purpose | Sign |
|---|---|---|---|
| `ghcr.io/nwarila-platform/ubi9-hashicorp-vault` | `nwarila-platform/ubi9-hashicorp-vault` | Vault server — official HashiCorp Vault 2.0.1 artifact on UBI9 (signed-checksum-verified in build) | ✍️ |
| `ghcr.io/nwarila-platform/ubi9-aws-signing-helper` | `nwarila-platform/ubi9-aws-signing-helper` | IAM-Roles-Anywhere KMS signing sidecar (Vault auto-unseal) | ✍️ |

## 2. Base building-blocks (exist; the "UBI9 image repo")

| Image / repo | Purpose | Sign | Note |
|---|---|---|---|
| `nwarila/ubi9-base` | UBI9 base | 🧱 | |
| `nwarila/ubi9-base-micro` | hardened micro base — everything first-party builds on | 🧱 | **v1.0.0 is a delivery gate for Keycloak.** Supply-chain plan gates the whole fold-in on this repo being "100% complete — very close, not done." |
| `nwarila/ubi9-application-template` | app-image template | 🧱 | |

## 3. Planned fold-ins (the supply-chain program — DEFERRED post-talos-cluster)

Convert genuinely-unsigned third-party images into signed first-party. Gated on §2
completeness. **None are MVP-blocking.** Split by method:

### 3a. Home-**build** (from source/base → `ubi9-micro` + binary)
| Target image | Repo exists? | Source it replaces | Tier / ref | Sign |
|---|---|---|---|---|
| `ghcr.io/nwarila/dr-restore-driver` | ❌ **no** | `docker.io/bitnami/kubectl` (interim) | **T1 pilot, ADR-0023** | ⏳ |
| `ghcr.io/nwarila/ubi9-python` | ❌ no | Python base for `source-rotator` + `talos-drift` (zero-rewrite rebase) | T1 | ⏳ |
| first-party `vault-config-operator` | ❌ no | `quay.io/redhat-cop/vault-config-operator` (**unsigned** — cosign tree empty v0.8.49) | T2-class (adopted this session, CP-4) | ⏳ |
| first-party `vault-secrets-operator` | ❌ no | `hashicorp/vault-secrets-operator` (GPG binaries only) | T2 | ⏳ |
| first-party `kube-rbac-proxy` | ❌ no | `quay.io/brancz/kube-rbac-proxy` (unsigned) | T2 | ⏳ |
| first-party `kubelet-csr-approver` | ❌ no | `ghcr.io/postfinance/kubelet-csr-approver` (unsigned) | T2 | ⏳ |
| first-party ARC controller | ❌ no | `ghcr.io/actions/gha-runner-scale-set-controller` (unsigned) | T4 (decide at ARC adoption; runner already has GitHub provenance — never rebuild it) | ⏳ |

### 3b. Mirror-**sign** (verify + `cosign copy`, not a rebuild — T3 Longhorn)
| Target | Source | Note |
|---|---|---|
| `ghcr.io/nwarila/csi-*` ×6 | `registry.k8s.io/sig-storage/{csi-attacher,csi-provisioner,csi-resizer,csi-snapshotter,csi-node-driver-registrar,livenessprobe}` (cosign-keyless-signed upstream) | 🪞 byte-identical copy of the signed upstream; CI guard maps Longhorn's per-release CSI pins → verified digests |
| `ghcr.io/nwarila/longhorn-*` ×7 | longhorn core: manager, engine, instance-manager, share-manager, backing-image-manager, ui, support-bundle-kit (SUSE-BCI, unsigned) | 🪞 mirror-and-sign, NOT rebuild (a ubi9 rebuild diverges from the tested storage data path); documented trust-on-first-use residual |

## 4. Wanted / not-yet-created — app repos (post-project consumers, not platform helpers)

| Repo / image | Purpose | State |
|---|---|---|
| **OAuth-backend** (Python 3.12) | OAuth backend for the owner's Chrome extension | ❌ wanted; the first-app forcing function alongside Keycloak |
| **Keycloak** (config/deploy) | 2 instances (internal-only + internet-facing guild) | ❌ post-project; consumes upstream Keycloak; waits on `ubi9-base-micro` v1.0.0 + a Postgres story |
| platform **registry** + **monitoring/alerting** | future platform services | ❌ backlog |

> **`dr-restore-driver` — the notable loose end.** The image `ghcr.io/nwarila/dr-restore-driver`
> is already *referenced* by the DR-validator manifest (ADR-0023/0024), but **no build repo
> exists** and **no image is published**. It causes no live break only because the DR-validator
> is inert by design. To make it real (per ADR-0023): author `driver.py` (Python subprocess-driving
> the *pinned* `kubectl`, replacing the 376-line `restore-driver.sh`, all safety guards preserved) +
> a `Dockerfile` (`ubi9-base-micro` + Python + pinned `kubectl`; no bash/coreutils/shell) → owner
> **builds + cosign-signs** into `ghcr.io/nwarila/dr-restore-driver` → the loop does the pin-swap PR
> retiring the interim `bitnami/kubectl`. Scaffolding was drafted to scratchpad once but never
> committed to a repo.

---

## Appendix — third-party images consumed directly (context, not home-built)

**Signed & CI-verifiable** (keyless GitHub-OIDC unless noted): Flux (SLSA L3), Cilium
(2 identities), Kyverno (separate signatures repo), `getsops/sops`, `siderolabs/talosctl`;
**static-key**: cert-manager (sha512, no-tlog — Kyverno v1.18 can't verify it → digest-pinned
interim, booked TD); **Google-OIDC**: `registry.k8s.io/*` (metrics-server, coredns, core k8s —
Talos-delivered). These stay Audit-at-admission by design (TD-0001 / TD-0002); the *first-party*
supply chain is enforced at `[Deny]`/`Fail`.

**Genuinely unsigned** (the fold-in candidates in §3): `vault-secrets-operator`,
`quay.io/brancz/kube-rbac-proxy`, `kubelet-csr-approver`, all `longhornio/*`, all
`ghcr.io/actions/*`, `docker.io/library/python`, `docker.io/bitnami/kubectl` (interim),
`quay.io/redhat-cop/vault-config-operator`.

---

_Maintenance: this is the canonical inventory — update it when an image is built, a fold-in
lands, or a wanted repo is created. Companion docs: `docs/tech-debt.md` (TD-0001/0002 supply-chain
deferrals), `_handoff/SUPPLY-CHAIN-INTEGRITY-PLAN.md` (fold-in program authority), ADR-0023
(dr-restore-driver contract), ADR-0024 (DR-validator boundary)._
