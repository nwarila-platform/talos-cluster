# ADR-0010: Rebase the Vault image onto Red Hat UBI 9 (ubi-micro)

## TL;DR

The Vault image moved from the Ubuntu-Chisel `FROM scratch` build to a Red Hat
**UBI 9 ubi-micro** runtime (`ghcr.io/nwarila-platform/ubi9-hashicorp-vault`).
This repo now pins `ubi9-hashicorp-vault@sha256:f4c4422b…` and the auto-unseal
sidecar pins the from-source FIPS `ubi9-aws-signing-helper@sha256:ed1d1940…`.
This ADR records the cutover and clarifies that prior references to "the chiseled
image" in ADR-0001/0006/0007/0008 now mean the UBI9-micro image; their decisions
(plain Kustomize, pin-and-verify, drop-all-caps, KMS auto-unseal) are unchanged.

## Context and Problem Statement

The Chisel build fetched the live, mutable Ubuntu archive, could not pin package
versions or use snapshots, and intermittently failed during `-security` publish
windows — it had already blocked the `aws-signing-helper` image build. A
reproducible, digest-pinnable, scanner-visible base was needed for both the Vault
image and the auto-unseal helper.

## Decision Drivers

1. **Reproducibility** — digest-pinned bases + resolvable package content.
2. **Scanner visibility** — a real rpm database so Trivy/Grype/OpenSCAP enumerate
   packages (the chiseled `FROM scratch` image carried none).
3. **FIPS for the helper** — the glibc-dynamic `aws_signing_helper` needs glibc +
   a from-source GOFIPS140 build, which UBI 9 supports and `FROM scratch` did not.
4. **No weakening of the runtime contract** — still shell-free, non-root 65532,
   read-only rootfs, drop-all-caps, public + cosign-verified.

## Considered Options

1. **UBI 9 ubi-minimal builder → ubi-micro runtime** (chosen).
2. Stay on Ubuntu Chisel (rejected: non-reproducible, blocked the helper build).
3. UBI 10 (rejected for now: deferred until a CMVP-validated RHEL 10 crypto
   module + a published DISA RHEL 10 STIG exist; tracked, ADR-gated).

## Decision Outcome

Chosen: **option 1**. The image repos `ubi9-hashicorp-vault` and
`ubi9-aws-signing-helper` build `ubi-minimal` → `ubi-micro`, preserve the rpmdb,
remove the shell that ubi-micro itself ships, keep the CA bundle at
`/etc/pki/tls/certs/ca-bundle.crt`, and publish multi-arch, cosign `--recursive`
signed, SBOM/provenance/attested, Trivy+Grype 0-fixable-HIGH/CRITICAL, public.
This repo repoints `kustomization.yaml`, `vault-statefulset.yaml`,
`validate.yaml`, and ADR-0006's cosign identity to the new names + digests.

## Confirmation

`validate.yaml` renders the Vault image as
`ghcr.io/nwarila-platform/ubi9-hashicorp-vault@sha256:f4c4422b…` (digest-pinned,
no tags, no image-pull Secret); Kyverno `verify-image-signatures` admits both new
images via the `ghcr.io/nwarila-platform/*` org wildcard + generic
`publish-image.yaml@refs/(heads/main|tags/v.*)` subjectRegExp; `cosign verify` /
`gh attestation verify` of the pinned digests succeed.

## Consequences

### Positive

- Reproducible, scanner-visible images; FIPS-validated helper crypto (Go
  Cryptographic Module v1.0.0, CMVP #5247) for the auto-unseal sidecar.
- The `ubi9-` repo names make the base explicit and ADR-gated.

### Negative

- The base major is encoded in the repo name, so a future UBI 9 → UBI 10 move
  implies a repo rename + a repeat of this repoint.
- Vault CE has no FIPS build (documented FIPS-OFF risk-acceptance in the image
  repo); the helper's FIPS posture does not extend to Vault's own crypto.

### Neutral

- The runtime contract (non-root 65532, no shell, read-only, drop-all-caps,
  awskms auto-unseal) is unchanged from the chiseled design.

## Related ADRs

- Clarifies/updates the image references in [ADR-0001], [ADR-0006], [ADR-0007],
  and [ADR-0008] (their decisions stand; only the base/name/digest changed).

[ADR-0001]: 0001-use-kustomize-not-helm-chart.md
[ADR-0006]: 0006-pin-and-verify-the-image.md
[ADR-0007]: 0007-disable-mlock-accept-swap-risk.md
[ADR-0008]: 0008-adopt-kms-auto-unseal.md
