# Imported Vault ADRs

This directory preserves the repository-specific ADRs that originated in
`nwarila-platform/deploy-vault` before Vault moved into this repository under
`clusters/talos-cluster/apps/vault/`.

The original deploy-vault numbering is intentionally retained here so the
historical supersession chain remains readable without renumbering into the
main talos-cluster repository ADR namespace.

| From `deploy-vault/docs/decision-records/repo/` | To `talos-cluster/docs/decision-records/repo/vault/` | Title |
| --- | --- | --- |
| `0001-use-kustomize-not-helm-chart.md` | [0001](0001-use-kustomize-not-helm-chart.md) | Use Kustomize, not the Vault Helm chart, for the shell-free image |
| `0002-use-ha-raft-integrated-storage.md` | [0002](0002-use-ha-raft-integrated-storage.md) | Use HA mode with integrated Raft storage |
| `0003-use-manual-shamir-unseal-initially.md` | [0003](0003-use-manual-shamir-unseal-initially.md) | Use manual Shamir unseal initially; defer auto-unseal |
| `0004-tls-bootstrap-is-temporary.md` | [0004](0004-tls-bootstrap-is-temporary.md) | Treat `tls_disable` as a temporary bootstrap state only |
| `0005-internal-only-before-gateway-exposure.md` | [0005](0005-internal-only-before-gateway-exposure.md) | Deploy internal-only before any Gateway exposure |
| `0006-pin-and-verify-the-image.md` | [0006](0006-pin-and-verify-the-image.md) | Digest-pin the image and verify its signature on-cluster |
| `0007-disable-mlock-accept-swap-risk.md` | [0007](0007-disable-mlock-accept-swap-risk.md) | Keep `disable_mlock=true` and accept the swap risk |
| `0008-adopt-kms-auto-unseal.md` | [0008](0008-adopt-kms-auto-unseal.md) | Adopt AWS KMS auto-unseal |
| `0009-recovery-escrow-and-bootstrap-ceremony.md` | [0009](0009-recovery-escrow-and-bootstrap-ceremony.md) | Recovery-bundle escrow and a one-time bootstrap ceremony |
| `0010-rebase-vault-image-onto-ubi9.md` | [0010](0010-rebase-vault-image-onto-ubi9.md) | Rebase the Vault image onto Red Hat UBI 9 |
| `0011-credential-delivery-shared-file-not-imds.md` | [0011](0011-credential-delivery-shared-file-not-imds.md) | Deliver auto-unseal credentials via a shared file |
| `0012-use-dedicated-longhorn-vault-storageclass.md` | [0012](0012-use-dedicated-longhorn-vault-storageclass.md) | Use a dedicated Longhorn Vault StorageClass |
| `0013-adopt-offline-root-vault-pki-for-internal-tls.md` | [0013](0013-adopt-offline-root-vault-pki-for-internal-tls.md) | Adopt offline-root Vault PKI for internal TLS |
