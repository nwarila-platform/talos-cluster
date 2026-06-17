# ADR-0008: Adopt AWS KMS auto-unseal (supersedes ADR-0003)

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-02                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | ADR-0003, ADR-0006, ADR-0007; talos-cluster [ADR-0012](../0012-vault-kms-auto-unseal-credential-delivery.md) |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | 2026-12-02                              |

## TL;DR

Replace the manual Shamir unseal of [ADR-0003] with **AWS KMS auto-unseal**
(`seal "awskms"`). Vault unseals itself on every restart by calling a dedicated
customer-managed KMS key (`alias/vault-unseal-talos`). The seal principal gets
AWS credentials from **IAM Roles Anywhere** via an `aws_signing_helper` sidecar
that refreshes a **shared credentials file** Vault reads (the `serve`/IMDS shim
originally chosen here did not work — see [ADR-0011]) — **no change to the
UBI9-micro Vault image**. Initialization produces **recovery keys** (not unseal
keys); see [ADR-0009] for the escrow.

## Context and Problem Statement

[ADR-0003] chose manual Shamir unseal for day one and explicitly tracked the
recurring operational burden as the headline deferred risk: every pod
restart/reschedule needs a human with the threshold of key shares. For a
3-replica StatefulSet on a self-hosted cluster, that is the dominant toil and a
real availability hazard (an unattended reboot leaves Vault sealed). The
recurring pain is **unseal**, not init (which happens once). Auto-unseal removes
the recurring pain entirely.

The constraints that shaped [ADR-0003] still hold: no init/unseal/root material
in Git ([ADR-0006]); the image is shell-free, read-only-rootfs, runs as 65532,
drops all capabilities ([ADR-0007], [ADR-0001]). Any solution must not modify or
weaken the image, and the cluster is self-hosted Talos — there is **no IRSA, EC2
instance profile, or IMDS** to source AWS credentials from.

## Decision Drivers

- Eliminate per-restart human unseal toil (the [ADR-0003] headline risk).
- No modification to the frozen, signed UBI9-micro image ([ADR-0006]).
- No long-lived AWS access key in Git (secret hygiene).
- Credentials that **auto-refresh** (short-lived STS must not strand a
  long-running Vault).
- ~$1/month recurring cost.

## Considered Options

1. **Keep manual Shamir unseal** ([ADR-0003] status quo).
2. **KMS auto-unseal**, credentials via a static IAM access key in SOPS.
3. **KMS auto-unseal**, credentials via **IAM Roles Anywhere** (cert → STS).
4. **Transit auto-unseal** via a second, already-unsealed Vault.

## Decision Outcome

**Chosen: Option 3 — KMS auto-unseal with IAM Roles Anywhere.**

- **Seal:** `seal "awskms" { kms_key_id = "alias/vault-unseal-talos" }` in
  `vault.hcl`; `AWS_REGION` supplied by env. The seal is configured **before**
  the first `vault operator init`, so init returns recovery keys + a root token
  (handled by [ADR-0009]), not Shamir unseal keys.
- **Key:** one **dedicated, single-purpose** customer-managed CMK
  (`alias/vault-unseal-talos`), automatic rotation off, with a hardened key
  policy (account root limited to key administration; only the Vault runtime
  role gets `kms:Encrypt`/`kms:Decrypt`/`kms:DescribeKey`). Rationale and the
  rejected shared-key option are in talos-cluster
  [ADR-0012](../0012-vault-kms-auto-unseal-credential-delivery.md).
- **Credential delivery:** an `aws_signing_helper` **`update`-mode** sidecar
  presents the `CN=vault-runtime` certificate and continuously refreshes a
  short-lived STS credential into a **shared, memory-backed credentials file**
  (`/aws/creds/credentials`, tmpfs). Vault's `awskms` seal reads it via
  `AWS_SHARED_CREDENTIALS_FILE` — a path the AWS SDK's default credential chain
  honors. A run-once bootstrap init container writes the file before Vault
  starts so the seal never races an empty file. **The originally chosen
  `serve`/IMDSv2 shim was abandoned** because Vault 2.0.1's `awskms` seal (AWS
  SDK Go v1) does not honor `AWS_EC2_METADATA_SERVICE_ENDPOINT` — see
  [ADR-0011] for the empirical evidence. The image is unchanged: it already
  ships a CA bundle (the `ca-certificates` RPM at
  `/etc/pki/tls/certs/ca-bundle.crt`), and the helper runs in separate sidecar
  containers.

Option 2 (static key) is rejected: the AWS SDK static-credentials provider never
expires/refreshes, and a standing AWS key in the SOPS layer is a larger blast
radius than a CN-scoped certificate that can only mint short-lived STS sessions.
Option 4 (Transit) is rejected: there is no second Vault, and it would invert
the dependency this ADR is trying to simplify.

## Confirmation

Validated end-to-end against the live account before adoption (talos-cluster
[ADR-0012](../0012-vault-kms-auto-unseal-credential-delivery.md) §Confirmation):
the `CN=vault-runtime` certificate assumed the runtime
role via Roles Anywhere and performed a KMS Encrypt→Decrypt round trip on the
CMK — the exact operations the `awskms` seal uses. On-cluster confirmation:
`vault status` / `GET /v1/sys/seal-status` shows `type=awskms`,
`recovery_seal=true`, `sealed=false` after auto-unseal; a deleted follower pod
re-unseals with no human; a node left idle past one STS TTL still unseals on
restart.

## Consequences

### Positive
- No human needed on pod restart/reschedule — the [ADR-0003] toil is gone.
- Image and hardening posture unchanged ([ADR-0006]/[ADR-0007] intact).
- ~$1/month (one CMK, rotation off; free SSM standard + Roles Anywhere).

### Negative
- **Availability inversion (headline risk):** with auto-unseal, recovery keys
  **cannot** unseal Vault if KMS/STS/Roles Anywhere is unreachable, or if the
  certificate expires or the CMK is disabled/deleted. A correlated AWS-reach
  loss during a quorum reboot can seal the whole cluster. Break-glass is the
  documented `awskms→Shamir` seal migration with the escrowed recovery keys
  (see [`deploy-vault` recover-sealed-quorum procedure](https://github.com/nwarila-platform/deploy-vault/blob/main/docs/how-to/recover-sealed-quorum.md)).
  This trades [ADR-0003]'s "needs a human" risk for "needs AWS reachable" — an
  explicit, accepted trade for a portfolio cluster.
- New dependencies: a Roles Anywhere leaf certificate (1-year, manual rotation
  until cert-manager lands) and a sidecar container.

### Neutral
- The Vault image is reused as-is; the AWS coupling is entirely in the
  StatefulSet (sidecar + env) and `vault.hcl` seal stanza.
- Migration path off auto-unseal is supported (`disabled = true` + `vault
  operator unseal -migrate` with recovery keys).

## Related ADRs

- [ADR-0003](0003-use-manual-shamir-unseal-initially.md) — **superseded by this
  ADR** (manual Shamir was the day-one stand-in).
- [ADR-0009](0009-recovery-escrow-and-bootstrap-ceremony.md) — recovery-bundle
  escrow + the one-time init ceremony.
- [ADR-0006](0006-pin-and-verify-the-image.md) — no secret material in Git.
- [ADR-0007](0007-disable-mlock-accept-swap-risk.md) — runtime hardening posture.
- [ADR-0011](0011-credential-delivery-shared-file-not-imds.md) — why credential
  delivery uses a shared file, not the `serve`/IMDS shim.
- talos-cluster [ADR-0012](../0012-vault-kms-auto-unseal-credential-delivery.md) — credential delivery, egress, CMK/IAM model.

[ADR-0011]: 0011-credential-delivery-shared-file-not-imds.md
