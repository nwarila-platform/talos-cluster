# ADR-0012: Vault KMS Auto-Unseal — AWS Credential Delivery, Egress, and Key Model

| Field          | Value                                     |
| -------------- | ----------------------------------------- |
| Status         | Accepted                                  |
| Date           | 2026-06-02                                |
| Authors        | Nick Warila (@NWarila), Claude            |
| Decision-maker | Nick Warila (sole portfolio maintainer)   |
| Consulted      | ADR-0008, ADR-0010, ADR-0011, deploy-vault ADR-0008/0009 |
| Informed       | None.                                     |
| Reversibility  | Medium                                    |
| Review-by      | 2026-12-02 (cert-manager re-evaluation)   |

## TL;DR

`deploy-vault` adopts AWS KMS auto-unseal (deploy-vault ADR-0008). Because the
cluster is self-hosted Talos (no IRSA / EC2 instance profile / Pod Identity),
the Vault seal principal gets AWS credentials from **IAM Roles Anywhere** using
an `aws_signing_helper` **serve-mode** sidecar (an IMDSv2 shim on
`127.0.0.1:9911`). `talos-cluster` owns three pieces of the wiring: the
**AWS egress** allowance, the **SOPS-encrypted workload certificate**, and the
acceptance of the **dedicated single-purpose CMK** model. The recovery/root
bundle is never in Git; it lives only in SSM Parameter Store under that CMK.

## Context and Problem Statement

Vault starts sealed. ADR-0003 in `deploy-vault` used manual Shamir unseal —
correct for day one but it requires a human on every pod restart. deploy-vault
ADR-0008 replaces that with KMS auto-unseal. KMS auto-unseal needs the Vault
process to call `kms:Encrypt`/`kms:Decrypt` with AWS credentials, from a cluster
that has **no AWS-native identity source** (not EKS, no instance profile, no
IMDS). The only in-AWS options are a static IAM access key or IAM Roles
Anywhere. The UBI9-micro Vault image (`FROM registry.access.redhat.com/ubi9/ubi-micro`, shell removed) is shell-free, read-only
rootfs, runs as UID 65532, and must not be modified. This ADR records how
`talos-cluster` delivers credentials and egress for that design without
weakening any of those constraints, and why the key model is a dedicated CMK.

## Decision Drivers

1. **No long-lived AWS access key in Git** (org deny-all + secret hygiene).
2. **No modification to the frozen, signed UBI9-micro Vault image** (no shell,
   no aws-cli, read-only rootfs, restricted PSS).
3. **Credentials must auto-refresh** so a long-running unsealed Vault does not
   break when short-lived STS credentials expire (~1h).
4. **Least privilege + auditability** across the seal principal, the one-time
   escrow writer, and the human break-glass reader.
5. **~$1/month** recurring cost target.
6. **GitOps hygiene** — secrets via SOPS reconciled by the `flux-system`
   Kustomization; no hand-edits to generator-owned files.

## Considered Options

### Credential delivery
1. **Static IAM access key** in a SOPS Secret, consumed via
   `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`.
2. **Roles Anywhere + `credential_process`** — signing-helper binary on an
   `emptyDir` (init container), referenced from `AWS_CONFIG_FILE`.
3. **Roles Anywhere + `serve` mode sidecar** — IMDSv2 shim; Vault uses
   `AWS_EC2_METADATA_SERVICE_ENDPOINT`.
4. **Roles Anywhere + static `AWS_SHARED_CREDENTIALS_FILE`** written by a
   sidecar.

### Key model
A. **One dedicated single-purpose CMK** for Vault (seal-wrap + escrow).
B. **One generically-named CMK shared** with SOPS/other SSM uses.
C. **Two CMKs** (separate seal and escrow keys).

## Decision Outcome

**Credential delivery: Option 3 (serve-mode sidecar).** The `aws_signing_helper`
runs as a sidecar, presents the workload certificate, and vends credentials via
a local IMDSv2-compatible endpoint that it refreshes **five minutes before
expiry**. Vault's AWS SDK discovers it through
`AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:9911` (no trailing slash).
This is the only option that (a) auto-refreshes independent of Vault's KMS call
cadence, (b) keeps the certificate/key out of the Vault container, and (c) needs
nothing executable inside the scratch image.

- Option 1 (static key) is **rejected**: the AWS SDK static-credentials provider
  never refreshes or expires, and a standing AWS key in the SOPS layer is a
  larger blast radius than a certificate that can only mint short-lived,
  CN-scoped STS sessions.
- Option 2 (`credential_process`) is the **fallback**: it also auto-refreshes,
  but it requires the helper binary to be exec-able from inside the Vault
  container's mount namespace and (on older SDKs) `AWS_SDK_LOAD_CONFIG=1`.
- Option 4 (static credentials file) is **rejected**: the SDK caches the file as
  static credentials and does **not** refresh, so Vault silently loses KMS
  access ~1h after any reschedule.

**Key model: Option A (one dedicated CMK).** `alias/vault-unseal-talos` is used
only by Vault — for seal-wrap *and* to encrypt the SSM escrow parameter — with
per-principal key-policy statements, automatic rotation **off**.

- Option B (shared/generic key) is **rejected**: Vault's `awskms` seal uses **no
  encryption context**, so any principal ever granted plain `kms:Decrypt` on a
  shared key can decrypt Vault's seal-wrapped root key given a Raft read.
  Isolation would become a forever-discipline rather than a structural property.
  A dedicated key also lets Vault own the key's lifecycle (seal-wrapped data
  means the key must never be disabled, destructively rotated, or deleted).
  Other SSM uses can continue to use the free AWS-managed `alias/aws/ssm` key, so
  a dedicated Vault key does not block "use SSM for other things."
- Option C (two CMKs) is **rejected** as unnecessary cost: per-principal
  statements on one key give the isolation a second physical key would, for half
  the spend.

### talos-cluster's three responsibilities

1. **AWS egress** — `deploy-vault`'s own `CiliumNetworkPolicy` (in its repo)
   allows egress to `kms`/`sts`/`rolesanywhere.us-east-1.amazonaws.com:443` plus
   DNS visibility for the Cilium FQDN proxy. The tenant envelope keeps
   default-deny + allow-DNS. Without this egress, every unseal fails closed at
   the network layer.
2. **Workload certificate** — `clusters/talos-cluster/apps/vault-aws-access/`
   holds the SOPS-encrypted `vault-ra-cert` Secret (`CN=vault-runtime` leaf +
   key). It is reconciled and decrypted by the `flux-system` Kustomization
   (which carries the `sops-age` provider) because the per-app `deploy-vault`
   Kustomization runs as the namespace-scoped `deploy-reconciler` SA with no
   decryption. The directory is hand-authored and allowlisted; it is not a
   `deploy-*` path, so `scripts/sync-deploy-repos.sh` re-indexes it without
   overwriting it.
3. **Key/IAM acceptance** — this ADR records acceptance of the dedicated-CMK
   model and the three-principal IAM split.

### IAM principals (one trust anchor)

| Principal | Identity | Permissions |
| --- | --- | --- |
| Runtime seal | RA role `vault-unseal-runtime` (cert `CN=vault-runtime`) | `kms:Encrypt/Decrypt/DescribeKey` on the CMK only |
| Escrow write (one-time) | Operator IAM user via managed policy `vault-escrow-write` | `ssm:PutParameter` on the escrow path + `kms:Encrypt/GenerateDataKey` **via SSM only**; **no** `kms:Decrypt`, **no** `ssm:GetParameter` |
| Break-glass read | IAM role `vault-break-glass` (MFA) | `ssm:GetParameter` on the escrow path + `kms:Decrypt` **via SSM only** |

The RA role trust policy pins `aws:SourceArn` to the trust anchor and
`StringEquals` on `aws:PrincipalTag/x509Subject/CN` and `x509Issuer/CN`, so a
valid certificate alone is insufficient — it must carry the expected subject and
issuer CNs. The CMK key policy grants the AWS account **key-administration
actions only** (no blanket data-plane `kms:*`), so a future broad IAM grant
cannot silently turn the seal key into shared decrypt material.

## Confirmation

This decision was confirmed before merge by an end-to-end dry run against the
live account (`793496711039`, `us-east-1`):

1. `aws_signing_helper credential-process` with the `CN=vault-runtime`
   certificate returned STS credentials and `sts:GetCallerIdentity` resolved to
   `assumed-role/vault-unseal-runtime/...` — proving the trust-policy conditions
   (subject CN, issuer CN, SourceArn) enforce correctly.
2. Those credentials performed `kms:DescribeKey` and a full **Encrypt→Decrypt
   round trip** on the CMK — exactly the operations Vault's `awskms` seal uses.
3. The Vault image already ships `ca-certificates_data`, so TLS to KMS/STS
   needs no image change.
4. The signing-helper Linux binary (v1.8.2, sha256 `7addb6eb…`) is dynamically
   linked against glibc, so the sidecar uses a glibc base, not `scratch`.

It is fully confirmed on-cluster when: all three Vault pods report
`type=awskms`, `recovery_seal=true`, `sealed=false` after auto-unseal; a deleted
follower pod re-unseals with no human; and a node left idle past one STS TTL
still unseals on restart (serve-mode proactive refresh).

## Consequences

### Positive
- No long-lived AWS key anywhere; the only standing secret is a short-validity,
  CN-scoped certificate. Per-pod-restart human toil (ADR-0003) is eliminated.
- The UBI9-micro Vault image is unchanged; the AWS dependency is a sidecar.
- Recovery/root material is never in Git (SSM-only, CMK-encrypted, write-once).

### Negative
- **Availability inversion (headline risk):** recovery keys **cannot** unseal
  Vault if KMS/STS/Roles Anywhere is unreachable or the cert/CMK is broken. A
  correlated AWS-reachability loss during a quorum reboot can seal the whole
  cluster. Break-glass is the documented `awskms→Shamir` seal migration with the
  escrowed recovery keys — rehearse it.
- The RA leaf certificate is a new rotation chore (1-year validity, no
  cert-manager yet). Expiry = loss of KMS auth on next restart.
- A sidecar plus a SOPS cert plus an egress policy is more moving parts than
  manual Shamir.

### Neutral
- The escrow uses the dedicated CMK rather than `alias/aws/ssm` so break-glass
  decrypt is resource-scoped; other SSM consumers can still use `alias/aws/ssm`.

## Assumptions

1. The cluster's Cilium has the DNS proxy / `toFQDNs` enabled. If not, AWS egress
   falls back to `toCIDRSet` from the AWS `ip-ranges.json` with a refresh owner.
2. The Vault 2.0.1 build's `go-kms-wrapping/awskms` wrapper resolves credentials
   via the standard AWS SDK chain (serve-mode IMDS works under SDK v1 and v2).
3. The offline CA private key is stored securely outside Git and is used only to
   re-issue the workload leaf on rotation.

## Supersedes

None. (Complements deploy-vault ADR-0008/0009; relates to local ADR-0011.)

## Superseded by

None (current).

## Related ADRs

- [ADR-0008](0008-gitops-via-flux.md) — Flux is the cluster GitOps engine.
- [ADR-0010](0010-adopt-kyverno-policy-engine.md) — image-verification substrate.
- [ADR-0011](0011-auto-discover-deploy-repositories.md) — the `deploy-*`
  convention this wiring lives alongside.
- `deploy-vault` ADR-0008 (auto-unseal) and ADR-0009 (escrow + ceremony).

## Compliance Notes

| Framework | Control / Practice ID | Evidence Contribution |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5 | SC-12, SC-28, AC-6 | Customer-managed key for at-rest seal/escrow; least-privilege per-principal key policy; MFA break-glass. |
| NIST SP 800-53 Rev. 5 | IA-5, AU-2 | No static credentials; certificate-based short-lived sessions; CloudTrail on KMS/SSM. |
| NIST SP 800-190 | 4.1, 4.4 | Image left unmodified/hardened; secret material delivered via SOPS, never baked or committed. |
| SSDF | PS.1, PO.5 | Recovery material escrowed out-of-band; environment hardening preserved. |
