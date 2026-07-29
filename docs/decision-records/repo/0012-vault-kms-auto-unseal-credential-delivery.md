# ADR-0012: Vault KMS Auto-Unseal — AWS Credential Delivery, Egress, and Key Model

| Field          | Value                                     |
| -------------- | ----------------------------------------- |
| Status         | Accepted                                  |
| Date           | 2026-06-02                                |
| Authors        | Nick Warila (@NWarila)                    |
| Decision-maker | Nick Warila (sole portfolio maintainer)   |
| Consulted      | ADR-0008, ADR-0010, ADR-0011, deploy-vault ADR-0008/0009 |
| Informed       | None.                                     |
| Reversibility  | Medium                                    |
| Review-by      | 2026-12-02 (cert-manager re-evaluation)   |

> **Correction (2026-07-29):** The originally accepted `serve`/IMDSv2
> credential-delivery mechanism did not work with Vault 2.0.1's AWS SDK Go v1.
> The active decision is the `aws_signing_helper update` shared-file mechanism
> documented below and in Vault
> [ADR-0011](vault/0011-credential-delivery-shared-file-not-imds.md). The helper
> refreshes the file and Vault is pointed at it, but the SDK may cache a loaded
> credential in-process: the demonstrated guarantee is a fresh credential at
> start or restart, while later KMS use beyond one STS TTL may require a Vault
> restart.

## TL;DR

`deploy-vault` adopts AWS KMS auto-unseal (deploy-vault ADR-0008). Because the
cluster is self-hosted Talos (no IRSA / EC2 instance profile / Pod Identity),
the Vault seal principal gets AWS credentials from **IAM Roles Anywhere** using
an `aws_signing_helper` **`update`-mode** sidecar that refreshes a shared,
memory-backed credentials file. Vault is pointed at
`/aws/creds/credentials` through `AWS_SHARED_CREDENTIALS_FILE`. AWS SDK Go v1
may cache a loaded credential in-process, so the accepted guarantee is that
start or restart reads a fresh file; later KMS use beyond one STS TTL may
require a Vault restart. `talos-cluster` owns three pieces of the wiring: the
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
3. **Fresh credentials at start or restart** — the helper must keep the shared
   file current so a restarted Vault does not read an expired STS credential.
   In-process caching by AWS SDK Go v1 is an accepted limit for later KMS calls.
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
3. **Roles Anywhere + `serve` mode sidecar** — the former IMDSv2-shim decision;
   rejected because Vault 2.0.1's AWS SDK Go v1 does not honor
   `AWS_EC2_METADATA_SERVICE_ENDPOINT`.
4. **Roles Anywhere + `update` mode sidecar** — refresh a shared credentials
   file and point Vault at it with `AWS_SHARED_CREDENTIALS_FILE` (chosen).

### Key model
A. **One dedicated single-purpose CMK** for Vault (seal-wrap + escrow).
B. **One generically-named CMK shared** with SOPS/other SSM uses.
C. **Two CMKs** (separate seal and escrow keys).

## Decision Outcome

**Credential delivery: Option 4 (`update`-mode shared-file sidecar).** The
`aws_signing_helper` sidecar presents the workload certificate and refreshes
short-lived STS credentials in the memory-backed
`/aws/creds/credentials` file. A run-once bootstrap init container writes that
file before Vault starts, and Vault is pointed at it through
`AWS_SHARED_CREDENTIALS_FILE`. This keeps the certificate/key out of the Vault
container and requires nothing executable inside the shell-free image.

AWS SDK Go v1 may cache a credential after loading it from the file. The
demonstrated guarantee is therefore that Vault start or restart reads a fresh
file; a later KMS operation more than one STS TTL after start may require a
Vault restart.

- Option 1 (static key) is **rejected**: the AWS SDK static-credentials provider
  never refreshes or expires, and a standing AWS key in the SOPS layer is a
  larger blast radius than a certificate that can only mint short-lived,
  CN-scoped STS sessions.
- Option 2 (`credential_process`) is the **fallback**: it also auto-refreshes,
  but it requires the helper binary to be exec-able from inside the Vault
  container's mount namespace and (on older SDKs) `AWS_SDK_LOAD_CONFIG=1`.
- Option 3 (`serve` mode) is **rejected**: Vault 2.0.1's AWS SDK Go v1 did not
  query the configured IMDSv2 endpoint, so the helper received no requests and
  Vault failed with `NoCredentialProviders`.

### Previous decision (2026-06-02)

The prior, no-longer-active credential-delivery decision and its rationale are
preserved verbatim:

> **Credential delivery: Option 3 (serve-mode sidecar).** The
> `aws_signing_helper` runs as a sidecar, presents the workload certificate,
> and vends credentials via a local IMDSv2-compatible endpoint that it
> refreshes **five minutes before expiry**. Vault's AWS SDK discovers it
> through
> `AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:9911` (no trailing
> slash). This is the only option that (a) auto-refreshes independent of
> Vault's KMS call cadence, (b) keeps the certificate/key out of the Vault
> container, and (c) needs nothing executable inside the scratch image.
>
> - Option 1 (static key) is **rejected**: the AWS SDK static-credentials
>   provider never refreshes or expires, and a standing AWS key in the SOPS
>   layer is a larger blast radius than a certificate that can only mint
>   short-lived, CN-scoped STS sessions.
> - Option 2 (`credential_process`) is the **fallback**: it also auto-refreshes,
>   but it requires the helper binary to be exec-able from inside the Vault
>   container's mount namespace and (on older SDKs)
>   `AWS_SDK_LOAD_CONFIG=1`.
> - Option 4 (static credentials file) is **rejected**: the SDK caches the file
>   as static credentials and does **not** refresh, so Vault silently loses KMS
>   access ~1h after any reschedule.

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

The credential-delivery wiring is confirmed on-cluster by the
`aws_signing_helper` sidecar running `update`, the Vault container carrying
`AWS_SHARED_CREDENTIALS_FILE=/aws/creds/credentials` with no
`AWS_EC2_METADATA_SERVICE_ENDPOINT`, and the live `vault.hcl` identifying the
helper-refreshed file. The accepted operational guarantee is that start or
restart reads a fresh file. Because AWS SDK Go v1 may cache a loaded credential
in-process, this does not confirm arbitrary later KMS use beyond one STS TTL
without a Vault restart.

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
2. The Vault 2.0.1 build's `go-kms-wrapping/awskms` wrapper resolves
   `AWS_SHARED_CREDENTIALS_FILE` at start or restart. AWS SDK Go v1 may cache
   that loaded credential in-process, so later KMS use beyond one STS TTL may
   require a Vault restart.
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
- Vault [ADR-0011](vault/0011-credential-delivery-shared-file-not-imds.md) —
  replaces the failed `serve`/IMDS shim with the active shared-file mechanism
  and records the AWS SDK Go v1 caching limitation.
- `deploy-vault` ADR-0008 (auto-unseal) and ADR-0009 (escrow + ceremony).

## Compliance Notes

| Framework | Control / Practice ID | Evidence Contribution |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5 | SC-12, SC-28, AC-6 | Customer-managed key for at-rest seal/escrow; least-privilege per-principal key policy; MFA break-glass. |
| NIST SP 800-53 Rev. 5 | IA-5, AU-2 | No static credentials; certificate-based short-lived sessions; CloudTrail on KMS/SSM. |
| NIST SP 800-190 | 4.1, 4.4 | Image left unmodified/hardened; secret material delivered via SOPS, never baked or committed. |
| SSDF | PS.1, PO.5 | Recovery material escrowed out-of-band; environment hardening preserved. |

## Changelog

| Date       | Change | Reason | Author/Role | Body-diff? |
| ---------- | ------ | ------ | ----------- | ---------- |
| 2026-07-29 | Replaced the active `serve`/IMDS credential-delivery decision with the `update`-mode shared-file mechanism; preserved the former decision under Previous decision. | Align the Accepted ADR with the live cluster and Vault ADR-0011 without overclaiming continuous in-process credential reload. | Nick Warila / sole portfolio maintainer | Yes |
