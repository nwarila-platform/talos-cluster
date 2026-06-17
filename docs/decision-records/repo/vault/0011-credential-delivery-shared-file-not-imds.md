# ADR-0011: Deliver auto-unseal credentials via a shared file, not an IMDS shim

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-02                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | ADR-0008; talos-cluster [ADR-0012](../0012-vault-kms-auto-unseal-credential-delivery.md) |
| Informed       | None.                                   |
| Reversibility  | Easy                                    |
| Review-by      | 2026-12-02                              |

## TL;DR

[ADR-0008] chose to deliver IAM Roles Anywhere credentials to Vault's `awskms`
seal through an `aws_signing_helper` **`serve`** sidecar (an IMDSv2-compatible
endpoint on `127.0.0.1:9911`, discovered via
`AWS_EC2_METADATA_SERVICE_ENDPOINT`). **That does not work with Vault 2.0.1.**
Its `awskms` seal uses AWS SDK Go **v1**, which never queries the configured
metadata endpoint. We switch to the **canonical** Roles Anywhere integration:
the helper runs in **`update`** mode, continuously refreshing a short-lived STS
credential into a shared, memory-backed **credentials file**
(`/aws/creds/credentials`), and Vault reads it via `AWS_SHARED_CREDENTIALS_FILE`.

## Context and Problem Statement

After the cluster was reconciled onto the UBI9 Vault image and the `serve`
sidecar, every Vault pod crash-looped:

```
error parsing Seal configuration: error fetching AWS KMS wrapping key
information: NoCredentialProviders: no valid providers in chain. Deprecated.
	For verbose messaging see aws.Config.CredentialsChainVerboseErrors
```

The `Deprecated.` suffix is the AWS SDK Go **v1** chain-provider error string,
which fixes the SDK generation in use. The sidecar itself was fully healthy:
with `--debug`, it logged a successful Roles Anywhere `CreateSession`
(`HTTP 201`, valid `ASIA…` STS credentials for `vault-unseal-runtime`) and
served them on `127.0.0.1:9911`.

The decisive evidence: **the helper logged zero incoming requests.** Vault never
queried `127.0.0.1:9911` despite `AWS_EC2_METADATA_SERVICE_ENDPOINT` being set
correctly on the running container. AWS SDK Go v1, as embedded in Vault 2.0.1's
`awskms` seal (`go-kms-wrapping` → `go-secure-stdlib/awsutil`), does not honor
that environment variable for its instance-metadata provider — it falls through
to the hard-coded link-local `169.254.169.254`, which on Talos (and under the
egress `CiliumNetworkPolicy`) is unreachable, yielding an immediate
`NoCredentialProviders`. No helper-side or env tweak (trailing slash,
`--hop-limit`, port) can change which endpoint the SDK dials.

## Decision Drivers

1. **Correctness** — the credential path must actually be exercised by Vault's
   SDK credential chain (empirically verified, not assumed).
2. **Auto-refresh** — short-lived STS sessions must not strand a running Vault
   ([ADR-0008] driver).
3. **No image change** — keep the frozen, signed UBI9-micro Vault image
   ([ADR-0006]); the AWS coupling stays in the StatefulSet.
4. **No long-lived AWS key in Git** ([ADR-0008] / talos-cluster
   [ADR-0012](../0012-vault-kms-auto-unseal-credential-delivery.md)).

## Considered Options

1. **Keep `serve`/IMDS and make the SDK honor the endpoint.** Rejected: the SDK
   generation Vault ships ignores `AWS_EC2_METADATA_SERVICE_ENDPOINT`; there is
   no supported configuration that redirects its metadata provider.
2. **`credential_process` in an AWS config file.** The SDK execs the helper on
   each refresh. Rejected for now: the helper binary would have to live inside
   the **shell-free UBI9-micro** Vault container (which ships no shell and
   cannot `cp` the binary in from the helper image), dragging the helper's
   dynamic-link closure into Vault's image — fragile and couples the two images.
3. **`update`-mode sidecar → shared credentials file** (chosen). The canonical
   AWS-documented Roles Anywhere integration; the SDK's default chain always
   reads `AWS_SHARED_CREDENTIALS_FILE`.
4. **Static IAM access key in SOPS.** Already rejected by [ADR-0008] Option 2
   (never refreshes; larger blast radius).

## Decision Outcome

**Chosen: Option 3.**

- The `aws-signing-helper` native sidecar runs `update` (no `--once`): a refresh
  loop that re-mints the STS credential before expiry and writes the
  `[default]` profile to `/aws/creds/credentials`.
- A run-once **`aws-creds-bootstrap`** init container runs `update --once` to
  the same file **before** Vault starts, so the seal never reads an empty file
  (replacing the unprobeable loopback-listener race the `serve` design had).
- `/aws/creds` is a **memory-backed `emptyDir`** (tmpfs) shared by the helper
  containers (read-write) and Vault (read-only) — the credential never touches
  disk.
- Vault gets `AWS_REGION` and `AWS_SHARED_CREDENTIALS_FILE=/aws/creds/credentials`;
  the `AWS_EC2_METADATA_SERVICE_ENDPOINT` env and the `9911` port are removed.

The certificate, CMK, trust anchor, profile, role, and egress
`CiliumNetworkPolicy` are unchanged — only the local hand-off from helper to
Vault changes.

## Confirmation

On-cluster: the `aws-creds-bootstrap` init container completes (writes a
non-empty `/aws/creds/credentials`); the Vault container starts without
`NoCredentialProviders` and reports `type=awskms`, `recovery_seal=true` once
initialized; a Vault container restart past the STS TTL still unseals because
the `update` sidecar keeps the file fresh.

## Consequences

### Positive
- The credential path is one Vault's SDK actually uses; no reliance on
  undocumented metadata-endpoint behavior.
- Credential stays in tmpfs, never on disk or in Git.
- No probe gymnastics — a run-to-completion init container is a clean ordering
  gate, unlike a loopback listener kubelet cannot probe.

### Negative
- In-process credential caching: AWS SDK Go v1's shared-file provider does not
  re-read the file mid-process, so a Vault process that needs KMS **more than
  one STS TTL after start** (e.g. an operator-driven seal rekey/migration) could
  use a stale credential until restart. Auto-unseal itself (KMS use at
  startup/unseal) is unaffected, and the `update` sidecar guarantees any restart
  reads a fresh file. Accepted for a portfolio cluster.

### Neutral
- Two helper containers now reference the cert (the sidecar and the bootstrap);
  both are scoped to the `aws-ra-cert` volume only.

## Related ADRs

- [ADR-0008](0008-adopt-kms-auto-unseal.md) — adopts KMS auto-unseal; this ADR
  corrects its credential-delivery mechanism.
- [ADR-0010](0010-rebase-vault-image-onto-ubi9.md) — the UBI9 image this runs on.
- talos-cluster [ADR-0012](../0012-vault-kms-auto-unseal-credential-delivery.md) — CMK/IAM/egress model (unchanged by this ADR).
