# vault-aws-access

Cluster-side wiring for **Vault KMS auto-unseal** (see `deploy-vault`
ADR-0008 / ADR-0009). This directory delivers the one long-lived secret the
design needs — the IAM Roles Anywhere **workload certificate** — into the
`deploy-vault` namespace as a SOPS-encrypted `Secret`.

## What it contains

- `vault-ra-cert.sops.yaml` — Secret `vault-ra-cert` (`deploy-vault` ns) with
  `tls.crt` + `tls.key`: the end-entity certificate (`CN=vault-runtime`) and
  its private key, issued by the offline self-managed CA
  (`CN=nwarila-platform-vault-ra-ca`). The `aws-signing-helper` sidecar in the
  Vault StatefulSet mounts this read-only to obtain short-lived STS credentials
  via IAM Roles Anywhere, which Vault's `awskms` seal then uses to call KMS.

## Why the cert (not an AWS access key) is the secret-zero

A static IAM access key never expires and is a standing AWS credential. The
X.509 key here can only mint **short-lived** STS sessions (≤1h) via a specific
Roles Anywhere trust anchor + profile + role, scoped by the certificate's
subject/issuer CN — and it cannot call KMS directly. The recovery/root bundle
itself is **never** in Git: it lives only in AWS SSM Parameter Store, encrypted
under the Vault CMK.

## AWS resources this pairs with (non-secret identifiers)

| Resource | Value |
| --- | --- |
| Region / Account | `us-east-1` / `793496711039` |
| CMK (seal + escrow) | `alias/vault-unseal-talos` |
| RA trust anchor | `vault-talos` |
| RA profile | `vault-runtime` |
| Runtime role | `arn:aws:iam::793496711039:role/vault-unseal-runtime` |
| Escrow path (SSM) | `/nwarila-platform/vault/talos-cluster/init-material` |

## Rotation

The leaf cert is valid 1 year (no cert-manager yet — see ADR-0008 deferred
work). To rotate: issue a new `CN=vault-runtime` leaf from the offline CA,
rebuild this Secret, `sops -e -i` it, and PR. The CA private key is held
**offline only** and is never committed here.

## Encrypt / edit

```sh
# edit (needs the age private key; e.g. .s3/secrets/age.agekey)
export SOPS_AGE_KEY_FILE=.s3/secrets/age.agekey
sops clusters/talos-cluster/apps/vault-aws-access/vault-ra-cert.sops.yaml
```

Encryption only needs the public age recipient in the repo-root `.sops.yaml`;
Flux's kustomize-controller decrypts at reconcile time via the `sops-age`
Secret in `flux-system`.
