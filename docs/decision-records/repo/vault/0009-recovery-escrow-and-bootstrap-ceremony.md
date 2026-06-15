# ADR-0009: Recovery-bundle escrow and a one-time bootstrap ceremony

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-02                              |
| Authors        | Nick Warila (@NWarila), Claude          |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | ADR-0006, ADR-0008; talos-cluster [ADR-0012](../0012-vault-kms-auto-unseal-credential-delivery.md) |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | 2026-12-02                              |

## TL;DR

Under [ADR-0008] auto-unseal, `vault operator init` returns **recovery keys**
and an initial **root token** exactly once. Escrow that bundle in **AWS SSM
Parameter Store** (Standard SecureString, encrypted under the Vault CMK,
write-once). Run init as a short, fail-closed **operator ceremony** from an
ephemeral context — **not** a standing in-cluster Job. Use
`recovery_shares=5, recovery_threshold=3` (see "Recovery share count" below);
mint an orphan least-privilege admin; **revoke** the initial root token. Nothing
here is ever committed to Git.

## Context and Problem Statement

Initialization happens **once per cluster lifetime**, and its output (recovery
keys + root token) is the most sensitive material in the system. With
auto-unseal, recovery keys are the break-glass path (rekey, regenerate-root,
seal migration); they cannot unseal Vault directly. We need a durable, access-
controlled place for that bundle that satisfies the no-secret-in-Git rule
([ADR-0006]) and is cheap, and we need a defensible way to *produce* it.

An adversarial review of a fully-automated in-cluster bootstrap Job surfaced a
**structurally irreducible failure window**: `POST /sys/init` returns the bundle
once, in memory; between that return and the durable escrow write, any ordinary
event (OOM, eviction, node drain, STS expiry, KMS throttle, partition) destroys
the only copy while Vault is already initialized — leaving Vault running but
with **no** root token and **no** recovery keys (break-glass permanently gone).
A preflight shrinks but cannot close that window. Automating a once-ever
operation also adds a bespoke signed image, a standing in-cluster AWS identity,
and an SSM egress hole — machinery whose cost is not justified by automating
something that runs once.

## Decision Drivers

- The recovery/root bundle must never be in Git, plaintext or SOPS ([ADR-0006]).
- Minimize the unrecoverable window and its blast radius.
- Least privilege: the writer must not be able to read escrow back.
- ~$1/month; no second CMK.
- Operability for a solo maintainer; clear break-glass.

## Considered Options

### Escrow store
1. **SSM Parameter Store Standard SecureString** under the Vault CMK.
2. SSM SecureString under the AWS-managed `alias/aws/ssm` key.
3. AWS Secrets Manager.

### Execution model
A. **One-time operator ceremony** (ephemeral context; AWS write off-cluster).
B. **Standing automated in-cluster bootstrap Job** (signed image, RA identity).

## Decision Outcome

**Escrow: Option 1.** SSM **Standard** SecureString at
`/nwarila-platform/vault/talos-cluster/init-material`, encrypted under the
dedicated Vault CMK (not `alias/aws/ssm`, whose key policy is uneditable), with
`Overwrite=false` (write-once). Standard tier + the CMK keep this within the
~$1/month target; Secrets Manager's per-secret charge buys rotation we do not
need for a one-time bundle. The escrow value is the recovery keys (and,
transiently, whatever `init` returns) — see "root token" below.

**Execution: Option A — one-time operator ceremony.** The init + escrow runs
from an ephemeral context (operator workstation + `kubectl port-forward`, or a
throwaway full-CLI pod), with the AWS `PutParameter` done off-cluster using the
human's `vault-escrow-write` managed policy. The ceremony is a strict fail-closed
state machine:

1. **Preflight** SSM writability (and KMS encrypt-via-SSM) — catches IAM/path
   misconfig **before** the irreversible init.
2. `GET /v1/sys/init` — if already initialized, do **not** init; go to step 5.
3. `POST /v1/sys/init` with `recovery_shares=5`, `recovery_threshold=3`
   (optionally `recovery_pgp_keys` so the one-time output is pre-encrypted).
4. **First** post-init action: write the raw init response to SSM
   (`Overwrite=false`).

   **Recovery share count (5/3, as built 2026-06-02).** Shamir *t-of-n* only
   buys separation-of-duties when shares are distributed to **distinct
   custodians**. For a solo maintainer whose bundle is escrowed as a **single
   blob** (SSM + one offline file), every share lives together, so the split is
   cosmetic to confidentiality regardless of `n`/`t`. Given that, 5/3 is chosen
   over the originally-drafted 3/2 because it is strictly **no weaker** (higher
   reconstruction threshold, 3>2; more redundancy, tolerates 2 lost vs 1) and a
   destructive re-init to change a cosmetic count would forfeit validated,
   working seal state for no security or availability gain.
5. Mint an **orphan** (`no_parent=true`) least-privilege admin token/policy,
   then **revoke** the initial root token (`auth/token/revoke-self`).
6. Idempotent rerun contract: `initialized + escrow present → exit 0`;
   `initialized + escrow ABSENT → fail loudly` (do not pretend success; do not
   attempt re-init, which is impossible).

**Root token:** revoked after admin creation; **not** escrowed long-term.
Break-glass to regain root is `sys/generate-root` using the escrowed recovery
keys — so escrow holds recovery keys, not a standing root token.

Option B (automated Job) is **rejected for v1**: it adds the catastrophic
lost-key window above plus a bespoke signed image and standing AWS identity to
automate a once-ever step. It remains a documented future option only if true
zero-touch-from-empty-cluster ever becomes a hard requirement.

## Confirmation

Confirmed when: the ceremony runbook
([`deploy-vault` bootstrap-and-unseal procedure](https://github.com/nwarila-platform/deploy-vault/blob/main/docs/how-to/bootstrap-and-unseal.md)) runs to
completion; `GET /v1/sys/seal-status` shows `initialized=true`, `sealed=false`;
the SSM parameter exists (`Overwrite=false` rejects a second write); the initial
root token is revoked; and a `sys/generate-root` break-glass drill using the
escrowed recovery keys succeeds in a non-prod path.

### As-built status (2026-06-02)

Done and verified on `talos-cluster`: init (recovery 5/3); KMS auto-unseal
(`sealed=false`, `recovery_seal=true`); all 3 replicas unsealed on the UBI9
image; **restart-safe** (a deleted replica re-unsealed unattended); escrow
written to `/nwarila-platform/vault/talos-cluster/init-material` **under the
CMK**, `Overwrite=false` (a second write is rejected); break-glass **read**
authorization confirmed by the CMK key policy (`EscrowReadBreakGlass` →
`vault-break-glass`).

**Operator follow-ups (intentionally not automated — handle hands-on):** mint
the orphan least-privilege admin and **revoke the initial root token** (it is
still live, escrowed in the bundle); run the `sys/generate-root` break-glass
drill in a non-prod path. These touch live root-credential material and are left
to a human per the runbook.

## Consequences

### Positive
- Smallest blast radius for the once-ever init; no standing in-cluster AWS
  identity, no escrow material in etcd, no bespoke image to maintain.
- Write-once escrow + a write-only writer (`vault-escrow-write` has
  `ssm:PutParameter` and KMS encrypt-via-SSM but **no** `kms:Decrypt`/
  `GetParameter`) means the writer cannot read the bundle back.
- Break-glass read is a separate MFA role (`vault-break-glass`); two CloudTrail
  identities, two revocation levers.

### Negative
- The init→escrow window is **structurally irreducible**, not closable. The
  preflight + writing escrow first + optional `recovery_pgp_keys` reduce
  likelihood/consequence; a crash in the window is documented as a known
  residual (it leaves Vault running but break-glass-less, requiring a
  re-init/restore).
- The ceremony is a manual step (acceptable — it runs once).

### Neutral
- Other SSM uses can continue under the free `alias/aws/ssm`; only Vault's
  escrow uses the CMK.

## Related ADRs

- [ADR-0008](0008-adopt-kms-auto-unseal.md) — the auto-unseal seal this escrows.
- [ADR-0006](0006-pin-and-verify-the-image.md) — no secret material in Git.
- talos-cluster [ADR-0012](../0012-vault-kms-auto-unseal-credential-delivery.md) — IAM principals (escrow-write / break-glass) + CMK.
