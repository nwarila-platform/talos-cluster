# ADR-0023: Use a Signed NWarila Image for the DR Restore Driver

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Proposed                                |
| Date           | 2026-07-10                              |
| Authors        | Nick Warila (@NWarila), Codex implementation support |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | ADR-0010, ADR-0020, current restore-driver CronJob and Kyverno boundary policy |
| Informed       | future platform operators and reviewers |
| Reversibility  | Medium                                  |
| Review-by      | 2026-07-17                              |

## Context and Problem Statement

ADR-0020 introduced a suspended `dr-restore-driver` CronJob for the first Vault
restore-validation slice. The CronJob currently uses the interim third-party
image `docker.io/bitnami/kubectl` pinned by digest. That image is acceptable for
the suspended bootstrap slice because it supplies `bash`, `kubectl`, and GNU
coreutils, but it is not a long-term supply-chain endpoint for production DR
automation.

The cluster already enforces keyless cosign verification for
`ghcr.io/nwarila-platform/*` images through Kyverno. The related `ghcr.io/nwarila/*`
first-party namespace is not yet covered, so a future `ghcr.io/nwarila/dr-restore-driver`
image would otherwise fall through unsigned admission policy. The repository
needs an explicit contract for the final restore-driver image and a narrow,
reviewable swap procedure before the CronJob is ever un-suspended.

## Decision Drivers

1. Keep the restore-driver supply chain first-party, digest-pinned, and signed
   before the driver becomes runnable.
2. Preserve the existing defense-in-depth boundary: the static CI guard, the
   Kyverno runtime boundary rule, and the CronJob manifest must agree on the
   approved image.
3. Avoid replacing the interim image until the owner has built, pushed, signed,
   and independently verified the final digest.
4. Keep the scaffold safe to merge now: the new `ghcr.io/nwarila/*` signature
   rule matches no current deployed Pod images.

## Decision

Replace the interim `docker.io/bitnami/kubectl` restore-driver image with a
first-party `ghcr.io/nwarila/dr-restore-driver` image after the owner creates,
builds, signs, and verifies that image.

The image will be created from the `ubi9-application-template` and based on the
hardened `ubi9-base-micro` base image. The build pipeline must publish an SBOM,
produce SLSA-L3 provenance through the template, and sign the image with cosign
keyless signing through GitHub Actions OIDC. The cluster-side trust anchor is the
`verify-nwarila-images` Kyverno rule, which enforces signatures for
`ghcr.io/nwarila/*` with issuer `https://token.actions.githubusercontent.com`,
Rekor at `https://rekor.sigstore.dev`, and a case-tolerant NWarila GitHub subject
regular expression.

The current scaffold intentionally does not change the CronJob image. Until the
owner performs the digest swap, the suspended CronJob remains pinned to the
interim bitnami digest.

## Image Contract

The `ghcr.io/nwarila/dr-restore-driver` image must provide only the runtime
surface needed by `restore-driver.sh`:

- `bash`, because the CronJob command is pinned to `/bin/bash`.
- `kubectl`, pinned by version and checksum in the image build.
- GNU coreutils, including `date -d`, because `restore-driver.sh` depends on GNU
  date behavior.
- No additional shell beyond `bash`.
- No embedded cluster credentials, Vault credentials, recovery shares, kubeconfig,
  talosconfig, or generated machine configuration.

The image must run under the existing CronJob security contract:

- UID and GID `65532`.
- `runAsNonRoot: true`.
- read-only root filesystem.
- writable `HOME=/tmp` backed by the existing `emptyDir`.
- no privilege escalation and no Linux capabilities.

The image must be referenced by digest only in cluster manifests:

```text
ghcr.io/nwarila/dr-restore-driver@sha256:<digest>
```

If the GHCR package is private, Kyverno must have registry read credentials before
the image is admitted. Otherwise the owner should keep the package public/readable
or add an explicit `imageRegistryCredentials` path to the signature policy before
the swap.

## Digest-Swap Sequence

The owner executes this sequence in order and before un-suspending the CronJob:

1. Create `NWarila/dr-restore-driver` from the application template, build from
   `ubi9-base-micro`, publish the image to `ghcr.io/nwarila/dr-restore-driver`,
   cosign-sign it through GitHub Actions OIDC, and record the immutable
   `@sha256` digest.
2. Confirm the `verify-nwarila-images` rule verifies that exact digest. Acceptable
   evidence is a Kyverno CLI check against the policy and/or a cluster admission
   dry-run or Audit observation that proves the digest is accepted for the
   intended GitHub OIDC subject.
3. In one PR, update all three active pins to the same NWarila digest:
   `clusters/talos-cluster/apps/vault-restore-validator/cronjob.yaml`,
   `APPROVED_RESTORE_DRIVER_IMAGE` in
   `scripts/check-vault-restore-validator-boundaries.sh`, and rule 1's approved
   image in
   `clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml`.
4. Refresh the offline Kyverno boundary fixtures in
   `docs/kyverno-tests/protect-dr-validate-boundary/` if they are used as
   validation evidence for the same PR.
5. Re-run the static guard and render checks. If the Kyverno Layer-2 boundary is
   being promoted from Audit to Enforce, coordinate that promotion with the same
   approved digest so rule 1 does not preserve the retired bitnami pin.
6. Only after those checks pass is the restore driver safe to un-suspend under
   the supervised ADR-0020 run procedure.

## Consequences

### Positive

- The restore-driver runtime moves from a third-party utility image to a
  first-party, signed, SBOM-backed image.
- Kyverno can enforce the `ghcr.io/nwarila/*` image family before any NWarila
  workload is introduced into the cluster.
- The digest swap has an explicit three-pin coordination point, reducing the
  chance that CI, runtime admission, and the CronJob drift apart.

### Negative

- The cluster now trusts the `NWarila` GitHub organization as a signing namespace
  in addition to `nwarila-platform` and `the-hero-wars-guys`.
- A private GHCR package would require Kyverno registry credentials before
  admission can verify the image.

### Neutral

- This ADR does not create the `dr-restore-driver` repository or Dockerfile.
- This ADR does not un-suspend or schedule the restore-validator CronJob.
- Until the digest swap lands, the interim bitnami image remains documented,
  digest-pinned, and suspended.

## Alternatives Considered

1. Keep `docker.io/bitnami/kubectl` permanently.

   Rejected. It supplies the current shell and kubectl runtime, but it does not
   meet the repository's long-term first-party signed-image standard for DR
   automation.

2. Put the image under `ghcr.io/nwarila-platform/*`.

   Deferred. `ghcr.io/nwarila/*` is the existing first-party namespace for the
   hardened UBI image template and base-image line this driver should consume.
   The cluster can safely add a separate signature rule for that namespace while
   it still matches no deployed images.

3. Build a one-off image outside the template.

   Rejected. The template already carries the desired signing, SBOM, and
   provenance posture; bypassing it would create a bespoke maintenance surface
   for a sensitive DR path.

## Confirmation

This ADR is confirmed when:

1. `verify-nwarila-images` exists in the Kyverno image-signature policy with
   `failureAction: Enforce`, `mutateDigest: false`, `required: true`, and the
   NWarila GitHub OIDC subject constraint.
2. No current cluster manifest deploys a `ghcr.io/nwarila/*` Pod image before the
   owner-built digest exists.
3. The owner confirms the exact canonical GitHub organization case emitted in the
   cosign certificate subject for `NWarila` repositories.
4. The future digest-swap PR updates the CronJob image, static guard constant,
   and Kyverno boundary rule 1 together.
5. `kubectl kustomize clusters/talos-cluster` and
   `bash scripts/check-vault-restore-validator-boundaries.sh` pass after the
   swap.

## Assumptions

1. The `NWarila` application template continues to publish cosign keyless
   signatures through GitHub Actions OIDC and Rekor.
2. GitHub's certificate subject for the organization is either `NWarila` or
   lowercase `nwarila`; the policy is case-tolerant for the `NW` segment, but the
   owner must confirm the exact emitted value before relying on live admission.
3. The restore-driver script continues to require GNU `date -d`; if the script is
   rewritten to avoid that dependency, the image contract can be narrowed.

## Out of Scope

- Creating the `NWarila/dr-restore-driver` repository.
- Writing the restore-driver Dockerfile.
- Publishing or signing the image.
- Updating the three active image pins to a final digest.
- Un-suspending, scheduling, or manually triggering the CronJob.

## Supersedes

None.

## Superseded by

None (current).

## Related ADRs

- [ADR-0010](0010-adopt-kyverno-policy-engine.md) establishes Kyverno as the
  image-signature policy engine and records the existing scoped Enforce posture.
- [ADR-0020](0020-automate-vault-restore-validation.md) defines the restore
  validator and the suspended restore-driver CronJob.
- [Vault ADR-0010](vault/0010-rebase-vault-image-onto-ubi9.md) records the
  analogous first-party UBI image posture for Vault.

## Compliance Notes

| Framework            | Control / Practice ID | Evidence Contribution |
| -------------------- | --------------------- | --------------------- |
| DISA Kubernetes STIG | V-242414              | Extends admission-time image signature enforcement to the first-party NWarila image namespace used by the DR restore driver. |
| NIST SP 800-190      | 4.1, 4.5              | Requires signed, immutable image references for a sensitive Kubernetes automation workload. |
| NIST SP 800-218 SSDF | PS.3, PW.4, RV.1      | Ties the restore-driver image to a reproducible, signed, SBOM-backed build pipeline and reviewable digest promotion. |
| SLSA                 | Build L3              | Records the expected provenance level for the first-party restore-driver image template. |
