# Documentation Index

This index classifies the current non-ADR documentation by Diataxis purpose.
The repository organizes docs by purpose, but it does not yet implement the
strict quadrant-directory layout required by ADR-0002 Confirmation. That layout
debt is tracked as [TD-0003](tech-debt.md).

## Tutorials

None yet.

## How-to

Runbooks are composite operational how-to documents under ADR-0002.

- [Out-Of-Band Talos Bootstrap](runbooks/bootstrap-out-of-band.md) - brings up
  the Talos substrate, ARC runners, cache, and image-policy dependencies in
  bootstrap order.
- [Vault Generate-Root Break-Glass](runbooks/dr-generate-root-breakglass.md) -
  walks through the owner-gated scratch proof for Vault recovery-key
  generate-root recovery.
- [DR Stage 1 Backup](runbooks/dr-stage1-backup.md) - operates and verifies the
  Longhorn Stage 1 backup lifecycle on the Synology NFS target.
- [DR Validate Boundary Enforce Hardening](runbooks/dr-validate-boundary-enforce-hardening.md) -
  promotes the restore-validator Kyverno boundary from Audit/Ignore to
  Enforce/Fail after evidence review.
- [Migrate The First VSO Secret](runbooks/migrate-first-vso-secret.md) - plans
  the first tenant Vault Secrets Operator secret migration or demo proof.
- [Reprovision A SecureBoot+TPM Talos Node](runbooks/reprovision-secureboot-node.md) -
  reprovisions one Talos node with SecureBoot and TPM-backed disk encryption.
- [Backup And DR Restore Drill](runbooks/restore-drill-backup-dr.md) - proves
  Stage 0 and Stage 1 recovery artifacts in isolated drill conditions.

## Explanation

- [Architecture Diagrams](explanation/architecture.md) - explains the current
  GitOps reconciliation flow and trust boundaries from committed manifests and
  accepted decisions.
- [Kubernetes And Talos Primer](explanation/kubernetes-talos-primer.md) -
  preserves the plain-language Kubernetes, TalosOS, node-role, VIP, and command
  flow introduction moved out of the root README.

## Reference

- [Compliance scanning](compliance/README.md) - records the CIS/Kubescape
  scanning posture, finding surfaces, and triage reference.
- [Offline validation - protect-dr-validate-boundary](kyverno-tests/protect-dr-validate-boundary/README.md) -
  documents the local Kyverno CLI validation suite and expected pass/fail
  fixture behavior.
- [Technical Debt Register](tech-debt.md) - tracks deliberately deferred gaps,
  including the strict Diataxis quadrant-directory layout deferral in TD-0003.

## Architecture Decision Records

ADRs are governed by ADR-0001 and are not subject to the Diataxis quadrant rule.
Use the ADR index and scoped directories for decision history:

- [ADR index](decision-records/README.md)
- [Org-mirrored ADRs](decision-records/org/)
- [Template ADRs](decision-records/template/)
- [Repository ADRs](decision-records/repo/)

## Diataxis Compliance Status

Current non-ADR docs are classified here by Diataxis purpose. The strict
quadrant-directory skeleton (`docs/tutorials/`, `docs/how-to/`,
`docs/reference/`, and `docs/explanation/`) is not yet implemented; see
[TD-0003](tech-debt.md) for the deferred closure path.
