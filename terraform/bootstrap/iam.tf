// Runtime IAM users for in-cluster identities (PLAN.md §2.9).
// Resources to be implemented in Phase 1 next session.
// Required:
//   - aws_iam_user.vault_unseal (talos-cluster-vault-unseal, prevent_destroy = true)
//     + aws_iam_user_policy.vault_unseal (inline, sourced from
//       ../../iam/policies/runtime-vault-unseal.json) per the "use inline, not
//       AttachUserPolicy" rule in PLAN.md §2.7.
//   - aws_iam_user.velero (talos-cluster-velero, prevent_destroy = true)
//     + aws_iam_user_policy.velero (inline, sourced from
//       ../../iam/policies/runtime-velero-backup.json).
//   - aws_iam_access_key for each, with secret outputs marked sensitive and
//     piped into the Vault/K8s seeding flow.
