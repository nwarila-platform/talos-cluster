// Vault auto-unseal KMS key.
// Resources to be implemented in Phase 1 next session per PLAN.md §2.9.
// Required:
//   - aws_kms_key.vault_unseal (SYMMETRIC_DEFAULT, ENCRYPT_DECRYPT, rotation enabled,
//     30-day deletion window, tag talos-cluster:component = vault-unseal,
//     prevent_destroy = true)
//   - aws_kms_alias.vault_unseal (alias/talos-cluster-vault-unseal)
//   - resource policy denying all principals except account root, the bootstrap
//     management roles, and the talos-cluster-vault-unseal IAM user.
