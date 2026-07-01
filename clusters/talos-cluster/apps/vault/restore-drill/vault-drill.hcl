disable_mlock = true
ui            = false

# Vault 2.x gates generate-root by default. The restore drill must keep this
# break-glass family token-less so a restored snapshot whose token store has
# been replaced can still be recovered from the recovery-key quorum.
enable_unauthenticated_access = ["generate-root"]

# Distinct cluster identity. A snapshot restored in Part 2 (152b) overwrites
# the cluster identity from the snapshot; for the empty Part 1 Vault this name
# keeps the drill provably distinct from the live cluster.
cluster_name = "vault-drill"

# AWS KMS auto-unseal — the SAME CMK the live Vault uses
# (alias/vault-unseal-talos). Credentials come from the aws-signing-helper
# sidecar's shared credentials file (IAM Roles Anywhere -> STS) via the
# vault-unseal-runtime role, which is KMS-only (Encrypt/Decrypt/DescribeKey on
# the one CMK; NO ssm:*). Auto-unseal here proves the drill can drive the CMK;
# it grants no path to the live Raft or to SSM.
seal "awskms" {
  kms_key_id = "alias/vault-unseal-talos"
}

# Single-node Raft with NO join directives whatsoever (intentionally absent
# below). With no join targets the drill Vault can never discover or join the
# live Vault's Raft — it bootstraps a brand-new single-member cluster of
# itself. This is the storage-layer half of the isolation guarantee (the
# network half is in networkpolicies.yaml).
storage "raft" {
  path = "/vault/data"
}

# Listener: TLS disabled. This is acceptable ONLY because the drill is reached
# exclusively via `kubectl port-forward` over loopback, and namespace ingress
# is default-deny (no in-cluster client can reach this port). The drill serves
# real key material in-pod once Part 2 restores a snapshot; that exposure is
# contained by (a) ingress default-deny, (b) port-forward-only access, and
# (c) teardown immediately after the drill. The advertised addresses (set via
# the pod env, not here) reference ONLY the drill service.
listener "tcp" {
  address         = "[::]:8200"
  cluster_address = "[::]:8201"
  tls_disable     = 1
}
