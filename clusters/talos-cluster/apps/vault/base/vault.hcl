disable_mlock = true
ui            = true

# AWS KMS auto-unseal (ADR-0008). The key is referenced by alias; region and
# credentials come from the environment / the aws-signing-helper sidecar
# (AWS_REGION + AWS_SHARED_CREDENTIALS_FILE; the helper refreshes that file —
# see ADR-0011), NOT from this file. Set kms_key_id in exactly ONE place (here)
# — do not also set VAULT_AWSKMS_SEAL_KEY_ID.
seal "awskms" {
  kms_key_id = "alias/vault-unseal-talos"
}

storage "raft" {
  path = "/vault/data"

  retry_join {
    leader_api_addr     = "https://vault-0.vault-internal.deploy-vault.svc.cluster.local:8200"
    leader_ca_cert_file = "/vault/tls/ca.crt"
  }
  retry_join {
    leader_api_addr     = "https://vault-1.vault-internal.deploy-vault.svc.cluster.local:8200"
    leader_ca_cert_file = "/vault/tls/ca.crt"
  }
  retry_join {
    leader_api_addr     = "https://vault-2.vault-internal.deploy-vault.svc.cluster.local:8200"
    leader_ca_cert_file = "/vault/tls/ca.crt"
  }
}

listener "tcp" {
  address            = "[::]:8200"
  cluster_address    = "[::]:8201"
  tls_cert_file      = "/vault/tls/tls.crt"
  tls_key_file       = "/vault/tls/tls.key"
  tls_client_ca_file = "/vault/tls/ca.crt"
  tls_min_version    = "tls13"
}
