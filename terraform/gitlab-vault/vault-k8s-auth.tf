# cert-manager signs through Vault without a stored credential. The Kubernetes
# auth method verifies the short-lived service-account tokens cert-manager
# mints (TokenReview through Vault's own service account; the chart's
# authDelegator binding) and the vault-issuer role maps one service account in
# one namespace, presenting the issuer's audience, to a policy whose only
# capability is signing under the tcn-server role. platform/cert-manager/
# issuer.yaml is the consumer.
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = "kubernetes"

  lifecycle {
    prevent_destroy = true
  }
}

resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  backend         = vault_auth_backend.kubernetes.path
  kubernetes_host = "https://kubernetes.default.svc:443"
  # No CA certificate and no reviewer JWT: Vault runs in a pod and uses its own
  # service account token and the cluster CA (the documented in-cluster form).
}

resource "vault_policy" "cert_manager_tcn_server" {
  name   = "cert-manager-tcn-server"
  policy = <<-EOT
    path "${vault_mount.pki_int.path}/sign/${vault_pki_secret_backend_role.tcn_server.name}" {
      capabilities = ["create", "update"]
    }
  EOT
}

resource "vault_kubernetes_auth_backend_role" "vault_issuer" {
  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = "vault-issuer"
  bound_service_account_names      = ["vault-issuer"]
  bound_service_account_namespaces = ["cert-manager"]
  # cert-manager puts vault://<cluster-issuer name> in every token it mints.
  audience                = "vault://vault-tcn-server"
  token_ttl               = 600
  token_max_ttl           = 600
  token_policies          = [vault_policy.cert_manager_tcn_server.name]
  token_no_default_policy = true
}
