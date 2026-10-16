# KV v2 store for per-project secrets (kv/data/ci/production/project-<id>/...).
resource "vault_mount" "kv" {
  path    = "kv"
  type    = "kv"
  options = { version = "2" }

  lifecycle {
    prevent_destroy = true
  }
}

# GitLab CI job ID tokens log in here; Vault fetches GitLab's OIDC discovery
# document and JWKS itself, trusting the GitLab server certificate.
resource "vault_jwt_auth_backend" "gitlab" {
  path                  = "gitlab"
  type                  = "jwt"
  oidc_discovery_url    = var.gitlab_url
  bound_issuer          = var.gitlab_url
  oidc_discovery_ca_pem = file(var.gitlab_ca_file)

  lifecycle {
    prevent_destroy = true
  }
}
