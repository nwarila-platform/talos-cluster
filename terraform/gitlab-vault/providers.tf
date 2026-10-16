# GitLab: the token is read from GITLAB_TOKEN (an administrator personal access
# token with the api and create_runner scopes); it is never written to files.
provider "gitlab" {
  base_url    = "${var.gitlab_url}/api/v4"
  cacert_file = var.gitlab_ca_file
}

# Vault: the token is read from VAULT_TOKEN.
provider "vault" {
  address      = var.vault_addr
  ca_cert_file = var.vault_ca_file
}

provider "kubernetes" {
  config_path = var.kubeconfig
}

provider "helm" {
  kubernetes = {
    config_path = var.kubeconfig
  }
}
