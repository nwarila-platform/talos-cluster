# One shared instance runner for the cluster. Isolation between projects is
# enforced in Vault (per-project roles), not by runner scoping.
resource "gitlab_user_runner" "cluster" {
  runner_type  = "instance_type"
  description  = "talos-cluster"
  untagged     = true
  tag_list     = ["talos"]
  access_level = "not_protected"

  # The token is unrecoverable; replacing the runner is a deliberate,
  # reviewed change that removes this guard for one apply.
  lifecycle {
    prevent_destroy = true
  }
}

# Every project's jobs reach Vault through these two instance-level variables.
resource "gitlab_instance_variable" "vault_addr" {
  key       = "VAULT_ADDR"
  value     = var.vault_incluster_url
  raw       = true
  protected = false
  masked    = false
}

resource "gitlab_instance_variable" "vault_cacert" {
  key           = "VAULT_CACERT"
  value         = file(var.vault_ca_file)
  variable_type = "file"
  raw           = true
  protected     = false
  masked        = false
}

locals {
  # var.gitlab_url is validated to https://<host> with no port, so the host is
  # exactly the certificate file name the runner expects.
  gitlab_host = trimprefix(var.gitlab_url, "https://")
}

resource "kubernetes_namespace_v1" "gitlab_runner" {
  metadata {
    name = "gitlab-runner"
  }
}

# The chart mounts this secret at /home/gitlab-runner/.gitlab-runner/certs/;
# the key must be <gitlab host>.crt for the runner to trust the server.
resource "kubernetes_secret_v1" "gitlab_ca" {
  metadata {
    name      = "gitlab-ca"
    namespace = kubernetes_namespace_v1.gitlab_runner.metadata[0].name
  }
  data = {
    "${local.gitlab_host}.crt" = file(var.gitlab_ca_file)
  }
}

resource "helm_release" "gitlab_runner" {
  name       = "gitlab-runner"
  repository = "https://charts.gitlab.io"
  chart      = "gitlab-runner"
  version    = "0.93.0"
  namespace  = kubernetes_namespace_v1.gitlab_runner.metadata[0].name
  atomic     = true
  timeout    = 300

  values = [file("${path.module}/../../platform/gitlab-runner/values.yaml")]

  set = [
    {
      name  = "gitlabUrl"
      value = "${var.gitlab_url}/"
    },
  ]

  set_sensitive = [
    {
      name  = "runnerToken"
      value = gitlab_user_runner.cluster.token
    },
  ]

  depends_on = [kubernetes_secret_v1.gitlab_ca]
}
