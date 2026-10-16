# A lowercase DNS host: labels of 1-63 characters that start and end
# alphanumerically, joined by single dots.
locals {
  host_pattern = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*"
}

variable "gitlab_url" {
  description = "GitLab instance (https://<host>, no port, no trailing slash); also the ID-token issuer."
  type        = string
  default     = "https://gitlab.trinitytechnicalservices.com"

  validation {
    condition     = can(regex("^https://${local.host_pattern}$", var.gitlab_url))
    error_message = "gitlab_url must be https://<valid lowercase host> with no port, path or trailing slash."
  }
}

variable "gitlab_ca_file" {
  description = "PEM certificate the GitLab server presents (self-signed today); trusted by this root, the runner and Vault's OIDC discovery."
  type        = string
  default     = "../../.state/gitlab/ca.crt"
}

variable "vault_addr" {
  description = "Vault as reached from where terraform runs (the NodePort on a control plane today)."
  type        = string
  default     = "https://10.69.112.63:30200"

  validation {
    condition = (
      can(regex("^https?://${local.host_pattern}(:[0-9]{1,5})?$", var.vault_addr))
      && try(tonumber(regex(":([0-9]+)$", var.vault_addr)[0]) >= 1 && tonumber(regex(":([0-9]+)$", var.vault_addr)[0]) <= 65535, true)
    )
    error_message = "vault_addr must be http(s)://<valid host>[:1-65535] with no path or trailing slash."
  }
}

variable "vault_ca_file" {
  description = "CA that signed Vault's serving certificate (written by make platform)."
  type        = string
  default     = "../../.state/vault/tls/ca.crt"
}

variable "vault_incluster_url" {
  description = "Vault as reached from job pods; also the exact ID-token audience every project role binds."
  type        = string
  default     = "https://vault.vault.svc.cluster.local:8200"

  validation {
    condition = (
      can(regex("^https://${local.host_pattern}(:[0-9]{1,5})?$", var.vault_incluster_url))
      && try(tonumber(regex(":([0-9]+)$", var.vault_incluster_url)[0]) >= 1 && tonumber(regex(":([0-9]+)$", var.vault_incluster_url)[0]) <= 65535, true)
    )
    error_message = "vault_incluster_url must be https://<valid host>[:1-65535] with no path or trailing slash."
  }
}

variable "kubeconfig" {
  description = "kubeconfig of the cluster that runs the GitLab runner (written by make bootstrap)."
  type        = string
  default     = "../../.state/configs/kubeconfig"
}

variable "projects" {
  description = "Projects managed here, keyed by <group>/<project>. Each gets a GitLab project with a protected main branch; while vault_access is true it also gets a Vault JWT role bound to that project id. ci_file (optional) is committed once to main as .gitlab-ci.yml. Offboarding = vault_access false (first apply), then archived true (second apply); entries are never simply removed."
  type = map(object({
    ci_file      = optional(string)
    vault_access = optional(bool, true)
    archived     = optional(bool, false)
  }))
  default = {
    "poc/vault-gitlab-poc" = {
      ci_file = "../../examples/vault-gitlab-poc/.gitlab-ci.yml"
    }
  }

  validation {
    condition     = alltrue([for key in keys(var.projects) : can(regex("^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*$", key))])
    error_message = "Project keys must be <group>/<project> using only a-z, 0-9 and -."
  }
  validation {
    condition     = length(distinct([for key in keys(var.projects) : replace(key, "/", "-")])) == length(var.projects)
    error_message = "Project keys must stay distinct after replacing / with - (that form names the Vault policy and role)."
  }
}
