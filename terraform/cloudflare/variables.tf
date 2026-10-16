locals {
  host_pattern = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*"
}

variable "cloudflare_account_id" {
  description = "Cloudflare account that owns the tunnel (32 hex characters)."
  type        = string
  default     = "b69e3910b7d95e7f7d91e6d296d8a1d8"

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be 32 lowercase hex characters."
  }
}

variable "zone" {
  description = "DNS zone the public hostnames live in (served by Cloudflare)."
  type        = string
  default     = "trinitytechnicalservices.com"

  validation {
    condition     = can(regex("^${local.host_pattern}$", var.zone))
    error_message = "zone must be a valid lowercase DNS name."
  }
}

variable "gitlab_host" {
  description = "Public hostname of GitLab; must equal the host of terraform/gitlab-vault's gitlab_url (the ID-token issuer) and lie inside var.zone."
  type        = string
  default     = "gitlab.trinitytechnicalservices.com"

  validation {
    condition     = can(regex("^${local.host_pattern}$", var.gitlab_host)) && endswith(var.gitlab_host, ".${var.zone}")
    error_message = "gitlab_host must be a valid lowercase DNS name inside var.zone."
  }
}

variable "gitlab_tunnel_name" {
  description = "Name of the dedicated GitLab tunnel (one connector service on the GitLab host)."
  type        = string
  default     = "tcnhq-ubt01-gitlab"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,62}$", var.gitlab_tunnel_name))
    error_message = "gitlab_tunnel_name must be lowercase a-z, 0-9 and -, at most 63 characters."
  }
}

variable "gitlab_origin_ca_path" {
  description = "Path, on the GitLab host, of the PEM certificate the connector trusts for the origin (GitLab's self-signed server certificate today)."
  type        = string
  default     = "/etc/cloudflared/gitlab-ca.crt"

  validation {
    condition     = can(regex("^/[A-Za-z0-9._/-]+$", var.gitlab_origin_ca_path))
    error_message = "gitlab_origin_ca_path must be an absolute path."
  }
}
