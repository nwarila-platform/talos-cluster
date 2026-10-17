output "gitlab_tunnel_id" {
  description = "UUID of the dedicated GitLab tunnel."
  value       = cloudflare_zero_trust_tunnel_cloudflared.gitlab.id
}

output "gitlab_tunnel_status" {
  description = "Tunnel status as last read by Terraform: inactive until the in-cluster connector first runs, then healthy."
  value       = cloudflare_zero_trust_tunnel_cloudflared.gitlab.status
}

output "gitlab_host" {
  description = "Public hostname that now resolves, through Cloudflare, to the tunnel."
  value       = var.gitlab_host
}

output "keycloak_tunnel_id" {
  description = "UUID of the dedicated Keycloak tunnel."
  value       = cloudflare_zero_trust_tunnel_cloudflared.keycloak.id
}

output "keycloak_tunnel_status" {
  description = "Tunnel status as last read by Terraform: inactive until the in-cluster connector first runs, then healthy."
  value       = cloudflare_zero_trust_tunnel_cloudflared.keycloak.status
}

output "keycloak_host" {
  description = "Public hostname that now resolves, through Cloudflare, to the Keycloak tunnel."
  value       = var.keycloak_host
}
