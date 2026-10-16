output "gitlab_tunnel_id" {
  description = "UUID of the dedicated GitLab tunnel."
  value       = cloudflare_zero_trust_tunnel_cloudflared.gitlab.id
}

output "gitlab_tunnel_status" {
  description = "Tunnel status as last read by Terraform: inactive until the host connector first runs, then healthy."
  value       = cloudflare_zero_trust_tunnel_cloudflared.gitlab.status
}

output "gitlab_host" {
  description = "Public hostname that now resolves, through Cloudflare, to the tunnel."
  value       = var.gitlab_host
}

output "gitlab_tunnel_env" {
  description = "Environment file content for the host connector service (TUNNEL_TOKEN=...); written to .state/cloudflare/gitlab-tunnel.env by scripts/cloudflare.sh."
  value       = "TUNNEL_TOKEN=${data.cloudflare_zero_trust_tunnel_cloudflared_token.gitlab.token}\n"
  sensitive   = true
}
