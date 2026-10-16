# The GitLab edge: one dedicated, remotely configured tunnel whose connector
# runs as its own service on the GitLab host (platform/gitlab-host/), one
# ingress rule for the GitLab hostname, and the proxied DNS record that sends
# the public name to the tunnel. LAN clients are unaffected: the site resolver
# answers the same name with GitLab's LAN address. Public reachability exists
# so AWS IAM can read GitLab's OpenID discovery document and JWKS
# (terraform/gitlab-vault/aws.tf).
data "cloudflare_zone" "this" {
  filter = {
    name = var.zone
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "gitlab" {
  account_id = var.cloudflare_account_id
  name       = var.gitlab_tunnel_name
  # Ingress rules live in Cloudflare (below), not in a file on the host; the
  # connector only needs its token.
  config_src = "cloudflare"

  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "gitlab" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.gitlab.id
  source     = "cloudflare"

  config = {
    ingress = [
      {
        hostname = var.gitlab_host
        # cloudflared runs on the GitLab host; the origin is GitLab's own nginx.
        service = "https://localhost:443"
        origin_request = {
          # The origin presents a self-signed certificate for the GitLab name:
          # verify it against that exact certificate instead of skipping
          # verification.
          origin_server_name = var.gitlab_host
          ca_pool            = var.gitlab_origin_ca_path
          no_tls_verify      = false
          http_host_header   = var.gitlab_host
          connect_timeout    = 10
        }
      },
      {
        # Everything that is not the GitLab hostname.
        service = "http_status:404"
      },
    ]
  }
}

resource "cloudflare_dns_record" "gitlab" {
  zone_id = data.cloudflare_zone.this.id
  name    = var.gitlab_host
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.gitlab.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "GitLab via the dedicated tunnel (terraform/cloudflare)"

  lifecycle {
    prevent_destroy = true
  }
}

# The connector token for the host. It is sensitive, lands in state (the
# bucket is already treated as a secret store) and is written by
# scripts/cloudflare.sh to .state/cloudflare/gitlab-tunnel.env for the
# operator to install on the host.
data "cloudflare_zero_trust_tunnel_cloudflared_token" "gitlab" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.gitlab.id
}
