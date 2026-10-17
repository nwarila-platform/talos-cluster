# The GitLab edge: one dedicated, remotely configured tunnel whose connector
# runs in the cluster (platform/cloudflared/), one ingress rule for the GitLab
# hostname to GitLab's LAN address, and the proxied DNS record that sends
# the public name to the tunnel. LAN clients are unaffected: the site resolver
# answers the same name with GitLab's LAN address. Off the LAN, mtls.tf requires
# a client certificate for everything except GitLab's OpenID discovery document
# and JWKS, which AWS IAM reads to verify CI ID tokens (terraform/gitlab-vault/aws.tf).
data "cloudflare_zone" "this" {
  filter = {
    name = var.zone
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "gitlab" {
  account_id = var.cloudflare_account_id
  name       = var.gitlab_tunnel_name
  # Ingress rules live in Cloudflare (below); the connector only needs its token.
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
        # The in-cluster connector reaches GitLab's nginx by its LAN address (not
        # by name, so the public CNAME can never route the tunnel to itself).
        service = "https://${var.gitlab_origin_address}:443"
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

# The connector token. It is sensitive and lands in state (the bucket is
# already treated as a secret store).
data "cloudflare_zero_trust_tunnel_cloudflared_token" "gitlab" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.gitlab.id
}

# The in-cluster connector reads its token and GitLab's certificate (the
# ca_pool above) from this Secret. The namespace is created by make platform
# (platform/cloudflared), before this root runs.
resource "kubernetes_secret_v1" "cloudflared_gitlab" {
  metadata {
    name      = "cloudflared-gitlab"
    namespace = "cloudflared"
  }

  data = {
    token    = data.cloudflare_zero_trust_tunnel_cloudflared_token.gitlab.token
    "ca.crt" = file(var.gitlab_ca_file)
  }

  type = "Opaque"
}
