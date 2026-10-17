# The Keycloak edge: a second dedicated tunnel whose connector runs inside the
# cluster (platform/keycloak/cloudflared.yaml), one ingress rule for the
# Keycloak hostname to the operator's Service, verified against the Vault PKI
# root by Keycloak's public name, and the proxied DNS record. The connector's
# token goes straight into the Secret the Deployment reads. LAN clients never
# use this path: the site resolver answers the same name with the cluster VIP.
# Off the LAN, mtls.tf requires a client certificate.
resource "cloudflare_zero_trust_tunnel_cloudflared" "keycloak" {
  account_id = var.cloudflare_account_id
  name       = var.keycloak_tunnel_name
  config_src = "cloudflare"

  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "keycloak" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.keycloak.id
  source     = "cloudflare"

  config = {
    ingress = [
      {
        hostname = var.keycloak_host
        service  = "https://keycloak-service.keycloak.svc.cluster.local:8443"
        origin_request = {
          origin_server_name = var.keycloak_host
          ca_pool            = var.keycloak_origin_ca_path
          no_tls_verify      = false
          http_host_header   = var.keycloak_host
          connect_timeout    = 10
        }
      },
      {
        service = "http_status:404"
      },
    ]
  }
}

resource "cloudflare_dns_record" "keycloak" {
  zone_id = data.cloudflare_zone.this.id
  name    = var.keycloak_host
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.keycloak.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "Keycloak via the in-cluster tunnel (terraform/cloudflare)"

  lifecycle {
    prevent_destroy = true
  }
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "keycloak" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.keycloak.id
}

# The in-cluster connector reads TUNNEL_TOKEN from this Secret. The namespace
# is created by make platform (platform/keycloak), before this root runs.
resource "kubernetes_secret_v1" "cloudflared_keycloak" {
  metadata {
    name      = "cloudflared-keycloak"
    namespace = "keycloak"
  }

  data = {
    token = data.cloudflare_zero_trust_tunnel_cloudflared_token.keycloak.token
  }

  type = "Opaque"
}
