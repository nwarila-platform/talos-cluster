# The remote-access tier. Off the LAN, GitLab and Keycloak answer only clients that present a
# certificate from this account's Cloudflare-managed CA (the Free plan accepts no other issuer;
# the certificates already on the owner's devices qualify). The one exception is the pair of
# GitLab documents AWS IAM reads to verify CI ID tokens: AWS cannot present a certificate, and
# both are public by design. On the LAN the site resolver answers both names with LAN addresses
# (GitLab's host, the cluster VIP), so this tier is never in the path; GitLab's own server-side
# calls to Keycloak depend on that, which is why make cloudflare checks the resolver first.

# Cloudflare asks for a client certificate during the TLS handshake on these hostnames.
resource "cloudflare_certificate_authorities_hostname_associations" "mtls" {
  zone_id   = data.cloudflare_zone.this.id
  hostnames = [var.gitlab_host, var.keycloak_host]
}

# The handshake alone admits clients without a certificate; these rules turn them away. A
# revoked certificate still verifies, so it is checked separately.
resource "cloudflare_ruleset" "mtls" {
  zone_id     = data.cloudflare_zone.this.id
  name        = "client certificate required"
  description = "Off-LAN access to GitLab and Keycloak needs a valid client certificate (terraform/cloudflare/mtls.tf)."
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      description = "Keycloak: client certificate required"
      action      = "block"
      expression  = "(http.host eq \"${var.keycloak_host}\" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))"
      enabled     = true
    },
    {
      description = "GitLab: client certificate required, except the two documents AWS reads"
      action      = "block"
      expression  = "(http.host eq \"${var.gitlab_host}\" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked) and not http.request.uri.path in {\"/.well-known/openid-configuration\" \"/oauth/discovery/keys\"})"
      enabled     = true
    },
  ]
}
