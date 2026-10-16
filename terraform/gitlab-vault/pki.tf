# Temporary Vault-internal CA: a root in pki-root signs the Linux issuing CA in
# pki-int-linux. Consumers bind only to pki-int-linux, so replacing the root
# later (offline root ceremony) re-signs one intermediate and nothing else.
# AIA and CDP are intentionally omitted until a stable publication host exists.
locals {
  org = "Trinity Technical Services"
}

resource "vault_mount" "pki_root" {
  path                  = "pki-root"
  type                  = "pki"
  description           = "temporary root CA; replaced by the offline root ceremony"
  max_lease_ttl_seconds = 315360000 # 10 years

  lifecycle {
    prevent_destroy = true
  }
}

resource "vault_pki_secret_backend_root_cert" "root" {
  backend         = vault_mount.pki_root.path
  type            = "internal"
  common_name     = "${local.org} Temporary Root CA"
  organization    = local.org
  issuer_name     = "temp-root"
  key_name        = "temp-root"
  key_type        = "ec"
  key_bits        = 384
  ttl             = "87600h"
  max_path_length = 1

  lifecycle {
    prevent_destroy = true
  }
}

resource "vault_mount" "pki_int" {
  path                  = "pki-int-linux"
  type                  = "pki"
  description           = "Linux and Kubernetes issuing CA"
  max_lease_ttl_seconds = 157680000 # 5 years

  lifecycle {
    prevent_destroy = true
  }
}

resource "vault_pki_secret_backend_intermediate_cert_request" "int" {
  backend      = vault_mount.pki_int.path
  type         = "internal"
  common_name  = "${local.org} Linux Issuing CA"
  organization = local.org
  key_name     = "linux-issuing"
  key_type     = "ec"
  key_bits     = 384
}

resource "vault_pki_secret_backend_root_sign_intermediate" "int" {
  backend         = vault_mount.pki_root.path
  issuer_ref      = vault_pki_secret_backend_root_cert.root.issuer_id
  csr             = vault_pki_secret_backend_intermediate_cert_request.int.csr
  common_name     = "${local.org} Linux Issuing CA"
  organization    = local.org
  ttl             = "43800h"
  max_path_length = 0
}

resource "vault_pki_secret_backend_intermediate_set_signed" "int" {
  backend     = vault_mount.pki_int.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.int.certificate
}

resource "vault_pki_secret_backend_issuer" "int" {
  backend     = vault_mount.pki_int.path
  issuer_ref  = vault_pki_secret_backend_intermediate_set_signed.int.imported_issuers[0]
  issuer_name = "linux-issuing"

  lifecycle {
    prevent_destroy = true
  }
}

resource "vault_pki_secret_backend_config_issuers" "int" {
  backend                       = vault_mount.pki_int.path
  default                       = vault_pki_secret_backend_issuer.int.issuer_id
  default_follows_latest_issuer = false
}

# Server certificates for names under the organisation's domain. IP SANs are
# allowed syntactically only; access to this role's issue endpoint must stay
# operator-only.
resource "vault_pki_secret_backend_role" "tcn_server" {
  backend                     = vault_mount.pki_int.path
  name                        = "tcn-server"
  issuer_ref                  = vault_pki_secret_backend_issuer.int.issuer_name
  allowed_domains             = ["trinitytechnicalservices.com"]
  allow_subdomains            = true
  allow_bare_domains          = false
  allow_glob_domains          = false
  allow_wildcard_certificates = false
  allow_any_name              = false
  allow_localhost             = false
  enforce_hostnames           = true
  allow_ip_sans               = true
  server_flag                 = true
  client_flag                 = false
  key_type                    = "ec"
  key_bits                    = 384
  ttl                         = 7776000 # 90 days
  max_ttl                     = 7776000
  require_cn                  = true
  no_store                    = false
}
