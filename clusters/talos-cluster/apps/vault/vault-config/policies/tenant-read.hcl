path "secret/data/{{identity.entity.aliases.auth_kubernetes_fc0d86cb.metadata.service_account_namespace}}/provisioned/*" {
  capabilities = ["read"]
}
# token_no_default_policy=true on the `tenant` role: VSO must self-renew/lookup its
# login token or it 403s and never syncs (see vso_token_renew_self_policy). The
# `tenant` role attaches tenant-read + tenant-write; granting these on either suffices.
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
