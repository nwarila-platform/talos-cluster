# Read-only org-pull source credentials for nwarila-platform (nwp).
# renew-self/lookup-self are REQUIRED: the role sets token_no_default_policy=true,
# so without them VSO gets 403 on auth/token/renew-self and never syncs.
path "secret/data/platform/org-pull/nwp/*" {
  capabilities = ["read"]
}
path "secret/metadata/platform/org-pull/nwp/*" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
