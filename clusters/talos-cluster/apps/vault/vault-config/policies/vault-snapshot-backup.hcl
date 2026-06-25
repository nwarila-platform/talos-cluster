# Least-privilege DR snapshot identity - Raft snapshot READ only. NEVER vault-admin.
path "sys/storage/raft/snapshot" { capabilities = ["read"] }

# token_no_default_policy roles need these or VSO/token renewal 403s.
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
