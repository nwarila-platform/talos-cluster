# B-apex source-minter (hwg). Reads ONLY the hwg org App key (per-org read split),
# mints per-repo contents:read GitHub tokens, and WRITES them to the per-tenant
# source-auth leaf. Deliberately NO read on provisioned/* data and NEITHER tenant-read
# NOR tenant-write: a compromised minter cannot pivot into any tenant secret/state bucket.
# The write path is broad across tenants by necessity (Vault cannot prefix-glob the ns
# segment), but bounded: this identity can only MINT hwg-repo READ tokens, so the worst
# case is a same-scope DoS, never cross-org exfiltration or repo write.
path "secret/data/platform/org-pull/hwg/gitops-source-auth" { capabilities = ["read"] }
# kv-v2 cas (check-and-set) version lookup for the rotation write. Exposes version
# metadata ONLY — never the token value, and not any other provisioned secret.
path "secret/metadata/+/provisioned/source-auth"            { capabilities = ["read"] }
path "secret/data/+/provisioned/source-auth"                { capabilities = ["create", "update"] }
# token_no_default_policy=true trap: must self-manage its own token (see the
# vso_token_renew_self_policy lesson: omit these and VSO/CronJob 403s on renew).
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
