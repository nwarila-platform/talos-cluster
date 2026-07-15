# vault-config-operator bootstrap ACL policy — THE OWNED, OUT-OF-BAND EXCEPTION.
#
# Applied ONCE by the owner-watched seed (scripts/vault-config/seed-operator-bootstrap.sh),
# NEVER by GitOps and NEVER by the operator itself. This is the bootstrap paradox
# (CP-4 design decision #4): if the operator could rewrite this policy it would
# self-escalate; if it could delete its own role it would self-lock-out. So the
# operator's own identity is excluded from the managed set and seeded out-of-band.
#
# This file is DR-capture + the seed input. It lives DELIBERATELY OUTSIDE the S0
# escalation guard's managed-policy scan scope (apps/vault/vault-config/policies/)
# because it legitimately grants the management-plane paths (sys/policies/acl,
# auth/kubernetes/role, sys/mounts) that the S0 guard is designed to REJECT in a
# *managed* policy. It is NOT a redhatcop Policy CR (a CR would make the operator
# manage it → self-manage → self-escalate). See ADR-0028.
#
# Scope discipline (design control 3): exact-path enumeration per managed object
# for auditability. The management-plane privilege itself is root-equivalent in
# OSS Vault and cannot be bounded by ACL (only Enterprise Sentinel can); it is
# bounded by defense-in-depth — short-TTL k8s-auth (no standing token), a
# restricted-PSA egress-to-Vault-only pod, and the S0 guard on the CONTENT of
# every managed policy — with the residual recorded honestly in ADR-0028.
#
# Capability discipline: real managed objects get [create, read, update] ONLY —
# NO delete until prune is deliberately armed (CP-4 S7, gated on the S6b
# reference-safety guard). Only the throwaway *-smoke objects carry delete, so
# the S3 smoke test can prove the full create/adopt/delete lifecycle without ever
# being able to delete a live object.
#
# NOTE (validated in S3): the exact path set the operator writes is confirmed +
# tightened by the owner-present S3 smoke test against live Vault. If the
# operator needs `sys/mounts` (list) to check mount existence, that read is added
# then (info disclosure only, not escalation).

# --- token lifecycle (token_no_default_policy roles 403 without these) ---
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }

# --- managed ACL policies: sys/policies/acl/<name> (S4 adopt + S5 vault-server) ---
path "sys/policies/acl/tenant-read"           { capabilities = ["create", "read", "update"] }
path "sys/policies/acl/tenant-write"          { capabilities = ["create", "read", "update"] }
path "sys/policies/acl/source-minter-hwg"     { capabilities = ["create", "read", "update"] }
path "sys/policies/acl/vso-org-pull-read-hwg" { capabilities = ["create", "read", "update"] }
path "sys/policies/acl/vso-org-pull-read-nwp" { capabilities = ["create", "read", "update"] }
path "sys/policies/acl/vault-snapshot-backup" { capabilities = ["create", "read", "update"] }
path "sys/policies/acl/vault-server"          { capabilities = ["create", "read", "update"] }

# --- managed k8s-auth roles: auth/kubernetes/role/<name> (S4 adopt + S5 vault-server) ---
path "auth/kubernetes/role/tenant"                { capabilities = ["create", "read", "update"] }
path "auth/kubernetes/role/source-minter-hwg"     { capabilities = ["create", "read", "update"] }
path "auth/kubernetes/role/vso-org-pull-hwg"      { capabilities = ["create", "read", "update"] }
path "auth/kubernetes/role/vso-org-pull-nwp"      { capabilities = ["create", "read", "update"] }
path "auth/kubernetes/role/vault-snapshot-backup" { capabilities = ["create", "read", "update"] }
path "auth/kubernetes/role/vault-server"          { capabilities = ["create", "read", "update"] }

# --- pki-int-tcn intermediate mount + its config/roles (S5; CP-5 serving cert) ---
# sys/mounts is management-plane but NOT sudo-gated for a secrets-engine mount
# (unlike sys/auth, which requires sudo). Scoped to the single mount path.
path "sys/mounts/pki-int-tcn"      { capabilities = ["create", "read", "update"] }
path "sys/mounts/pki-int-tcn/tune" { capabilities = ["create", "read", "update"] }
# Mount-scoped glob: intermediate generate/set-signed, config/urls, issuers, roles.
path "pki-int-tcn/*"               { capabilities = ["create", "read", "update"] }

# --- S3 smoke-test throwaway objects (delete-capable to prove the full
#     create/adopt/delete lifecycle; removable after the S3 GO sign-off) ---
path "sys/policies/acl/vault-config-operator-smoke"     { capabilities = ["create", "read", "update", "delete"] }
path "auth/kubernetes/role/vault-config-operator-smoke" { capabilities = ["create", "read", "update", "delete"] }
path "sys/mounts/pki-vco-smoke"                         { capabilities = ["create", "read", "update", "delete"] }
path "sys/mounts/pki-vco-smoke/tune"                    { capabilities = ["create", "read", "update", "delete"] }
path "pki-vco-smoke/*"                                  { capabilities = ["create", "read", "update", "delete"] }
