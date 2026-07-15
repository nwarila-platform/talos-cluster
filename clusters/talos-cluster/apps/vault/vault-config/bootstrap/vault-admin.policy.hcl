# vault-admin ACL policy — BREAK-GLASS ADMIN CAPTURE (out-of-band, DR material).
#
# This is the policy attached to the durable recovered admin token minted by
# the 2026-07-14 generate-root break-glass (VAULT-LIVE-ADMIN-RECOVERY-RUNBOOK).
# Captured 2026-07-15 from live `sys/policies/acl/vault-admin` (owner decision:
# capture out-of-band, bootstrap-class).
#
# WHITESPACE (declared, grant-identical): the live policy ends in a single
# stray CRLF (a Windows-authoring artifact, same class as the S4a tenant-write
# capture); it is written here with a normalized LF ending. The grants are
# byte-identical to live; a break-glass re-apply of this file harmlessly
# rewrites live's trailing byte to LF. If the live policy changes deliberately,
# re-capture it here in the same PR that records why.
#
# NEVER operator-managed, NEVER GitOps-applied (same paradox class as the
# vault-config-operator identity, ADR-0028): if the reconciler — or any git
# commit — could rewrite this policy, a repo compromise could neuter or hijack
# the break-glass identity. Enforced by
# scripts/check-vault-config-operator-bootstrap-invariants.py (protected
# identity set). Re-applied only by the owner during a break-glass ceremony.
#
# The capability content below is deliberately admin-grade; it is OUTSIDE the
# S0 managed-policy allowlist scan scope by design (bootstrap/ dir).
path "sys/health"            { capabilities = ["read"] }
path "sys/seal-status"       { capabilities = ["read"] }
path "sys/mounts"            { capabilities = ["read","list"] }
path "sys/storage/raft/configuration" { capabilities = ["read"] }
path "sys/policies/acl/*"    { capabilities = ["create","read","update","delete","list"] }
path "auth/*"                { capabilities = ["create","read","update","delete","list","sudo"] }
path "secret/*"              { capabilities = ["create","read","update","delete","list"] }

path "sys/mounts/pki-int-tcn*" { capabilities = ["create","read","update","delete"] }

path "pki-int-tcn/*" { capabilities = ["create","read","update","delete","list"] }

path "sys/storage/raft/snapshot" { capabilities = ["read"] }

path "sys/auth/kubernetes*" { capabilities = ["create","read","update","delete","list","sudo"] }
path "auth/kubernetes/*" { capabilities = ["create","read","update","delete","list","sudo"] }
path "sys/mounts/herowars-kv*" { capabilities = ["create","read","update","delete","list"] }
path "herowars-kv/*" { capabilities = ["create","read","update","delete","list"] }
path "sys/policies/acl/engine-porter-rw" { capabilities = ["create","read","update","delete","list"] }
path "sys/quotas/rate-limit/*" { capabilities = ["create","read","update","delete","list"] }
