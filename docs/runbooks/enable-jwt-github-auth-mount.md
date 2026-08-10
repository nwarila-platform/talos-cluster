# Runbook: Enable the `jwt-github` Vault Auth Mount

**Scope.** This is the one owner-only AR4a-2 ceremony that must run before the
AR4a-1 draft PR can merge. It enables the Vault JWT auth mount and re-seeds the
vault-config-operator bootstrap policy with the complete, already-reviewed
GitHub-OIDC grant set. It does not create a consumer role, policy, or secret.

**Hard gate: the AR4a-1 PR must not be merged until this ceremony has completed
against its exact immutable head. The OWNER runs this ceremony and the OWNER
merges that exact tree.** The implementation loop must not merge it, enable
auto-merge, or move the PR head after the ceremony.

## Why this is owner-only

Vault gates `sys/auth/*` with the `sudo` capability. That capability enables
auth-method lifecycle operations and is deliberately absent from the
vault-config-operator bootstrap identity. The operator may configure
`auth/jwt-github/config` only after the mount exists; allowing it to create auth
mounts would turn a scoped reconciler into a general authentication-plane
administrator.

The bootstrap policy is the same out-of-band exception recorded by
[ADR-0028](../decision-records/repo/0028-vault-config-operator-bootstrap-identity.md).
Git authors the exact HCL, but Flux and the operator never apply it. The owner
re-seeds it with a short-lived admin token using the byte-verifying seed script.

## Preconditions and evidence packet

Do this in one bounded sitting. Stop if any item is false:

1. The PR is still a **Draft**, auto-merge is disabled, CI is green and
   up-to-date, and the owner has approved the exact diff.
2. Record the PR URL, immutable `headRefOid`, and current `main` SHA. The latter
   is the rollback tree.
3. Record the SHA-256 of
   `clusters/talos-cluster/apps/vault/vault-config/bootstrap/vault-config-operator.policy.hcl`.
4. Confirm that parsing every file recursively discovered under `managed/`
   whose name ends case-insensitively in `.yaml` or `.yml` (including files
   named literally `.yaml` or `.yml`), then recursively descending `kind: *List`
   envelopes, yields no mapping with
   `kind: JWTOIDCAuthEngineRole`. The check fails closed if `managed/` is
   missing or a discovered file is unreadable, invalid YAML, or contains a
   non-mapping top-level document. Files whose names do not end
   case-insensitively in `.yaml` or `.yml` (including extensionless names and
   `.json`) and files outside `managed/` reached through cross-root `resources:`
   are not parsed by this precondition; those surfaces are tracked in TD-0016.
   AR4a is foundation only.
5. Use a short-TTL admin token. Never use or print a standing root token.

```bash
PR_URL=https://github.com/nwarila-platform/talos-cluster/pull/NNN
gh pr view "${PR_URL}" \
  --json isDraft,autoMergeRequest,headRefOid,mergeStateStatus,statusCheckRollup

PR_HEAD_SHA="$(gh pr view "${PR_URL}" --json headRefOid --jq .headRefOid)"
PRIOR_MAIN_SHA="$(git rev-parse origin/main)"
git fetch origin
git checkout --detach "${PR_HEAD_SHA}"
test "$(git rev-parse HEAD)" = "${PR_HEAD_SHA}"

BOOTSTRAP_HCL=clusters/talos-cluster/apps/vault/vault-config/bootstrap/vault-config-operator.policy.hcl
BOOTSTRAP_HCL_SHA256="$(sha256sum "${BOOTSTRAP_HCL}" | awk '{print $1}')"
printf 'PR head: %s\nPrior main: %s\nBootstrap HCL SHA-256: %s\n' \
  "${PR_HEAD_SHA}" "${PRIOR_MAIN_SHA}" "${BOOTSTRAP_HCL_SHA256}"

python3 - <<'PY'
from pathlib import Path

import yaml


def _flatten_docs(docs):
    """Descend kind:List envelopes recursively."""
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        items = doc.get("items")
        if isinstance(kind, str) and kind.endswith("List") and isinstance(items, list):
            yield from _flatten_docs(items)
            continue
        yield doc


managed = Path("clusters/talos-cluster/apps/vault/vault-config/managed")
if not managed.is_dir():
    raise SystemExit(f"precondition failed: managed directory is missing: {managed}")
paths = sorted(
    path
    for path in managed.rglob("*")
    if path.name.casefold().endswith((".yaml", ".yml")) and path.is_file()
)
for path in paths:
    try:
        raw = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise SystemExit(f"precondition failed: cannot parse {path}: {exc}")
    if any(doc is not None and not isinstance(doc, dict) for doc in raw):
        raise SystemExit(f"precondition failed: {path} contains a non-mapping YAML document")
    if any(
        doc.get("kind") == "JWTOIDCAuthEngineRole"
        for doc in _flatten_docs(raw)
    ):
        raise SystemExit(f"precondition failed: {path} contains JWTOIDCAuthEngineRole")
PY
```

Save those three identifiers in the ceremony record before proceeding. The
owner must merge exactly `PR_HEAD_SHA`; a rebase, force-push, or follow-up commit
invalidates the ceremony and requires a fresh review and re-run.

## Ceremony

The first command is the sole `sudo`-gated act. The second performs the single
combined re-seed: config create/read/update plus the two `deploy-*`
create/read/update/delete grants. Do not split it into multiple seeds.

```bash
vault auth enable -path=jwt-github jwt

REVOKE_TOKEN_AFTER=true \
  scripts/vault-config/seed-operator-bootstrap.sh
```

The seed script reads the checked-out HCL, writes the policy, reads it back, and
fails unless the live body is byte-identical. It does not print either secret
material or the policy body.

## Verify and freeze the head

Capture only non-secret output:

```bash
vault auth list -format=json \
  | jq -e '."jwt-github/".type == "jwt"'

sha256sum "${BOOTSTRAP_HCL}"
test "$(git rev-parse HEAD)" = "${PR_HEAD_SHA}"

gh pr view "${PR_URL}" \
  --json isDraft,autoMergeRequest,headRefOid,mergeStateStatus,statusCheckRollup
```

The evidence record must show:

- `jwt-github/` exists with type `jwt`;
- the seed script's byte-verification succeeded;
- the local HCL digest still equals `BOOTSTRAP_HCL_SHA256`;
- the PR remains a draft, has no auto-merge request, and still points at
  `PR_HEAD_SHA`;
- required checks remain green and up-to-date.

Freeze the head now. In the same sitting, the owner may mark the PR ready and
**the OWNER merges it**. Do not delegate the merge to the implementation loop
or enable auto-merge.

## Expected reconciliation

After the owner merges the exact tree, Flux applies the config CR. Both
prerequisites are explicit:

- if the mount is absent, the operator write fails;
- if the bootstrap config grant is absent, the operator write returns a
  permission error.

In either case the generation-aware `JWTOIDCAuthEngineConfig` health expression
never sees a current-generation `ReconcileSuccessful=True`, so
`vault-config-managed` times out NotReady rather than presenting the failed
reconcile as healthy. Once both prerequisites exist, the controller's normal
retry converges automatically; no CR edit is required.

## Abort before merge

If the exact `PR_HEAD_SHA` cannot be merged in the same sitting, do not
substitute another tree:

1. Keep the PR unmerged.
2. Verify `vault list auth/jwt-github/role` returns no keys (`No value found`
   also means no role collection exists). Any role is a stop condition requiring
   investigation.
3. Disable the otherwise-unused mount.
4. Check out `PRIOR_MAIN_SHA` and re-seed its prior bootstrap HCL.
5. Record the abort and both HCL digests. A replacement head requires a new
   review and ceremony.

```bash
vault list auth/jwt-github/role
# Continue only with an empty list or "No value found".
vault auth disable jwt-github

git checkout --detach "${PRIOR_MAIN_SHA}"
REVOKE_TOKEN_AFTER=true \
  scripts/vault-config/seed-operator-bootstrap.sh
```

## Rollback after merge

Rollback order matters because the v0.8.49 config CR is non-deletable: pruning
the CR does not erase the Vault-side config.

1. Remove and settle every `JWTOIDCAuthEngineRole` first.
2. Remove the `JWTOIDCAuthEngineConfig` and let Flux prune its CR.
3. The owner confirms no `auth/jwt-github/role/*` entries remain.
4. The owner disables `jwt-github`; disabling the mount removes its retained
   config.
5. Remove `vault-egress-github-oidc`.
6. Re-seed the bootstrap HCL with the retired three-stanza grant set removed.

Disabling the mount while the config CR remains is not a rollback: it creates an
expected retry/NotReady loop because the operator continues writing the absent
mount. Conversely, re-establishing both prerequisites lets reconciliation
converge automatically.

Existing batch tokens cannot be revoked and remain valid until their bounded
TTL expires. Old GitHub run re-runs may re-authenticate while a role still
exists. AR4a itself creates no role, so the foundation delivers no
authentication until a later owner-merged consumer onboarding PR adds one.
