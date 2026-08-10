# ADR-0030: Per-Org Source-Token Minter — Shared Script, Per-Org Identity

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-20                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | Two independent adversarial audits (see References) |
| Informed       | None.                                   |
| Reversibility  | Medium (the envelope is per-org and additive; the KV layout in TD-0012 is not) |
| Review-by      | N/A (Accepted)                          |

## TL;DR

GitOps source tokens are minted per organization. Every organization gets its **own**
ServiceAccount, ClusterRole/Binding, CronJob, Vault ACL policy, and Vault Kubernetes-auth
role. All of them share **one** minter script, because the script is entirely env-driven and
duplicating a credential-minting program invites drift in the artifact least able to afford it.

The security boundary between organizations is **not** the script's contents. It is Vault's
Kubernetes-auth role binding an exact ServiceAccount name — which a pod cannot forge — plus
per-org policy scoping of the App key, plus GitHub App installations covering only their own
org's repositories. That boundary is **asymmetric**, and this ADR exists partly to record the
asymmetry: it is structural for `VAULT_ROLE` and `VAULT_KEY_PATH`, and **absent for
`ORG_LABEL`**.

A CI guard that policed the shared script's *source* for hardcoded organizations was written,
audited, and **withdrawn**. It is recorded here because the reasoning generalizes.

## Context and Problem Statement

Before this change exactly one organization (`hwg`) could mint GitOps source tokens.
Onboarding `nwp` required a second minter. The shared-script design raised an obvious
question: if only environment variables decide which organization the script acts as, what
stops a misconfigured CronJob from minting for the wrong one?

The intuitive answer — "inspect the script in CI and forbid organization defaults" — was
implemented. Two independent adversarial audits then established that it was the wrong answer
on three separate counts, and it was removed.

## Decision

### 1. Per-org envelope, one shared script

Per organization: `serviceaccount-<prefix>`, `clusterrole-<prefix>`,
`clusterrolebinding-<prefix>`, `cronjob-<prefix>`, a managed `Policy`, and a managed
`KubernetesAuthEngineRole`. Shared: the `source-rotator-script` ConfigMap and the `vault-ca`
trust anchor.

Each organization gets its **own** ClusterRole and binding rather than sharing one. A
`ClusterRoleBinding`'s `roleRef` is immutable, so re-pointing an existing binding at a renamed
shared role makes Flux's server-side apply fail on an immutable field and stall the
reconcile. Duplicating a two-verb read-only rule is the cheaper trade; the artifact that must
**not** be duplicated is the minter script.

### 2. The real boundary, and its asymmetry

| Variable | Wrong value is caught by | Strength |
| --- | --- | --- |
| `VAULT_ROLE` | Vault TokenReview against `bound_service_account_names` | **Structural.** The pod's ServiceAccount comes from `serviceAccountName`, not from env, and cannot be forged from inside the pod. Vault denies the cross-org value. |
| `VAULT_KEY_PATH` | the authenticated role's own ACL policy | **Structural.** Whatever role authenticates can read only its own organization's App key. |
| `ORG_LABEL` | GitHub declining to mint | **Contingent — not a boundary.** |

`ORG_LABEL` affects neither authentication nor the key read. It only selects which tenant
namespaces are minted for. A wrong value is caught only if GitHub refuses the mint, and that
refusal is not guaranteed: the mint sends a **bare repository name** (it comes from the
`nwarila.io/deploy-repo` label, and a Kubernetes label value cannot contain a slash), which
GitHub resolves inside the minter's *own* installation. Where a same-named repository exists
there, the mint succeeds and the token is written into the other organization's tenant leaf,
logging `OK`. A label matching no tenants exits zero as a no-op.

This is tracked as **TD-0012**, with two triggers — a compromised policy holder **and** an
accidental onboarding copy-paste — and two impacts: denial of service, and cross-org
credential *placement* (one org's token deposited where another org's VSO will sync it into a
readable Secret).

### 3. Fail-fast env reads are hygiene, not a control

The shared script reads its three org-selecting variables via subscript so a missing variable
raises rather than defaults. This is worth keeping and worth not regressing. It is **not** what
prevents cross-org minting, and no document in this repository should imply that it is.

### 4. A source-policing CI guard was attempted and withdrawn

It checked that the script read its variables fail-fast, that no defaulting accessor touched
them, and that no organization appeared as a literal. Adversarial review found:

- **It was not sound.** Bypasses existed along every axis probed — decorators, name rebinding,
  import aliasing, runtime-constructed keys, `.yml` files, subdirectories, `kind: List`
  envelopes, init containers, and kustomize patch files.
- **It was actively harmful.** It rejected legitimate code: `from os import environ`, a helper
  that post-processes a value, keyword-argument calls, loop-driven reads, env supplied by
  `valueFrom`/`envFrom`, kustomize patch files, and — worst — the script documenting or
  validating its own organization boundary.
- **It was blind to the only reachable risk.** Against a copy-pasted `ORG_LABEL`, its
  role/key-path consistency rule passed (both values were self-consistent) and its
  organization-registration rule passed (the wrong org's name is still a registered
  organization). It would have reported green on precisely the misconfiguration that produces
  the cross-org write.

A control that is bypassable, blocks honest work, **and** does not cover the real residual is
worse than no control, because it dilutes trust in the guards that do work.

Withdrawing it does cost something: there is now no automated regression signal for the
fail-fast property. That is accepted. If automation is wanted later, the correct shape is a
**behavioural** test — run the minter with a variable unset and assert it exits non-zero —
not source-pattern matching.

## Consequences

- **Onboarding an organization is deliberately not touchless.** It requires a reviewed
  registration and an owner-watched, out-of-band Vault seed, because the operator's bootstrap
  policy enumerates paths by name and gains two lines per organization. That policy is applied
  outside GitOps by design (ADR-0028). The procedure is `docs/runbooks/onboard-organization.md`.
- **Seed before merge.** The operator cannot write a policy it has not been granted. Merging
  first leaves the new CRs unreconciled, takes `vault-config-managed` NotReady at its health
  timeout, and freezes `vault-tls-cm` behind its `dependsOn`. Certificate renewal is
  unaffected and the root Kustomization does not stall.
- **The shared script raises change blast radius.** A bad edit breaks every organization at
  once. Accepted: that failure is red Jobs, whereas duplicated copies drift silently.
- **TD-0012 remains open** and is the real security residual of this design. Its preferred
  closure — re-laying tenant KV under an org-owned parent segment — would make the cross-org
  write inexpressible regardless of `ORG_LABEL`, which no amount of source inspection can
  achieve.
- **The Kyverno tamper-protection policy matches by wildcard**, so a newly onboarded rotator
  is protected on creation rather than depending on someone remembering to enumerate it. That
  policy raises the bar against non-platform actors; Flux's kustomize-controller and
  `cluster-admin` are excluded, so it is not a control against either.
- **The guard manifest now fails on an unlisted guard**, not merely a stale line count.
  Refreshing figures for rows that exist could never notice a guard nobody listed.

## Alternatives Considered

- **A per-org copy of the minter script.** Rejected: two copies of a credential-minting
  program drift, and the drift is invisible until it issues the wrong credential.
- **Keep hardening the source-policing guard.** Rejected: a syntactic checker over a Python
  program embedded in YAML cannot be made sound against a determined author, and any in-repo
  guard can be edited by the same pull request that breaks what it guards. Each round of
  hardening traded one hole for another while blocking honest patterns.
- **Narrow the cross-org write grant now.** Rejected for this change: Vault ACL cannot express
  the intended scope (`*` is legal only as a path's final character; `+` matches exactly one
  whole segment), so the only expressible alternatives trade a narrow leaf for a wider subtree.
  Booked as TD-0012 rather than half-fixed.
- **Assert the tenant namespace prefix inside the minter.** Deferred, not rejected: it would
  close the accidental trigger cheaply, but it does nothing for the compromised-holder trigger
  and therefore complements rather than replaces the TD-0012 re-layout.

## References

- `docs/runbooks/onboard-organization.md` — the procedure, and what fails silently if skipped
- `docs/tech-debt.md` — TD-0012, both triggers and both impacts
- [ADR-0011]: convention discovery of deploy repositories
- [ADR-0028]: the vault-config-operator bootstrap identity, applied out-of-band
- Adversarial review: two independent auditors across several rounds, plus a parallel
  bypass sweep whose findings drove the withdrawal in §4

[ADR-0011]: 0011-auto-discover-deploy-repositories.md
[ADR-0028]: 0028-vault-config-operator-bootstrap-identity.md
