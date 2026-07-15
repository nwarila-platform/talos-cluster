# ADR-0029: MVP Stability Contract + Security Floor

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-15                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Low (the contract is deliberately hard to reverse once declared) |
| Review-by      | N/A (Accepted)                          |

## TL;DR

The platform's MVP is defined as a **stability contract**, not just a feature
set: **every breaking change lands BEFORE MVP is declared; after declaration the
consumed surface is locked and only backward-compatible changes are allowed.**
Because imposing them later would break downstream consumers, the **security
floor** — a cluster-wide default-deny CiliumClusterwideNetworkPolicy and
`restricted` Pod Security enforcement — is rolled INTO the MVP scope rather than
deferred. Downstream repos may consume Talos and Vault immediately, provided they
build to the strict contract (restricted-compliant pods + explicit
NetworkPolicies) from day one.

## Context and Problem Statement

Over ~6 weeks the project scope expanded from "deliver a zero-touch tenant" to a
broad platform-hardening + portfolio + self-management program, which buried a
usable MVP under open-ended work. The owner asked, plainly, where the line is
that downstream repositories (Keycloak, an OAuth backend, guild/media services)
can **start consuming** Talos and Vault.

The platform is already live and usable. The blocker is not capability — it is
**stability**: if the consumed surface keeps shifting after downstream repos
build against it, each shift is a breaking change delivered to consumers with no
warning. Two changes we intend to make are especially breaking if done late:

1. **A cluster-wide default-deny network floor** — today networking is
   per-namespace opt-in, so a new namespace is *open by default*. Imposing a
   default-deny floor after consumers deploy breaks their traffic unless it was
   pre-allowlisted.
2. **Tightening Pod Security from `baseline`-enforce to `restricted`-enforce** —
   done late, this breaks any already-deployed workload that is not
   restricted-compliant.

Separately, the Vault serving certificate expires 2026-09-10 with no automated
renewal — the one true *deadline* (distinct from the *contract* question).

## Decision

1. **Stability-contract rule (binding).** MVP is the point at which the consumed
   surface is declared **locked**. All breaking changes MUST land before that
   declaration. Post-MVP changes to the locked surface MUST be
   backward-compatible.

2. **Roll all known breaking changes into MVP.** The MVP scope therefore
   includes, and will not defer: fail-closed image-signature **Enforce** (from
   interim Audit), **per-tenant-scoped** registry credentials (retiring the
   org-wide `ghcr-pull`), the **serving-cert cutover** to cert-manager
   auto-renewal, and the **security floor** below.

3. **Security floor (in MVP).** Before declaring MVP: a cluster-wide default-deny
   `CiliumClusterwideNetworkPolicy` with explicit allowlists, and `restricted`
   Pod Security enforcement cluster-wide. Genuinely-privileged platform
   components (e.g. Longhorn) receive **justified per-namespace exemptions** —
   never a weakened global floor. Both roll out recovery-first, one namespace at
   a time, after a traffic/compatibility audit.

4. **The locked API (frozen at MVP).** Downstream consumers may depend on:
   tenant naming `<org-prefix>-<repo-databaseId>`; Vault consumer paths
   `secret/data/<ns>/{provisioned,state}/*` and `platform/org-pull/<org>/*`;
   SA-name-bound Kubernetes-auth roles (per-org VSO, "Hardened Model A");
   fail-closed signature enforcement on first-party GHCR orgs; cluster-wide
   default-deny networking; and `restricted` Pod Security.

5. **Build downstream now, to the strict contract.** Consumers should build
   restricted-compliant pods with explicit NetworkPolicies from the start, so the
   floor landing is a no-op for them rather than a break. Talos consumption is
   unreserved today; Vault consumption is safe once the cert cutover lands (the
   deadline, ~Aug-11).

6. **Scope discipline.** MVP is otherwise kept lean: the one end-to-end
   touchless-onboarding proof is in scope; the DR restore drill, remaining guard
   work, and further presentation polish are fast-follow, not MVP gates. The
   `[codex]` history rewrite runs dead-last (post-functional, pre-showcase).

## Consequences

- **Downstream repos get a durable contract.** They can build in parallel with
  platform completion instead of waiting, and the locked surface will not shift
  under them post-MVP.
- **MVP is deliberately larger than a minimal feature set.** That is the correct
  consequence of the rule, not scope creep: the security floor and the
  breaking hardening are pulled forward precisely so they are never a late
  surprise.
- **Real rollout work + risk.** default-deny and `restricted`-enforce will trip
  current privileged platform components; each needs an audited allowlist /
  justified exemption and a recovery-first, one-change-at-a-time rollout.
- **Post-MVP change discipline.** Any future change to the locked API must be
  backward-compatible or gated behind a new, explicitly-versioned contract — a
  constraint this ADR deliberately imposes.
- **The cert deadline is unchanged.** The stability contract does not move the
  ~Aug-11 renewal target; it is tracked as the one hard deadline.

## Alternatives Considered

- **Ship a lean MVP now, harden (floor/enforce) later.** Rejected: every later
  hardening step becomes a breaking change delivered to consumers who already
  built — the exact failure the contract exists to prevent.
- **Never impose a security floor; lock the current looser posture as the
  contract.** Rejected by the owner: the strict floor (default-deny +
  `restricted`) is the intended posture, so it must be locked in *before*
  consumers build, not renounced.
- **Keep the full CP-1…CP-9 critical path with no contract framing.** Rejected:
  it delivers the same work but gives downstream consumers no stability
  guarantee and no clear "safe to build on" line.

## References

- `_handoff/ROADMAP.md` §0–§1 (the at-a-glance contract + the locked API list).
- `_handoff/CP4-VAULT-CONFIG-RECONCILER-DESIGN.md` (the Vault-config reconciler that CP-5 rides on).
- [ADR-0025](0025-deliberate-transparency-public-repo.md) (public-repo transparency posture).
- [ADR-0027](0027-fail-closed-first-party-image-admission.md) (fail-closed first-party image admission).
- [Technical Debt Register](../../tech-debt.md) (TD-0008 selector-role gap; TD-0001/0002 supply-chain deferrals).
