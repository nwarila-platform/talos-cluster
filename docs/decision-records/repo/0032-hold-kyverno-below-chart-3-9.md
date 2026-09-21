# ADR-0032: Hold Kyverno Below Chart 3.9.0

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-09-21                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | Six-round P2 adversarial pre-execute audit |
| Informed       | None.                                   |
| Reversibility  | High                                    |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Remain below chart 3.9.0; 3.8.x stays Renovate-eligible. Security and fix
releases in 3.9.x and every later line are blocked for as long as the hold
stands, while 3.8.x patches remain eligible. The rule does not constrain the
chart's `appVersion`.

Accept an average of roughly 22 reports-controller restarts per day since
2026-07-17 — about one per 1.1 hours on average, occurring episodically rather
than at a steady cadence — rather than upgrade into a defect proven at library
level to hang on `[h,h,v]`, with the live-admission likelihood kept explicitly
unproven.

## Context and Problem Statement

Kyverno v1.18.2 pins `kyverno/sdk` commit `3c70db82e2e4`. Its
`extensions/imagedataloader/context.go` starts `AddImages` workers that write
the shared `idc.list` map without synchronization between them, and `Get`
returns from a cache hit without releasing its read lock. The race detector
reproduces the first defect, including the live controller's `fatal error:
concurrent map writes` crash form, and a focused SDK test proves `[h,h,v]`
hangs on the second.

Kyverno v1.19.1 pins SDK commit `68d74afcb07a`. It no longer calls `AddImages`,
but its pinned SDK retains the `Get` defect. It builds its prefetch list by
ranging an image-category map and then calls `Get` serially. A live Vault pod
repeats the helper image across two init containers and also has the Vault
image, so a Vault request CAN present `[h,h,v]`. The frequency of that ordering
and an in-cluster Vault denial on v1.19.1 are UNPROVEN. Chart 3.9.0, which ships
app v1.19.0, also predates the v1.19.1 workaround in
kyverno/kyverno#17327.

The first-party ImageValidatingPolicy uses `failurePolicy: Fail`, so a request
that hangs on this path can become an admission denial rather than only a
delay. Meanwhile the deployed v1.18.2 controllers crash repeatedly, and a
webhook EOF has already blocked a Vault Flux reconciliation until an explicit
retry.

## Decision

### Hold boundary

Add a Flux Helm package rule with `allowedVersions: "<3.9.0"`. This is a
ceiling over every chart release at or above 3.9.0, not a freeze on 3.9.x alone
and not a pin to chart 3.8.2. Later 3.8.x releases, including security patches,
remain Renovate-eligible. Security and fix releases in 3.9.x and every later
line are blocked while the hold stands. The rule does not constrain a chart's
`appVersion`. The comparator `<3.9.0` excludes semver prereleases by itself:
npm-style range satisfaction does not admit a prerelease unless the range
names one. This covers `3.9.0-rc.4` and prereleases of otherwise-allowed 3.8.x
lines. Renovate's default `ignoreUnstable: true` is therefore a redundant
second filter here, not the basis of prerelease coverage; setting it to
`false` would not weaken the hold. Only `includePrerelease: true` would admit
prereleases through the range.

Renovate removes the actionable blocked-update entry from the dependency
dashboard after applying `allowedVersions`. Keep the hold visible with the
top-level `dependencyDashboardFooter` linked to TD-0023.

### Removal condition

Lift the hold only when the newest stable Kyverno chart above the current pin
has an app version whose `go.mod` pins a `kyverno/sdk` commit in which
`extensions/imagedataloader/context.go` both releases the read lock on every
`Get` cache-hit return path and performs no `idc.list` write inside an
`AddImages` worker closure. A fixed older candidate is not sufficient, because
removing an unbounded ceiling would also expose a newer defective line.

Checking this condition is manual until Piece 2 adds the expiry detector.

## Consequences

- Flux reconciles can still fail intermittently and self-heal on retry. There
  is NO alerting on that behavior: the standing zero-alerting gap remains.
- Security and fix releases in 3.9.x and every later line cannot be selected
  while the hold stands. Later 3.8.x patches remain eligible, and
  `appVersion` remains unconstrained.
- The actionable blocked-update entry disappears from the dependency
  dashboard. The footer preserves a visible, linked record of the hold.
- Removal-condition checks can be missed or become stale until Piece 2 lands;
  no machine-checkable expiry exists in this piece.
- No repository guard couples the rule's matcher to the dashboard footer.
  Matcher drift can silently stop the hold from matching while the config
  validator and current Renovate coverage guard remain green and the footer
  still asserts an active hold. Detecting this belongs to Piece 2, the expiry
  detector, alongside automating the manual removal-condition check.

## Alternatives Considered

- **Upgrade to 3.9.x now.** Rejected: defect 2 remains unfixed in the SDK pinned
  by Kyverno v1.19.1, while chart 3.9.0 predates even the workaround that stops
  calling `AddImages`.
- **Retire `verify-image-signatures-enforced`.** Rejected for now, not
  permanently. It is the only first-party legacy `ClusterPolicy` path that,
  through Kyverno's Pod handling, covers the `pods/ephemeralcontainers`
  admission subresource; the ImageValidatingPolicy itself declares only
  `resources: ["pods"]`. `verify-image-signatures.yaml` is a separate legacy
  Pod image policy for third-party families. The repository already plans this
  retirement, but it remains blocked until first-party ephemeral-subresource
  coverage and the PolicyReport-based pin detector are migrated.
- **Set `background: false` on the image policies.** Rejected: this does not
  remove admission or subresource coverage; it changes background scanning and
  report production. The drift detector reads results whose `policy` equals
  `verify-image-signatures-enforced`, and the source guard pins
  `background: true` for both named legacy image `ClusterPolicy` resources.
- **Run a patched first-party Kyverno build.** Rejected for now because it
  means owning a fork of an admission controller. Revisit if upstream stalls.

## References

- [TD-0023](../../tech-debt.md#td-0023--kyverno-chart-held-below-390)
- [Renovate configuration](../../../.github/renovate.json5)
- `clusters/talos-cluster/apps/kyverno/policies/ivp-verify-first-party.yaml:84-101`
- `clusters/talos-cluster/apps/kyverno/policies/verify-image-signatures.yaml:30-61`
- `clusters/talos-cluster/apps/kyverno/policies/verify-image-signatures-enforced.yaml:3-6`
- `scripts/README.md:29`
- `scripts/check-sigstore-pin-verification.py:120-151`
- `scripts/check-image-signature-enforcement.py:196-199,1730-1742`
- [kyverno/sdk#123](https://github.com/kyverno/sdk/issues/123) and closed,
  unmerged fix [PR #124](https://github.com/kyverno/sdk/pull/124)
- [kyverno/sdk#125](https://github.com/kyverno/sdk/issues/125)
- [kyverno/sdk PR #127](https://github.com/kyverno/sdk/pull/127)
- [kyverno/kyverno#17327](https://github.com/kyverno/kyverno/pull/17327)
