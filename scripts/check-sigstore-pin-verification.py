#!/usr/bin/env python3
"""CP-1 — the sigstore-pin drift detector (first-party offline-verification health).

WHY THIS EXISTS: verify-image-signatures-enforced verifies first-party GHCR
signatures OFFLINE against Sigstore public-good keys pinned in the policy +
scripts/check-image-signature-enforcement.py (rekor.pubkey / ctlog.pubkey /
Fulcio roots). Those pins are SINGLE-VALUED (Kyverno's rekor.pubkey/ctlog.pubkey
take one key each), so if Sigstore rotates a key AND our GitHub-Actions cosign
signing switches to it, a newly-built first-party image's signature would no
longer verify against the stale pin. These same four pins are byte-identical in
the single merged ImageValidatingPolicy `verify-first-party`, which now enforces
[Deny]/failurePolicy:Fail. (This script inspects the legacy ClusterPolicy, which
is Audit; that is a proxy for the shared pins, not a claim that this legacy
ClusterPolicy currently denies.) The residual must be DETECTED because stale
pins now fail-close first-party admission for new signatures.

WHY SIGNATURE-BASED (not pure-TUF): the live Sigstore TUF root already carries
MORE than one valid tlog/ctlog key at a time (e.g. the 2021 Rekor v1 key our
signatures currently use AND a newer 2025 Rekor v2 key). "A newer key exists in
TUF" is therefore NOT drift — our signatures still use the pinned key. The only
accurate signal is: does a REAL deployed first-party signature still verify
against the pins? Kyverno's background scan answers exactly that every cycle and
records it in the guard-pinned policy's PolicyReport, so this detector reads that
ground truth instead of re-implementing verification or second-guessing TUF.

THE MECHANISM: the daily scheduled scan workflow feeds this script
`kubectl get clusterpolicies.kyverno.io,policyreports.wgpolicyk8s.io,\
clusterpolicyreports.wgpolicyk8s.io -A -o json` on stdin. It fails the run RED
(the repo's established zero-red-sweep visibility surface) on EITHER:
  (a) the guard-pinned ClusterPolicy is MISSING or not Ready — it is verifying
      nothing, so an absence of `fail` results is meaningless (closes the
      "policy deleted/broken => silent green" blind spot; a WARN on a green run
      is invisible in a zero-red model); OR
  (b) any guard-pinned policy result is not `pass`/`skip` (fail-closed allowlist:
      `fail` and `error` and any future/unexpected status all count as drift —
      a deployed first-party signature no longer verifies against the pins, so
      the pins must be bumped to the current Sigstore keys or the failing image
      investigated).
A healthy, Ready policy with simply no first-party workloads scanned is a
legitimate PASS.

SCOPE (honest): this is REACTIVE — it catches drift once a mismatched image is
deployed and scanned. It reads the Audit-mode legacy ClusterPolicy, but the pins it
checks are the same ones in the current [Deny]/Fail `verify-first-party` IVP — so
treat a hit as current fail-closed admission risk, not a non-destructive warning. Truly
PROACTIVE (catch a rotation before a new-key image is ever deployed) belongs to
the source repos' CI verify-at-ingest (supply-chain doctrine) — booked, not here.

Pure stdin -> exit-code filter (no cluster access) so the selftest drives it with
fixtures. Exit 0 = policy healthy + pins current; 1 = policy missing/not-Ready OR
a first-party verification failed (drift); 2 = tooling/usage error (malformed
input fails CLOSED).
"""

from __future__ import annotations

import argparse
import json
import sys

ENFORCED_POLICY_NAME = "verify-image-signatures-enforced"
CLUSTERPOLICY_KIND = "ClusterPolicy"
# Fail-closed ALLOWLIST: only these enforced-policy result statuses are safe.
# Everything else (fail, error, warn, null, any future status) is treated as
# drift, so an unexpected verification status can never silently pass.
SAFE_RESULTS = {"pass", "skip"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fail if the guard-pinned first-party signature policy is missing/not "
            "Ready, or if any first-party image no longer verifies against the "
            "pinned Sigstore keys (offline-verification drift)."
        )
    )
    parser.add_argument(
        "--policy-name",
        default=ENFORCED_POLICY_NAME,
        help=f"enforced policy name to inspect (default: {ENFORCED_POLICY_NAME})",
    )
    return parser.parse_args()


def fail_usage(message: str) -> SystemExit:
    print(f"ERROR: {message}", file=sys.stderr)
    return SystemExit(2)


def policy_is_ready(item: dict) -> bool:
    conditions = ((item.get("status") or {}).get("conditions")) or []
    for cond in conditions:
        if isinstance(cond, dict) and cond.get("type") == "Ready":
            return cond.get("status") == "True"
    return False


def main() -> int:
    args = parse_args()
    raw = sys.stdin.read()
    if not raw.strip():
        raise fail_usage("no input on stdin (expected kubectl get -o json output)")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise fail_usage(f"stdin is not valid JSON: {exc}")
    items = data.get("items")
    if not isinstance(items, list):
        raise fail_usage("input has no items list (expected a kubectl List)")

    enforced_present = False
    enforced_ready = False
    scanned = 0
    passed = 0
    drift: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise fail_usage(f"list item is not an object: {item!r}")
        meta = item.get("metadata") or {}
        if item.get("kind") == CLUSTERPOLICY_KIND and meta.get("name") == args.policy_name:
            enforced_present = True
            enforced_ready = policy_is_ready(item)
            continue
        results = item.get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            raise fail_usage(
                f"report {meta.get('namespace', '-')}/{meta.get('name', '?')} "
                "has non-list results"
            )
        report_ns = meta.get("namespace", "-")
        for result in results:
            if not isinstance(result, dict):
                raise fail_usage(f"result is not an object: {result!r}")
            if result.get("policy") != args.policy_name:
                continue
            scanned += 1
            status = result.get("result")
            res_list = result.get("resources") or [{}]
            first = res_list[0] if res_list else {}
            ident = (
                f"{result.get('rule', '?')} -> "
                f"{first.get('namespace', report_ns)}/{first.get('name', '?')} "
                f"[{status}]"
            )
            if status in SAFE_RESULTS:
                if status == "pass":
                    passed += 1
            else:
                drift.append(ident)

    # Policy-health gate: a missing or not-Ready enforced policy verifies NOTHING,
    # so an absence of `fail` results is meaningless -> fail RED (BS-1a). This is
    # checked BEFORE the drift/empty-scan branches so a broken policy can never
    # masquerade as "pins current".
    if not enforced_present:
        print(
            f"FAIL: enforced policy '{args.policy_name}' is NOT PRESENT in the "
            "supplied ClusterPolicies. First-party signatures are being verified "
            "by NOTHING (or the policy was deleted). Restore it (Flux reconciles "
            "clusters/talos-cluster/apps/kyverno/policies) before trusting any "
            "offline-verification result.",
            file=sys.stderr,
        )
        return 1
    if not enforced_ready:
        print(
            f"FAIL: enforced policy '{args.policy_name}' is present but NOT Ready "
            "(status.conditions Ready != True). Kyverno is not enforcing/scanning "
            "it, so drift cannot be observed. Investigate the policy + Kyverno.",
            file=sys.stderr,
        )
        return 1

    if drift:
        print(
            f"FAIL: {len(drift)} first-party image(s) no longer verify against "
            f"the pinned Sigstore keys under '{args.policy_name}' (result not "
            "pass/skip). This is offline-verification DRIFT: our GitHub-Actions "
            "cosign signing has likely rotated to a Sigstore key the "
            "single-valued pins do not cover (e.g. a Rekor v1->v2 tlog-key "
            "switch). Runbook: re-source the current keys from the Sigstore TUF "
            "root (cosign initialize) and bump rekor.pubkey / ctlog.pubkey / "
            "roots in verify-image-signatures-enforced.yaml AND "
            "scripts/check-image-signature-enforcement.py (they must stay "
            "byte-identical), OR investigate the failing image if it is a "
            "genuinely bad signature or a transient registry/error status.",
            file=sys.stderr,
        )
        for ident in drift:
            print(f"  - {ident}", file=sys.stderr)
        return 1

    if scanned == 0:
        print(
            f"PASS: enforced policy '{args.policy_name}' is present + Ready; no "
            "first-party images were scanned (no first-party workloads at scan "
            "time). Nothing to drift-check, and the policy is confirmed healthy."
        )
        return 0

    print(
        f"PASS: enforced policy '{args.policy_name}' is Ready and all {scanned} "
        f"result(s) verify against the pinned Sigstore keys ({passed} pass; pins "
        "are current)."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — tooling failures must exit 2
        print(f"ERROR: tooling failure: {exc!r}", file=sys.stderr)
        sys.exit(2)
