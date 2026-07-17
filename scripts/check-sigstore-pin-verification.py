#!/usr/bin/env python3
"""CP-1 — the sigstore-pin drift detector (first-party offline-verification health).

WHY THIS EXISTS: verify-image-signatures-enforced verifies first-party GHCR
signatures OFFLINE against Sigstore public-good keys pinned in the policy +
scripts/check-image-signature-enforcement.py (rekor.pubkey / ctlog.pubkey /
Fulcio roots). Those pins are SINGLE-VALUED (Kyverno's rekor.pubkey/ctlog.pubkey
take one key each), so if Sigstore rotates a key AND our GitHub-Actions cosign
signing switches to it, a newly-built first-party image's signature would no
longer verify against the stale pin. At AUDIT that surfaces as a PolicyReport
`fail`; at ENFORCE it would fail-closed a pod. The residual must be DETECTED.

WHY SIGNATURE-BASED (not pure-TUF): the live Sigstore TUF root already carries
MORE than one valid tlog/ctlog key at a time (e.g. the 2021 Rekor v1 key our
signatures currently use AND a newer 2025 Rekor v2 key). "A newer key exists in
TUF" is therefore NOT drift — our signatures still use the pinned key. The only
accurate signal is: does a REAL deployed first-party signature still verify
against the pins? Kyverno's background scan answers exactly that every cycle and
records it in the enforced policy's PolicyReport, so this detector reads that
ground truth instead of re-implementing verification or second-guessing TUF.

THE MECHANISM: the daily scheduled scan workflow feeds this script
`kubectl get policyreport,clusterpolicyreport -A -o json` on stdin. Any
verify-image-signatures-enforced result of `fail` or `error` fails the run RED
(a red scheduled workflow is the repo's established zero-red-sweep visibility
surface) — a deployed first-party signature no longer verifies against the pins,
so the pins must be bumped to the current Sigstore keys (or the failing image
investigated). All `pass`/`skip` = the pins are current.

SCOPE (honest): this is REACTIVE — it catches drift once a mismatched image is
deployed and scanned. At Audit that is a non-destructive early warning. Truly
PROACTIVE (catch a rotation before a new-key image is ever deployed) belongs to
the source repos' CI verify-at-ingest (supply-chain doctrine) — booked, not here.

Pure stdin -> exit-code filter (no cluster access) so the selftest drives it with
fixtures. Exit 0 = pins current; 1 = a first-party verification failed (drift);
2 = tooling/usage error (malformed input fails CLOSED).
"""

from __future__ import annotations

import argparse
import json
import sys

ENFORCED_POLICY_NAME = "verify-image-signatures-enforced"
DRIFT_RESULTS = {"fail", "error"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fail if any first-party image no longer verifies against the "
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

    scanned = 0
    passed = 0
    drift: list[str] = []
    for report in items:
        if not isinstance(report, dict):
            raise fail_usage(f"report item is not an object: {report!r}")
        meta = report.get("metadata") or {}
        report_ns = meta.get("namespace", "-")
        results = report.get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            raise fail_usage(
                f"report {report_ns}/{meta.get('name', '?')} has non-list results"
            )
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
            if status in DRIFT_RESULTS:
                drift.append(ident)
            elif status == "pass":
                passed += 1

    if scanned == 0:
        # No first-party images scanned by the enforced policy. Not drift (there
        # may be no first-party workloads at scan time), but surface it so a
        # silently-not-running policy is visible.
        print(
            f"WARN: no '{args.policy_name}' results found in the supplied "
            "PolicyReports (no first-party images scanned, or the policy is not "
            "producing reports). Not treated as drift.",
        )
        return 0

    if drift:
        print(
            f"FAIL: {len(drift)} first-party image(s) no longer verify against "
            f"the pinned Sigstore keys under '{args.policy_name}'. This is "
            "offline-verification DRIFT: our GitHub-Actions cosign signing has "
            "likely rotated to a Sigstore key the single-valued pins do not "
            "cover (e.g. a Rekor v1->v2 tlog-key switch). Runbook: re-source the "
            "current keys from the Sigstore TUF root (cosign initialize) and "
            "bump rekor.pubkey / ctlog.pubkey / roots in "
            "verify-image-signatures-enforced.yaml AND "
            "scripts/check-image-signature-enforcement.py (they must stay "
            "byte-identical), OR investigate the failing image if it is a "
            "genuinely bad signature.",
            file=sys.stderr,
        )
        for ident in drift:
            print(f"  - {ident}", file=sys.stderr)
        return 1

    print(
        f"PASS: all {scanned} '{args.policy_name}' result(s) verify against the "
        f"pinned Sigstore keys ({passed} pass; pins are current)."
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
