#!/usr/bin/env python3
"""CP-4 S7 — the #133 stuck-Terminating detector (the real prune mitigation).

WHY THIS EXISTS (source-verified at kustomize-controller v1.9.1, S7 round-1
audit): Flux prune is fire-and-forget — the apiserver ACCEPTS a DELETE of a
finalizer-bearing object (sets deletionTimestamp, returns 200), pkg/ssa
records a successful DeletedAction, the object leaves status.Inventory, and
`wait:true` health-checks only the APPLY change-set. So a redhat-cop CR whose
operator finalizer strands on a failed Vault-side delete (upstream #133)
hangs Terminating while the Kustomization reports READY — silent at the Flux
layer (upstream test "accepted delete leaves inventory" pins this). The S6b
guard bounds the blast radius (only UNREFERENCED objects can be pruned), so
the residual is an orphaned live Vault object + a stuck CR — drift, not a
consumer break — but drift must be DETECTED, not accepted.

THE MECHANISM: the daily scheduled scan workflow feeds this script
`kubectl get <the four redhatcop kinds> -A -o json` on stdin; any item whose
`metadata.deletionTimestamp` is older than --max-age-minutes fails the run
RED. A red scheduled workflow is the repo's established visibility surface
(the zero-red sweep). Younger deletions are in-flight (the operator retries;
reconcile interval 10m) and only WARN.

Pure stdin -> exit-code filter (no cluster access here) so the selftest can
drive it with fixtures. Exit 0 = no stuck deletion; 1 = stuck-Terminating CR
found; 2 = tooling/usage error (malformed input fails CLOSED).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail if any redhatcop CR has been Terminating too long."
    )
    parser.add_argument(
        "--max-age-minutes",
        type=int,
        default=30,
        help="deletionTimestamp older than this = stuck (default: 30; the "
        "Flux reconcile interval is 10m, so 30m means ~3 failed retries)",
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

    now = datetime.now(timezone.utc)
    stuck: list[str] = []
    in_flight = 0
    for item in items:
        meta = (item or {}).get("metadata") or {}
        ts = meta.get("deletionTimestamp")
        if not ts:
            continue
        try:
            deleted_at = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError as exc:
            raise fail_usage(f"unparseable deletionTimestamp {ts!r}: {exc}")
        age_minutes = (now - deleted_at).total_seconds() / 60.0
        ident = (
            f"{item.get('kind', '?')}/{meta.get('name', '?')} "
            f"(ns {meta.get('namespace', '?')}, deleting {age_minutes:.0f}m)"
        )
        if age_minutes > args.max_age_minutes:
            stuck.append(ident)
        else:
            in_flight += 1
            print(f"WARN: in-flight deletion (younger than threshold): {ident}")

    if stuck:
        print(
            f"FAIL: {len(stuck)} redhatcop CR(s) stuck Terminating longer than "
            f"{args.max_age_minutes}m — the operator finalizer is stranded "
            "(upstream #133): the Vault-side delete keeps failing while Flux "
            "reports Ready. Runbook: vault-config/README.md 'Prune (ARMED in "
            "S7)' — decide the live object's fate FIRST.",
            file=sys.stderr,
        )
        for ident in stuck:
            print(f"  - {ident}", file=sys.stderr)
        return 1

    print(
        f"PASS: no stuck-Terminating redhatcop CRs ({len(items)} scanned, "
        f"{in_flight} in-flight deletion(s) within threshold)."
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
