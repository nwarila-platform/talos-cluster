#!/usr/bin/env python3
"""Regression self-test for the S7 stuck-Terminating detector."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

GUARD = Path(__file__).resolve().parent / "check-vault-config-terminating.py"


def iso(minutes_ago: float) -> str:
    return (
        (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago))
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def kube_list(items) -> str:
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": items})


def cr(kind: str, name: str, deletion_ts: str | None = None) -> dict:
    meta = {"name": name, "namespace": "vault-config-operator"}
    if deletion_ts:
        meta["deletionTimestamp"] = deletion_ts
    return {"apiVersion": "redhatcop.redhat.io/v1alpha1", "kind": kind, "metadata": meta}


def run(stdin: str, *extra: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GUARD), *extra],
        input=stdin,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + "\n" + proc.stderr


CASES = [
    (
        "empty-list-passes",
        kube_list([]),
        (),
        0,
        ["PASS", "0 scanned"],
    ),
    (
        "healthy-crs-pass",
        kube_list([cr("Policy", "tenant-read"), cr("SecretEngineMount", "pki-int-tcn")]),
        (),
        0,
        ["PASS", "2 scanned"],
    ),
    (
        "stuck-terminating-fails",
        kube_list([cr("Policy", "old-ghost", iso(120))]),
        (),
        1,
        ["FAIL", "stuck Terminating", "Policy/old-ghost", "deleting 120m"],
    ),
    (
        "in-flight-deletion-warns-passes",
        kube_list([cr("KubernetesAuthEngineRole", "retiring", iso(2))]),
        (),
        0,
        ["WARN: in-flight deletion", "PASS", "1 in-flight"],
    ),
    (
        "threshold-is-configurable",
        kube_list([cr("Policy", "borderline", iso(10))]),
        ("--max-age-minutes", "5"),
        1,
        ["FAIL", "Policy/borderline"],
    ),
    (
        "mixed-only-stuck-fails",
        kube_list(
            [
                cr("Policy", "fine"),
                cr("Policy", "fresh-delete", iso(1)),
                cr("PKISecretEngineRole", "stuck-role", iso(90)),
            ]
        ),
        (),
        1,
        ["PKISecretEngineRole/stuck-role", "deleting 90m"],
    ),
    (
        "malformed-json-tooling-error",
        "{not json",
        (),
        2,
        ["not valid JSON"],
    ),
    (
        "empty-stdin-tooling-error",
        "",
        (),
        2,
        ["no input on stdin"],
    ),
    (
        "non-list-tooling-error",
        json.dumps({"kind": "Policy"}),
        (),
        2,
        ["no items list"],
    ),
    (
        "bad-timestamp-tooling-error",
        kube_list([cr("Policy", "weird", "not-a-time")]),
        (),
        2,
        ["unparseable deletionTimestamp"],
    ),
]


def main() -> int:
    failures = 0
    for name, stdin, extra, want_rc, fragments in CASES:
        rc, output = run(stdin, *extra)
        ok = rc == want_rc and all(f in output for f in fragments)
        print(f"{'PASS' if ok else 'FAIL'}  {name} (rc={rc}, want {want_rc})")
        if not ok:
            failures += 1
            missing = [f for f in fragments if f not in output]
            if missing:
                print(f"      missing fragments: {missing}")
            print("      | " + output.strip().replace("\n", "\n      | ")[:800])
    print()
    if failures:
        print(f"SELFTEST FAIL ({failures} case(s))")
        return 1
    print("SELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
