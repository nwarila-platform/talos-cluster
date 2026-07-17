#!/usr/bin/env python3
"""Regression self-test for the CP-1 sigstore-pin drift detector."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

GUARD = Path(__file__).resolve().parent / "check-sigstore-pin-verification.py"
ENFORCED = "verify-image-signatures-enforced"


def kube_list(items) -> str:
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": items})


def report(results, kind: str = "PolicyReport", ns: str = "deploy-vault") -> dict:
    meta = {"name": "cpol-report", "namespace": ns}
    return {"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": kind, "metadata": meta, "results": results}


def result(policy: str, rule: str, res: str, name: str = "vault-0") -> dict:
    return {
        "policy": policy,
        "rule": rule,
        "result": res,
        "resources": [{"namespace": "deploy-vault", "name": name}],
    }


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
        "no-enforced-results-warns-pass",
        kube_list([report([result("verify-image-signatures", "verify-flux-images", "fail")])]),
        (),
        0,
        ["WARN", "no 'verify-image-signatures-enforced'"],
    ),
    (
        "all-first-party-pass",
        kube_list([report([
            result(ENFORCED, "verify-nwarila-platform-images", "pass"),
            result(ENFORCED, "verify-nwarila-images", "pass"),
        ])]),
        (),
        0,
        ["PASS", "2 ", "pins are current"],
    ),
    (
        "first-party-fail-is-drift",
        kube_list([report([
            result(ENFORCED, "verify-nwarila-platform-images", "pass"),
            result(ENFORCED, "verify-nwarila-images", "fail"),
        ])]),
        (),
        1,
        ["FAIL", "DRIFT", "verify-nwarila-images"],
    ),
    (
        "first-party-error-is-drift",
        kube_list([report([result(ENFORCED, "verify-herowars-images", "error")])]),
        (),
        1,
        ["FAIL", "DRIFT"],
    ),
    (
        "skip-only-passes",
        kube_list([report([result(ENFORCED, "verify-nwarila-images", "skip")])]),
        (),
        0,
        ["PASS"],
    ),
    (
        "third-party-fail-ignored",
        # Only the enforced (first-party) policy drives drift; third-party Audit
        # fails (cilium/kyverno/vso) are the known TD-0001/0002 state, not drift.
        kube_list([report([
            result("verify-image-signatures", "verify-cilium-images", "fail"),
            result(ENFORCED, "verify-nwarila-platform-images", "pass"),
        ])]),
        (),
        0,
        ["PASS", "1 "],
    ),
    (
        "clusterpolicyreport-kind-scanned",
        kube_list([report([result(ENFORCED, "verify-nwarila-images", "fail")], kind="ClusterPolicyReport")]),
        (),
        1,
        ["FAIL", "DRIFT"],
    ),
    (
        "custom-policy-name-arg",
        kube_list([report([result("other-enforced", "r", "fail")])]),
        ("--policy-name", "other-enforced"),
        1,
        ["FAIL", "DRIFT"],
    ),
    (
        "empty-stdin-fails-closed",
        "",
        (),
        2,
        ["ERROR", "no input"],
    ),
    (
        "malformed-json-fails-closed",
        "{not json",
        (),
        2,
        ["ERROR", "not valid JSON"],
    ),
    (
        "no-items-list-fails-closed",
        json.dumps({"apiVersion": "v1", "kind": "List"}),
        (),
        2,
        ["ERROR", "no items list"],
    ),
    (
        "non-list-results-fails-closed",
        kube_list([{"kind": "PolicyReport", "metadata": {"name": "x"}, "results": "oops"}]),
        (),
        2,
        ["ERROR", "non-list results"],
    ),
]


def main() -> int:
    failures = 0
    for name, stdin, extra, want_rc, want_substrings in CASES:
        rc, out = run(stdin, *extra)
        ok = rc == want_rc and all(s in out for s in want_substrings)
        status = "PASS" if ok else "FAIL"
        print(f"{name:38s} rc={rc} (want {want_rc})  {status}")
        if not ok:
            failures += 1
            if rc != want_rc:
                print(f"    expected rc {want_rc}, got {rc}")
            for s in want_substrings:
                if s not in out:
                    print(f"    missing substring: {s!r}")
            print(f"    output: {out.strip()[:400]}")
    print()
    if failures:
        print(f"SELFTEST FAIL: {failures}/{len(CASES)} cases failed")
        return 1
    print(f"SELFTEST PASS ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
