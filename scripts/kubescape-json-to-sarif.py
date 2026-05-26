#!/usr/bin/env python3
# =============================================================================
# kubescape-json-to-sarif.py — convert a kubescape cluster-scan JSON report
# into SARIF 2.1.0 suitable for GitHub Code Scanning ingestion.
#
# Why this script exists: kubescape v4.0.8's `--format sarif` is only
# supported when scanning local files, not when scanning a live cluster
# (kubescape rejects with `format "sarif" is only supported when scanning
# local files`). Our use case is the live cluster, so we scan to JSON and
# convert here.
#
# Output: SARIF 2.1.0. Each (control, resource) pair becomes one result.
# `partialFingerprints.kubescapeFingerprint` is the stable per-finding key
# Code Scanning uses to track Open/Fixed/Dismissed state across runs.
#
# Usage: kubescape-json-to-sarif.py <input.json> <output.sarif>
# =============================================================================
import hashlib
import json
import sys
from pathlib import Path

KUBESCAPE_INFO_URI = "https://kubescape.io/"
CONTROL_HELP_URI_TEMPLATE = "https://hub.armosec.io/docs/{control_id_lc}"

# Kubescape severity (string) -> SARIF level + numeric security-severity
# (Code Scanning uses security-severity to bucket Critical/High/Medium/Low).
SEVERITY_MAP = {
    "Critical": ("error", "9.5"),
    "High":     ("error", "7.5"),
    "Medium":   ("warning", "5.0"),
    "Low":      ("note", "2.5"),
    "Unknown":  ("note", "0.0"),
}


def severity_to_sarif(sev: str) -> tuple[str, str]:
    return SEVERITY_MAP.get(sev or "Unknown", SEVERITY_MAP["Unknown"])


def build_rule(control_id: str, control: dict) -> dict:
    name = control.get("name", control_id)
    severity = control.get("severity", "Unknown")
    level, security_severity = severity_to_sarif(severity)
    cis_tag = ""
    # control name often starts with "CIS-X.Y.Z " — extract for tags
    if name.startswith("CIS-"):
        first_token = name.split(" ", 1)[0]
        cis_tag = first_token.lower().replace("cis-", "cis-k8s-")
    tags = ["security", "kubescape", "cis-k8s-benchmark"]
    if cis_tag:
        tags.append(cis_tag)
    return {
        "id": control_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {
            "text": f"{name} (Kubescape control {control_id}, severity {severity})."
        },
        "helpUri": CONTROL_HELP_URI_TEMPLATE.format(control_id_lc=control_id.lower()),
        "defaultConfiguration": {"level": level},
        "properties": {
            "security-severity": security_severity,
            "tags": tags,
            "kubescape-severity": severity,
        },
    }


def resource_to_location(resource_id: str) -> dict:
    # Kubescape resource IDs look like:
    #   /<ns>/<Kind>/<name>
    #   /<ns>/<Kind>/<name>/<apiVersion>//<Kind>/<name>
    # GitHub Code Scanning rejects custom URI schemes (e.g. "kubernetes://")
    # when the checkout URI is file://. Use a relative path inside a
    # synthetic "cluster-resources/" subtree instead — this passes the
    # URI-scheme-matches-checkout check and tells reviewers the finding
    # is on a live K8s resource, not a file in the repo. logicalLocations
    # carries the structured K8s identity for the Security-tab display.
    # Resource IDs vary in shape: kubescape uses both <ns>/<Kind>/<name>
    # and <apiVersion>/<ns>/<Kind>/<name>, plus // separators when one
    # finding spans multiple resources. We don't parse the structure;
    # we use the resource_id verbatim as the logical-location identifier
    # and synthesize a relative path for the SARIF artifact URI.
    parts = [seg.replace(" ", "_") or "_" for seg in resource_id.strip("/").split("/")]
    if not parts:
        parts = ["cluster-scope"]
    uri = "cluster-resources/" + "/".join(parts)
    # name = last non-empty segment, for the Security-tab summary line.
    display_name = next((p for p in reversed(parts) if p and p != "_"), "unknown")
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            # Code Scanning needs a region for some finding-types; use a
            # synthetic line 1:1 marker since K8s resources have no source
            # line. This is the standard SARIF idiom for non-file artifacts.
            "region": {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1},
        },
        "logicalLocations": [
            {
                "name": display_name,
                "kind": "kubernetesResource",
                "fullyQualifiedName": resource_id.lstrip("/"),
            }
        ],
    }


def fingerprint(control_id: str, resource_id: str) -> str:
    raw = f"{control_id}|{resource_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def convert(scan: dict, kubescape_version: str = "v4.0.8") -> dict:
    summary = scan.get("summaryDetails", {})
    controls = summary.get("controls", {})  # dict keyed by control id
    results_in = scan.get("results", [])

    # Only include rules for controls that actually appeared in scan output.
    referenced_control_ids = set()
    for r in results_in:
        for c in r.get("controls", []):
            referenced_control_ids.add(c.get("controlID"))

    rules = []
    for cid in sorted(referenced_control_ids):
        ctrl = controls.get(cid, {"name": cid, "severity": "Unknown"})
        rules.append(build_rule(cid, ctrl))

    sarif_results = []
    for r in results_in:
        resource_id = r.get("resourceID", "")
        for c in r.get("controls", []):
            status = (c.get("status") or {}).get("status")
            if status != "failed":
                continue  # SARIF results = failing controls only
            control_id = c.get("controlID")
            name = c.get("name") or control_id
            severity = c.get("severity") or controls.get(control_id, {}).get("severity")
            level, _ = severity_to_sarif(severity)
            sarif_results.append({
                "ruleId": control_id,
                "level": level,
                "message": {
                    "text": f"{name} failed for resource {resource_id}.",
                },
                "locations": [resource_to_location(resource_id)],
                "partialFingerprints": {
                    "kubescapeFingerprint": fingerprint(control_id, resource_id),
                },
            })

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Kubescape",
                        "version": kubescape_version,
                        "informationUri": KUBESCAPE_INFO_URI,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "properties": {
                    "framework": summary.get("frameworks", [{}])[0].get("name", "cis-v1.10.0"),
                    "complianceScore": summary.get("complianceScore"),
                    "score": summary.get("score"),
                    "clusterName": scan.get("clusterName"),
                },
            }
        ],
    }
    return sarif


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: kubescape-json-to-sarif.py <input.json> <output.sarif>", file=sys.stderr)
        return 2
    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    scan = json.loads(in_path.read_text(encoding="utf-8"))
    sarif = convert(scan)
    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    results_count = len(sarif["runs"][0]["results"])
    rules_count = len(sarif["runs"][0]["tool"]["driver"]["rules"])
    print(f"SARIF written: {out_path} (rules={rules_count}, results={results_count})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
