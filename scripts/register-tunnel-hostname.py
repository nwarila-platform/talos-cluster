#!/usr/bin/env python3
"""Register hostnames at the Cloudflare edge for the nwarila-platform tunnels.

The public tier needs nothing here: the ``*.nickwarila.com`` wildcard already
lands on the public connector. The mTLS tier is different, because every
Cloudflare primitive that makes a hostname "protected" is per-FQDN. For each
protected hostname this script converges, in this order and idempotently:

  1. the zone mTLS hostname association (the edge starts asking for a cert);
  2. the multi-domain Access application (OTP, and the aud the connector pins);
  3. the WAF block entry (``cert_verified`` false is rejected at the edge);
  4. the explicit DNS CNAME to the mTLS tunnel.

DNS is last on purpose. Until the CNAME exists the hostname resolves through
the wildcard to the PUBLIC connector, whose proxy cannot select an mTLS-tier
pod, so the origin is unreachable rather than exposed. Deregistration runs the
same steps in reverse, DNS first.

Every write is read-modify-write against the live object and prints the
before/after for the change evidence. ``--dry-run`` prints the plan only.
The token is read from ``CLOUDFLARE_API_TOKEN`` or ``~/.cloudflare/api-token``
and is never printed.

Usage:
  register-tunnel-hostname.py --tier mtls   [--dry-run] HOST...
  register-tunnel-hostname.py --tier public [--dry-run] HOST...
  register-tunnel-hostname.py --tier mtls --remove [--dry-run] HOST...
  register-tunnel-hostname.py --reconcile [--dry-run]

``--reconcile`` reads the desired protected set from live Ingresses of class
``cf-tunnel-nwp-mtls`` (plus the pinned canary) and converges the edge to
exactly that set. It is the loop the scheduled reconciler runs.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.cloudflare.com/client/v4"
ZONE = "nickwarila.com"
ZONE_ID = "fe48439aa4b8d76a79e54328b68661d7"
ACCOUNT_ID = "b69e3910b7d95e7f7d91e6d296d8a1d8"
TUNNELS = {
    "public": "1f59f78a-16f8-4e3c-8567-de0235e39871",
    "mtls": "fb6932d9-c6e4-4ccb-8e4c-dee47aa05313",
}
CANARIES = {
    "public": f"canary-nwp-public.{ZONE}",
    "mtls": f"canary-nwp-mtls.{ZONE}",
}
# The repurposed tmp.nickwarila.com application; its aud is pinned in the
# nwp-mtls connector ConfigMap. Never create a second app for this tier.
ACCESS_APP_ID = "9bea7759-a20e-4496-afb5-efb454eeec50"
ACCESS_APP_NAME = "nwp-mtls"
# Hostnames that must stay associated but are NOT managed by this script.
FOREIGN_MTLS_HOSTS = {f"kasm.{ZONE}"}
WAF_RULE_DESCRIPTION = "Enforce mTLS authentication (nwp-mtls tier)"
MTLS_CLASS = "cf-tunnel-nwp-mtls"


class CloudflareError(RuntimeError):
    pass


class Client:
    def __init__(self, token: str) -> None:
        self._token = token

    def call(self, method: str, path: str, body: dict | list | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            f"{API}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            payload = json.loads(error.read() or b"{}")
        if not payload.get("success"):
            errors = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in payload.get("errors", []))
            raise CloudflareError(f"{method} {path} -> {errors or 'unknown error'}")
        return payload["result"]


def read_token() -> str:
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        path = Path.home() / ".cloudflare" / "api-token"
        if path.is_file():
            token = path.read_text(encoding="utf-8").strip()
    if not token:
        raise SystemExit("no token: set CLOUDFLARE_API_TOKEN or write ~/.cloudflare/api-token")
    return token


def in_zone(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host == ZONE or not host.endswith(f".{ZONE}") or "*" in host:
        raise SystemExit(f"{host!r} is not a concrete hostname inside {ZONE}")
    return host


class Edge:
    def __init__(self, client: Client, dry_run: bool) -> None:
        self.cf = client
        self.dry_run = dry_run

    def log(self, step: str, before, after) -> None:
        marker = "PLAN " if self.dry_run else "APPLY"
        print(f"{marker} {step}\n       before: {before}\n       after:  {after}")

    # -- 1. mTLS hostname association ---------------------------------------
    def associations(self) -> list[str]:
        return sorted(self.cf.call("GET", f"/zones/{ZONE_ID}/certificate_authorities/hostname_associations").get("hostnames", []))

    def set_associations(self, hosts: set[str]) -> None:
        before = self.associations()
        # Keep the foreign (unmanaged) hosts, drop managed hosts no longer
        # desired, add the desired set. Never touch anything outside the zone.
        after = sorted((set(before) - self._managed_not_in(hosts, before)) | FOREIGN_MTLS_HOSTS | hosts)
        if before == after:
            print(f"OK    mTLS association already {after}")
            return
        self.log("mTLS hostname association", before, after)
        if not self.dry_run:
            self.cf.call("PUT", f"/zones/{ZONE_ID}/certificate_authorities/hostname_associations", {"hostnames": after})

    def _managed_not_in(self, desired: set[str], current: list[str]) -> set[str]:
        """Managed hostnames present at the edge but absent from the desired set."""
        return {h for h in current if h not in FOREIGN_MTLS_HOSTS and h not in desired and h.endswith(f".{ZONE}")}

    # -- 2. Access application domains --------------------------------------
    def access_app(self) -> dict:
        return self.cf.call("GET", f"/accounts/{ACCOUNT_ID}/access/apps/{ACCESS_APP_ID}")

    def set_access_domains(self, hosts: set[str]) -> None:
        app = self.access_app()
        before = sorted(app.get("self_hosted_domains") or [app.get("domain")])
        after = sorted(hosts)
        if before == after and app.get("name") == ACCESS_APP_NAME:
            print(f"OK    Access app {ACCESS_APP_NAME} already covers {after}")
            return
        self.log(f"Access app {ACCESS_APP_ID} domains", before, after)
        if not self.dry_run:
            primary = after[0]
            self.cf.call(
                "PUT",
                f"/accounts/{ACCOUNT_ID}/access/apps/{ACCESS_APP_ID}",
                {
                    "name": ACCESS_APP_NAME,
                    "type": "self_hosted",
                    "domain": primary,
                    "self_hosted_domains": after,
                    "destinations": [{"type": "public", "uri": h} for h in after],
                    "session_duration": app.get("session_duration", "24h"),
                    "app_launcher_visible": app.get("app_launcher_visible", True),
                    "allowed_idps": app.get("allowed_idps", []),
                    "auto_redirect_to_identity": app.get("auto_redirect_to_identity", False),
                    "enable_binding_cookie": app.get("enable_binding_cookie", False),
                    "http_only_cookie_attribute": app.get("http_only_cookie_attribute", False),
                    "options_preflight_bypass": app.get("options_preflight_bypass", False),
                    "policies": [p["id"] for p in app.get("policies", []) if p.get("id")],
                },
            )

    # -- 3. WAF block rule ---------------------------------------------------
    def waf_entrypoint(self) -> dict:
        return self.cf.call("GET", f"/zones/{ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint")

    @staticmethod
    def waf_expression(hosts: set[str]) -> str:
        quoted = " ".join(f'"{h}"' for h in sorted(hosts))
        return f"(not cf.tls_client_auth.cert_verified and http.host in {{{quoted}}})"

    def set_waf(self, hosts: set[str]) -> None:
        entry = self.waf_entrypoint()
        rules = entry.get("rules", [])
        ours = next((r for r in rules if r.get("description") == WAF_RULE_DESCRIPTION), None)
        wanted = self.waf_expression(hosts) if hosts else None
        before = ours.get("expression") if ours else None
        if before == wanted:
            print(f"OK    WAF rule already {wanted!r}")
            return
        self.log(f"WAF rule {WAF_RULE_DESCRIPTION!r}", before, wanted)
        if self.dry_run:
            return
        ruleset_id = entry["id"]
        if ours and wanted:
            self.cf.call(
                "PATCH",
                f"/zones/{ZONE_ID}/rulesets/{ruleset_id}/rules/{ours['id']}",
                {"action": "block", "expression": wanted, "description": WAF_RULE_DESCRIPTION, "enabled": True},
            )
        elif ours:
            self.cf.call("DELETE", f"/zones/{ZONE_ID}/rulesets/{ruleset_id}/rules/{ours['id']}")
        else:
            self.cf.call(
                "POST",
                f"/zones/{ZONE_ID}/rulesets/{ruleset_id}/rules",
                {"action": "block", "expression": wanted, "description": WAF_RULE_DESCRIPTION, "enabled": True},
            )

    # -- 4. DNS --------------------------------------------------------------
    def dns_record(self, name: str) -> dict | None:
        records = self.cf.call("GET", f"/zones/{ZONE_ID}/dns_records?name={name}&per_page=10")
        return next((r for r in records if r["name"] == name), None)

    def set_cname(self, name: str, tunnel: str) -> None:
        target = f"{TUNNELS[tunnel]}.cfargotunnel.com"
        current = self.dns_record(name)
        before = f"{current['type']} {current['content']} proxied={current['proxied']}" if current else None
        after = f"CNAME {target} proxied=True"
        if before == after:
            print(f"OK    DNS {name} already -> {target}")
            return
        self.log(f"DNS {name}", before, after)
        if self.dry_run:
            return
        body = {"type": "CNAME", "name": name, "content": target, "proxied": True, "ttl": 1,
                "comment": f"nwp {tunnel} tunnel; managed by register-tunnel-hostname.py"}
        if current:
            self.cf.call("PUT", f"/zones/{ZONE_ID}/dns_records/{current['id']}", body)
        else:
            self.cf.call("POST", f"/zones/{ZONE_ID}/dns_records", body)

    def delete_cname(self, name: str, tunnel: str) -> None:
        current = self.dns_record(name)
        target = f"{TUNNELS[tunnel]}.cfargotunnel.com"
        if not current or current.get("content") != target:
            print(f"OK    DNS {name} not pointing at the {tunnel} tunnel; leaving it alone")
            return
        self.log(f"DNS {name}", f"CNAME {target}", None)
        if not self.dry_run:
            self.cf.call("DELETE", f"/zones/{ZONE_ID}/dns_records/{current['id']}")


def desired_from_cluster() -> set[str]:
    proc = subprocess.run(
        ["kubectl", "get", "ingress", "-A", "-o", "json"],
        capture_output=True, text=True, check=True,
    )
    hosts: set[str] = set()
    for item in json.loads(proc.stdout).get("items", []):
        if item.get("spec", {}).get("ingressClassName") != MTLS_CLASS:
            continue
        for rule in item["spec"].get("rules", []):
            if rule.get("host"):
                hosts.add(in_zone(rule["host"]))
    return hosts


def converge_mtls(edge: Edge, hosts: set[str]) -> None:
    """Order matters: registration opens last, deregistration closes first."""
    hosts = set(hosts) | {CANARIES["mtls"]}
    edge.set_associations(hosts)
    edge.set_access_domains(hosts)
    edge.set_waf(hosts)
    for host in sorted(hosts):
        edge.set_cname(host, "mtls")
    # Anything we previously registered that is no longer desired: DNS first.
    stale = edge._managed_not_in(hosts, edge.associations())
    for host in sorted(stale):
        edge.delete_cname(host, "mtls")
    if stale:
        edge.set_associations(hosts)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("hosts", nargs="*")
    parser.add_argument("--tier", choices=tuple(TUNNELS))
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv[1:])

    edge = Edge(Client(read_token()), args.dry_run)
    try:
        if args.reconcile:
            desired = desired_from_cluster()
            print(f"desired mTLS-tier hostnames from live {MTLS_CLASS} Ingresses: {sorted(desired)}")
            converge_mtls(edge, desired)
            return 0
        if not args.tier or not args.hosts:
            parser.error("--tier and at least one HOST are required unless --reconcile")
        hosts = {in_zone(h) for h in args.hosts}
        if args.tier == "public":
            for host in sorted(hosts):
                if args.remove:
                    edge.delete_cname(host, "public")
                else:
                    print(f"OK    {host}: public tier needs no edge registration; the *.{ZONE} wildcard already lands here")
            return 0
        current = set(edge.associations()) - FOREIGN_MTLS_HOSTS
        desired = (current - hosts) if args.remove else (current | hosts)
        converge_mtls(edge, desired)
        return 0
    except CloudflareError as error:
        print(f"register-tunnel-hostname: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
