#!/usr/bin/env python3
"""Register hostnames at the Cloudflare edge for the nwarila-platform tunnels.

The public tier needs no per-host registration here: when the separately
managed ``*.nickwarila.com`` wildcard exists, it lands on the public connector.
The mTLS tier converges four per-host protections in a fixed order: certificate
association, Access application domains, WAF rule, then DNS.  Removal reverses
the safety boundary by deleting stale DNS before any of those protections are
narrowed.

All mutable edge state is read before the first write; Access posture and every
desired or stale DNS ownership decision are validated before any mutation.  A
dry run executes the same ordered plan, but logs each mutation instead of
sending it.  The API token is read from ``CLOUDFLARE_API_TOKEN`` or
``~/.cloudflare/api-token`` and is never printed.

Usage:
  register-tunnel-hostname.py --tier mtls   [--dry-run] HOST...
  register-tunnel-hostname.py --tier public [--dry-run] HOST...
  register-tunnel-hostname.py --tier mtls --remove [--dry-run] HOST...
  register-tunnel-hostname.py --reconcile [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
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
ACCESS_APP_ID = "9bea7759-a20e-4496-afb5-efb454eeec50"
WAF_RULE_DESCRIPTION = "Enforce mTLS authentication (nwp-mtls tier)"
MTLS_CLASS = "cf-tunnel-nwp-mtls"
TENANT_LABEL = "nwarila.io/tenant"

# These names belong to other services or to the zone itself.  This is a
# closed list: they are never accepted from an operator or tenant Ingress and
# are never added, removed, or rewritten by this script.
UNMANAGED_HOSTS = {
    ZONE,
    f"kasm.{ZONE}",
    f"www.{ZONE}",
    f"autoconfig.{ZONE}",
    f"localhost.{ZONE}",
}

# Both health-check names are platform-reserved.  Unlike UNMANAGED_HOSTS, the
# mTLS canary is deliberately managed by the internal pin in converge_mtls;
# neither canary is valid operator or tenant input.
RESERVED_CANARY_HOSTS = frozenset(CANARIES.values())

NWP_TUNNEL_TARGETS = {f"{tunnel_id}.cfargotunnel.com" for tunnel_id in TUNNELS.values()}
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_UNSET = object()


class CloudflareError(RuntimeError):
    """A concise, token-free operational failure."""


class HostnameError(ValueError):
    """A hostname cannot be managed by this script."""


class UnmanagedHostname(HostnameError):
    """A syntactically valid hostname is deliberately outside our ownership."""


class ReservedCanaryHostname(HostnameError):
    """A platform canary cannot be claimed through an external input path."""


class Client:
    def __init__(self, token: str) -> None:
        self._token = token

    def call(self, method: str, path: str, body: dict | list | None = None):
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
            try:
                payload = json.loads(error.read() or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise CloudflareError(f"{method} {path} -> HTTP {error.code}") from None
        except urllib.error.URLError as error:
            raise CloudflareError(f"{method} {path} -> transport error: {error.reason}") from None
        if not payload.get("success"):
            errors = "; ".join(f"{item.get('code')}: {item.get('message')}" for item in payload.get("errors", []))
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


def _normalise(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _concrete_in_zone(host: str) -> str:
    host = _normalise(host)
    if not host or host == ZONE or not host.endswith(f".{ZONE}") or "*" in host:
        raise HostnameError(f"{host!r} is not a concrete hostname inside {ZONE}")
    if len(host) > 253 or any(not HOST_LABEL.fullmatch(label) for label in host.split(".")):
        raise HostnameError(f"{host!r} is not a valid DNS hostname")
    return host


def in_zone(host: str) -> str:
    """Return a canonical hostname allowed through an external input path."""
    host = _normalise(host)
    if host in UNMANAGED_HOSTS:
        raise UnmanagedHostname(f"{host!r} is reserved and unmanaged")
    if host in RESERVED_CANARY_HOSTS:
        raise ReservedCanaryHostname(f"{host!r} is a platform-reserved canary")
    return _concrete_in_zone(host)


def _edge_hostname(host: str) -> str:
    """Validate an edge mutation, including the internally pinned mTLS canary."""
    host = _normalise(host)
    if host == CANARIES["mtls"]:
        return _concrete_in_zone(host)
    return in_zone(host)


def _managed_associations(current: list[str]) -> set[str]:
    managed: set[str] = set()
    for raw in current:
        host = _normalise(str(raw))
        if host in UNMANAGED_HOSTS:
            continue
        try:
            managed.add(in_zone(host))
        except HostnameError:
            # Preserve out-of-zone or malformed live entries: this script has
            # no authority to infer ownership merely from their presence.
            continue
    return managed


def _association_target(current: list[str], desired: set[str]) -> list[str]:
    managed = _managed_associations(current)
    preserved = {str(host) for host in current if _normalise(str(host)) not in managed}
    return sorted(preserved | desired)


def _has_otp_posture(app: dict) -> bool:
    for policy in app.get("policies") or []:
        if not isinstance(policy, dict):
            continue
        raw_decision = policy.get("decision")
        decision = raw_decision.strip().lower() if isinstance(raw_decision, str) else ""
        if decision != "allow":
            continue
        for include in policy.get("include") or []:
            if not isinstance(include, dict):
                continue
            email_domain = include.get("email_domain")
            domain = email_domain.get("domain") if isinstance(email_domain, dict) else None
            if (
                isinstance(domain, str)
                and domain.strip()
            ):
                return True
            if include.get("otp"):
                return True
    return False


def _require_access_posture(app: dict) -> None:
    if app.get("type") != "self_hosted":
        raise CloudflareError(
            f"Access app {ACCESS_APP_ID} is not type self_hosted; refusing to change DNS"
        )
    if not _has_otp_posture(app):
        raise CloudflareError(
            f"Access app {ACCESS_APP_ID} has no allow policy with a meaningful "
            "email_domain/otp include; refusing to change DNS"
        )


class Edge:
    def __init__(self, client: Client, dry_run: bool) -> None:
        self.cf = client
        self.dry_run = dry_run

    def log(self, step: str, before, after) -> None:
        marker = "PLAN " if self.dry_run else "APPLY"
        print(f"{marker} {step}\n       before: {before}\n       after:  {after}")

    def associations(self) -> list[str]:
        result = self.cf.call("GET", f"/zones/{ZONE_ID}/certificate_authorities/hostname_associations")
        return sorted(str(host) for host in result.get("hostnames", []))

    def set_associations(self, hosts: set[str], before: list[str] | None = None) -> None:
        before = self.associations() if before is None else sorted(before)
        after = _association_target(before, hosts)
        if before == after:
            print(f"OK    mTLS association already {after}")
            return
        self.log("mTLS hostname association", before, after)
        if not self.dry_run:
            self.cf.call(
                "PUT",
                f"/zones/{ZONE_ID}/certificate_authorities/hostname_associations",
                {"hostnames": after},
            )

    def access_app(self) -> dict:
        return self.cf.call("GET", f"/accounts/{ACCOUNT_ID}/access/apps/{ACCESS_APP_ID}")

    @staticmethod
    def access_patch(hosts: set[str]) -> dict:
        ordered = sorted(hosts)
        return {
            "self_hosted_domains": ordered,
            "destinations": [{"type": "public", "uri": host} for host in ordered],
        }

    def set_access_domains(self, hosts: set[str], app: dict | None = None) -> None:
        app = self.access_app() if app is None else app
        _require_access_posture(app)
        wanted = self.access_patch(hosts)
        before = {
            "self_hosted_domains": sorted(app.get("self_hosted_domains") or []),
            "destinations": app.get("destinations") or [],
        }
        if before == wanted:
            print(f"OK    Access app {ACCESS_APP_ID} already covers {wanted['self_hosted_domains']}")
            return
        self.log(f"Access app {ACCESS_APP_ID} domains", before, wanted)
        if not self.dry_run:
            # PATCH deliberately carries only domain membership.  The primary
            # domain, name, policies, and every other live field stay intact.
            self.cf.call("PATCH", f"/accounts/{ACCOUNT_ID}/access/apps/{ACCESS_APP_ID}", wanted)

    def waf_entrypoint(self) -> dict:
        return self.cf.call("GET", f"/zones/{ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint")

    @staticmethod
    def waf_expression(hosts: set[str]) -> str:
        quoted = " ".join(f'"{host}"' for host in sorted(hosts))
        return f"(not cf.tls_client_auth.cert_verified and http.host in {{{quoted}}})"

    @classmethod
    def waf_body(cls, hosts: set[str]) -> dict:
        return {
            "action": "block",
            "expression": cls.waf_expression(hosts),
            "description": WAF_RULE_DESCRIPTION,
            "enabled": True,
        }

    def set_waf(self, hosts: set[str], entry: dict | None = None) -> None:
        entry = self.waf_entrypoint() if entry is None else entry
        rules = entry.get("rules", [])
        ours = next((rule for rule in rules if rule.get("description") == WAF_RULE_DESCRIPTION), None)
        wanted = self.waf_body(hosts)
        before = None if ours is None else {
            "action": ours.get("action"),
            "expression": ours.get("expression"),
            "description": ours.get("description"),
            "enabled": ours.get("enabled"),
        }
        if (
            ours is not None
            and ours.get("expression") == wanted["expression"]
            and ours.get("action") == "block"
            and ours.get("enabled") is True
        ):
            print(f"OK    WAF rule already {wanted['expression']!r}")
            return
        self.log(f"WAF rule {WAF_RULE_DESCRIPTION!r}", before, wanted)
        if self.dry_run:
            return
        ruleset_id = entry["id"]
        if ours:
            self.cf.call("PATCH", f"/zones/{ZONE_ID}/rulesets/{ruleset_id}/rules/{ours['id']}", wanted)
        else:
            self.cf.call("POST", f"/zones/{ZONE_ID}/rulesets/{ruleset_id}/rules", wanted)

    def dns_record(self, name: str) -> dict | None:
        query = urllib.parse.urlencode({"name": name, "per_page": 10})
        records = self.cf.call("GET", f"/zones/{ZONE_ID}/dns_records?{query}")
        return next((record for record in records if _normalise(record.get("name", "")) == name), None)

    @staticmethod
    def _assert_dns_write_owned(name: str, current: dict | None) -> None:
        try:
            _edge_hostname(name)
        except HostnameError as error:
            raise CloudflareError(str(error)) from None
        if current is None:
            return
        if current.get("type") != "CNAME" or current.get("content") not in NWP_TUNNEL_TARGETS:
            rendered = f"{current.get('type')} {current.get('content')}"
            raise CloudflareError(f"DNS {name} is unmanaged ({rendered}); refusing to overwrite it")

    @staticmethod
    def _assert_dns_delete_owned(name: str, current: dict | None, tunnel: str) -> None:
        try:
            _edge_hostname(name)
        except HostnameError as error:
            raise CloudflareError(str(error)) from None
        if current is None:
            return
        target = f"{TUNNELS[tunnel]}.cfargotunnel.com"
        if current.get("type") != "CNAME" or current.get("content") != target:
            rendered = f"{current.get('type')} {current.get('content')}"
            raise CloudflareError(
                f"DNS {name} is not the expected {tunnel} CNAME ({rendered}); "
                "refusing to narrow its edge controls"
            )

    def set_cname(self, name: str, tunnel: str, current=_UNSET) -> None:
        current = self.dns_record(name) if current is _UNSET else current
        self._assert_dns_write_owned(name, current)
        target = f"{TUNNELS[tunnel]}.cfargotunnel.com"
        before = None if current is None else (
            f"{current.get('type')} {current.get('content')} proxied={current.get('proxied')}"
        )
        after = f"CNAME {target} proxied=True"
        if before == after:
            print(f"OK    DNS {name} already -> {target}")
            return
        self.log(f"DNS {name}", before, after)
        if self.dry_run:
            return
        body = {
            "type": "CNAME",
            "name": name,
            "content": target,
            "proxied": True,
            "ttl": 1,
            "comment": f"nwp {tunnel} tunnel; managed by register-tunnel-hostname.py",
        }
        if current:
            self.cf.call("PUT", f"/zones/{ZONE_ID}/dns_records/{current['id']}", body)
        else:
            self.cf.call("POST", f"/zones/{ZONE_ID}/dns_records", body)

    def delete_cname(self, name: str, tunnel: str, current=_UNSET) -> None:
        try:
            _edge_hostname(name)
        except HostnameError as error:
            raise CloudflareError(str(error)) from None
        current = self.dns_record(name) if current is _UNSET else current
        target = f"{TUNNELS[tunnel]}.cfargotunnel.com"
        if (
            not current
            or current.get("type") != "CNAME"
            or current.get("content") != target
        ):
            print(f"OK    DNS {name} not pointing at the {tunnel} tunnel; leaving it alone")
            return
        self.log(f"DNS {name}", f"CNAME {target}", None)
        if not self.dry_run:
            self.cf.call("DELETE", f"/zones/{ZONE_ID}/dns_records/{current['id']}")


@dataclass(frozen=True)
class Discovery:
    hosts: frozenset[str]
    refused: frozenset[str]


def _kubectl_json(args: list[str]) -> dict:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "kubectl failed").strip()
        raise CloudflareError(f"{' '.join(args)}: {detail}") from None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        raise CloudflareError(f"{' '.join(args)} returned invalid JSON: {error.msg}") from None


def desired_from_cluster() -> Discovery:
    # kubectl cannot select namespaced objects by a label on their Namespace.
    # Use an unavoidable N+1 shape: one server-side Namespace label selection,
    # then exactly one namespaced Ingress read per selected tenant.  Never read
    # Ingresses from an unlabelled namespace.
    namespaces = _kubectl_json(
        ["kubectl", "get", "namespaces", "--selector", f"{TENANT_LABEL}=true", "-o", "json"]
    )
    tenant_namespaces = {
        item.get("metadata", {}).get("name")
        for item in namespaces.get("items", [])
        if item.get("metadata", {}).get("labels", {}).get(TENANT_LABEL) == "true"
    }
    tenant_namespaces.discard(None)

    hosts: set[str] = set()
    refused: set[str] = set()
    for namespace in sorted(tenant_namespaces):
        ingresses = _kubectl_json(
            ["kubectl", "get", "ingress", "--namespace", namespace, "-o", "json"]
        )
        for item in ingresses.get("items", []):
            if item.get("spec", {}).get("ingressClassName") != MTLS_CLASS:
                continue
            metadata = item.get("metadata", {})
            source = f"{namespace}/{metadata.get('name', '<unnamed>')}"
            for rule in item.get("spec", {}).get("rules", []):
                raw = rule.get("host")
                if raw is None or not str(raw).strip():
                    print(f"SKIP   {source}: Ingress rule has no non-empty host", file=sys.stderr)
                    continue
                try:
                    hosts.add(in_zone(str(raw)))
                except (UnmanagedHostname, ReservedCanaryHostname):
                    host = _normalise(str(raw))
                    refused.add(host)
                    print(f"REFUSE {source}: reserved hostname {host}", file=sys.stderr)
                except HostnameError as error:
                    print(f"SKIP   {source}: {error}", file=sys.stderr)
    return Discovery(frozenset(hosts), frozenset(refused))


def converge_mtls(
    edge: Edge,
    hosts: set[str],
    before_associations: list[str] | None = None,
) -> None:
    """Converge a complete desired set with deterministic, fail-closed order."""
    # Validate every supplied host as external input first.  The mTLS canary is
    # added only through this internal pin, after that validation boundary.
    desired = {in_zone(host) for host in hosts}
    desired.add(CANARIES["mtls"])

    # Snapshot and validate every dependency before the first mutation.  Most
    # importantly, stale is derived from the pre-write association list.
    before_associations = edge.associations() if before_associations is None else sorted(before_associations)
    stale = _managed_associations(before_associations) - desired
    app = edge.access_app()
    waf = edge.waf_entrypoint()
    dns = {host: edge.dns_record(host) for host in sorted(stale | desired)}

    # Nothing mutates until both the Access posture and every DNS ownership
    # decision have passed.  A stale record is removable only when absent or
    # still the exact mTLS CNAME this script owns.
    _require_access_posture(app)
    for host in stale:
        edge._assert_dns_delete_owned(host, dns[host], "mtls")
    for host in desired:
        edge._assert_dns_write_owned(host, dns[host])

    # Close stale routes before narrowing any protection.
    for host in sorted(stale):
        edge.delete_cname(host, "mtls", dns[host])

    # Open only after every protection is in its desired state.
    edge.set_associations(desired, before_associations)
    edge.set_access_domains(desired, app)
    edge.set_waf(desired, waf)
    for host in sorted(desired):
        edge.set_cname(host, "mtls", dns[host])


def _validate_cli_hosts(raw_hosts: list[str]) -> tuple[set[str], list[str]]:
    hosts: set[str] = set()
    errors: list[str] = []
    for raw in raw_hosts:
        try:
            hosts.add(in_zone(raw))
        except HostnameError as error:
            errors.append(str(error))
    return hosts, errors


def _remove_public(edge: Edge, hosts: set[str]) -> None:
    # Preflight every record so a batch cannot partially mutate before an
    # unmanaged collision is discovered.
    records = {host: edge.dns_record(host) for host in sorted(hosts)}
    for host, record in records.items():
        if record and (record.get("type") != "CNAME" or record.get("content") not in NWP_TUNNEL_TARGETS):
            rendered = f"{record.get('type')} {record.get('content')}"
            raise CloudflareError(f"DNS {host} is unmanaged ({rendered}); refusing to overwrite it")
    for host in sorted(hosts):
        edge.delete_cname(host, "public", records[host])


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("hosts", nargs="*")
    parser.add_argument("--tier", choices=tuple(TUNNELS))
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv[1:])

    try:
        if args.reconcile:
            if args.tier or args.hosts or args.remove:
                parser.error("--reconcile cannot be combined with --tier, --remove, or HOST")
            discovery = desired_from_cluster()
            if discovery.refused:
                print(
                    "register-tunnel-hostname: refusing reconcile because reserved hostnames were declared: "
                    + ", ".join(sorted(discovery.refused)),
                    file=sys.stderr,
                )
                return 2
            print(f"desired mTLS-tier hostnames from labelled tenant Ingresses: {sorted(discovery.hosts)}")
            edge = Edge(Client(read_token()), args.dry_run)
            converge_mtls(edge, set(discovery.hosts))
            return 0

        if not args.tier or not args.hosts:
            parser.error("--tier and at least one HOST are required unless --reconcile")
        hosts, errors = _validate_cli_hosts(args.hosts)
        if errors:
            for error in errors:
                print(f"register-tunnel-hostname: {error}", file=sys.stderr)
            return 2

        if args.tier == "public" and not args.remove:
            for host in sorted(hosts):
                print(
                    f"OK    {host}: public tier needs no edge registration; "
                    f"when the separately managed *.{ZONE} wildcard exists, it lands here"
                )
            return 0

        edge = Edge(Client(read_token()), args.dry_run)
        if args.tier == "public":
            _remove_public(edge, hosts)
            return 0

        before = edge.associations()
        current = _managed_associations(before)
        desired = current - hosts if args.remove else current | hosts
        converge_mtls(edge, desired, before)
        return 0
    except CloudflareError as error:
        print(f"register-tunnel-hostname: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
