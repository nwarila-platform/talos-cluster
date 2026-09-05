#!/usr/bin/env python3
"""Offline contract tests for register-tunnel-hostname.py.

The fake Cloudflare client records every non-GET call.  No test can reach the
network or a live edge account.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import sys
import urllib.error
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

SCRIPT = Path(__file__).with_name("register-tunnel-hostname.py")
SPEC = importlib.util.spec_from_file_location("register_tunnel_hostname", SCRIPT)
assert SPEC and SPEC.loader
register = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = register
SPEC.loader.exec_module(register)

ASSOCIATIONS = f"/zones/{register.ZONE_ID}/certificate_authorities/hostname_associations"
ACCESS = f"/accounts/{register.ACCOUNT_ID}/access/apps/{register.ACCESS_APP_ID}"
WAF_ENTRYPOINT = f"/zones/{register.ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint"
WAF_COLLECTION = f"/zones/{register.ZONE_ID}/rulesets/ruleset-1/rules"
WAF_RULE = f"/zones/{register.ZONE_ID}/rulesets/ruleset-1/rules/waf-1"
DNS_COLLECTION = f"/zones/{register.ZONE_ID}/dns_records"
CANARY = register.CANARIES["mtls"]
MTLS_TARGET = f"{register.TUNNELS['mtls']}.cfargotunnel.com"
PUBLIC_TARGET = f"{register.TUNNELS['public']}.cfargotunnel.com"


@dataclass(frozen=True)
class Result:
    stdout: str


class FakeClient:
    """A state-bearing Cloudflare double; ``writes`` is the audit evidence."""

    def __init__(
        self,
        hosts: set[str],
        *,
        dns_hosts: set[str] | None = None,
        app: dict | None = None,
        waf: dict | None = None,
        associations: list[str] | None = None,
    ) -> None:
        self.association_hosts = sorted(hosts) if associations is None else sorted(associations)
        self.app = copy.deepcopy(app if app is not None else good_app(hosts))
        self.waf = copy.deepcopy(waf if waf is not None else good_waf(hosts))
        self.dns: dict[str, dict] = {}
        for number, host in enumerate(sorted(hosts if dns_hosts is None else dns_hosts), 1):
            self.dns[host] = {
                "id": f"dns-{number}",
                "name": host,
                "type": "CNAME",
                "content": MTLS_TARGET,
                "proxied": True,
            }
        self.writes: list[tuple[str, str, dict | list | None]] = []

    def call(self, method: str, path: str, body: dict | list | None = None):
        if method == "GET":
            return self._get(path)
        body = copy.deepcopy(body)
        self.writes.append((method, path, body))
        if method == "PUT" and path == ASSOCIATIONS:
            self.association_hosts = list(body["hostnames"])
        elif method == "PATCH" and path == ACCESS:
            self.app.update(body)
        elif method in {"PATCH", "POST"} and "/rulesets/ruleset-1/rules" in path:
            replacement = {"id": "waf-1", **body}
            self.waf["rules"] = [replacement]
        elif method in {"PUT", "POST"} and "/dns_records" in path:
            record_id = path.rsplit("/", 1)[-1] if method == "PUT" else f"dns-{len(self.dns) + 1}"
            self.dns[body["name"]] = {"id": record_id, **body}
        elif method == "DELETE" and "/dns_records/" in path:
            record_id = path.rsplit("/", 1)[-1]
            self.dns = {name: record for name, record in self.dns.items() if record["id"] != record_id}
        return {}

    def _get(self, path: str):
        if path == ASSOCIATIONS:
            return {"hostnames": copy.deepcopy(self.association_hosts)}
        if path == ACCESS:
            return copy.deepcopy(self.app)
        if path == WAF_ENTRYPOINT:
            return copy.deepcopy(self.waf)
        if path.startswith(f"{DNS_COLLECTION}?"):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            name = query["name"][0]
            record = self.dns.get(name)
            return [] if record is None else [copy.deepcopy(record)]
        raise AssertionError(f"unexpected GET {path}")


def good_app(hosts: set[str]) -> dict:
    ordered = sorted(hosts)
    return {
        "id": register.ACCESS_APP_ID,
        "name": "existing-name-must-survive",
        "type": "self_hosted",
        "domain": f"tmp.{register.ZONE}",
        "self_hosted_domains": ordered,
        "destinations": [{"type": "public", "uri": host} for host in ordered],
        "policies": [
            {
                "id": "policy-1",
                "decision": "allow",
                "include": [{"email_domain": {"domain": "example.test"}}],
            }
        ],
        "sentinel": "must-survive",
    }


def good_waf(hosts: set[str], *, action: str = "block", enabled: bool = True) -> dict:
    return {
        "id": "ruleset-1",
        "rules": [
            {
                "id": "waf-1",
                "description": register.WAF_RULE_DESCRIPTION,
                "action": action,
                "enabled": enabled,
                "expression": expected_waf_expression(hosts),
            }
        ],
    }


def cname_body(host: str, tier: str = "mtls") -> dict:
    return {
        "type": "CNAME",
        "name": host,
        "content": f"{register.TUNNELS[tier]}.cfargotunnel.com",
        "proxied": True,
        "ttl": 1,
        "comment": f"nwp {tier} tunnel; managed by register-tunnel-hostname.py",
    }


def expected_access_body(hosts: set[str]) -> dict:
    ordered = sorted(hosts)
    body = {
        "self_hosted_domains": ordered,
        "destinations": [{"type": "public", "uri": host} for host in ordered],
    }
    assert set(body) == {"self_hosted_domains", "destinations"}
    return body


def expected_waf_expression(hosts: set[str]) -> str:
    quoted = " ".join(f'"{host}"' for host in sorted(hosts))
    return f"(not cf.tls_client_auth.cert_verified and http.host in {{{quoted}}})"


def expected_waf_body(hosts: set[str]) -> dict:
    body = {
        "action": "block",
        "expression": expected_waf_expression(hosts),
        "description": register.WAF_RULE_DESCRIPTION,
        "enabled": True,
    }
    assert body["action"] == "block"
    assert body["enabled"] is True
    assert body["expression"] == expected_waf_expression(hosts)
    return body


@contextlib.contextmanager
def patched(obj, name: str, value):
    previous = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, previous)


@contextlib.contextmanager
def captured():
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        yield stdout, stderr


def kubectl_result(namespaces: list[dict], ingresses_by_namespace: dict[str, list[dict]]):
    calls: list[list[str]] = []

    def run(args, *, capture_output, text, check):
        assert capture_output and text and check
        calls.append(list(args))
        if "namespaces" in args:
            items = namespaces
        else:
            assert "--all-namespaces" not in args, args
            namespace_name = args[args.index("--namespace") + 1]
            items = ingresses_by_namespace.get(namespace_name, [])
        payload = {"items": items}
        return Result(json.dumps(payload))

    return run, calls


def namespace(name: str, tenant: bool = True) -> dict:
    labels = {register.TENANT_LABEL: "true" if tenant else "false"}
    return {"metadata": {"name": name, "labels": labels}}


def ingress(namespace_name: str, name: str, host: str, ingress_class: str | None = None) -> dict:
    return {
        "metadata": {"namespace": namespace_name, "name": name},
        "spec": {
            "ingressClassName": register.MTLS_CLASS if ingress_class is None else ingress_class,
            "rules": [{"host": host}],
        },
    }


def expected_controls(
    hosts: set[str],
    *,
    waf_method: str = "PATCH",
) -> list[tuple[str, str, dict]]:
    ordered = sorted(hosts)
    waf_path = WAF_RULE if waf_method == "PATCH" else WAF_COLLECTION
    return [
        ("PUT", ASSOCIATIONS, {"hostnames": ordered}),
        ("PATCH", ACCESS, expected_access_body(hosts)),
        (waf_method, waf_path, expected_waf_body(hosts)),
    ]


def test_add_order() -> None:
    host = f"guacd.{register.ZONE}"
    before = {CANARY}
    desired = {CANARY, host}
    fake = FakeClient(before, waf={"id": "ruleset-1", "rules": []})
    before_app = copy.deepcopy(fake.app)
    register.converge_mtls(register.Edge(fake, False), {host})
    expected = expected_controls(desired, waf_method="POST") + [("POST", DNS_COLLECTION, cname_body(host))]
    assert fake.writes == expected, f"add writes:\n{fake.writes!r}"
    assert set(fake.writes[1][2]) == {"self_hosted_domains", "destinations"}
    for field in ("name", "domain", "policies", "sentinel"):
        assert fake.app[field] == before_app[field], (field, before_app[field], fake.app[field])


def test_remove_order() -> None:
    old = f"old.{register.ZONE}"
    before = {CANARY, old}
    desired = {CANARY}
    fake = FakeClient(before)
    register.converge_mtls(register.Edge(fake, False), set())
    expected = [
        ("DELETE", f"{DNS_COLLECTION}/dns-2", None),
        *expected_controls(desired),
    ]
    assert fake.writes == expected, f"remove writes:\n{fake.writes!r}"
    assert old not in fake.dns


def test_reconcile_drop_order() -> None:
    old = f"old.{register.ZONE}"
    keep = f"keep.{register.ZONE}"
    before = {CANARY, old}
    desired = {CANARY, keep}
    fake = FakeClient(before)
    run, _ = kubectl_result([namespace("tenant-a")], {"tenant-a": [ingress("tenant-a", "keep", keep)]})
    with patched(register.subprocess, "run", run), patched(register, "read_token", lambda: "fake-token"), patched(
        register, "Client", lambda _token: fake
    ):
        rc = register.main([str(SCRIPT), "--reconcile"])
    expected = [
        ("DELETE", f"{DNS_COLLECTION}/dns-2", None),
        *expected_controls(desired),
        ("POST", DNS_COLLECTION, cname_body(keep)),
    ]
    assert rc == 0
    assert fake.writes == expected, f"reconcile writes:\n{fake.writes!r}"


def test_dry_run_matches_apply_plan_without_writes() -> None:
    def normalise_transcript(output: str) -> str:
        lines = []
        for line in output.splitlines():
            if line.startswith("APPLY "):
                line = "CHANGE " + line.removeprefix("APPLY ")
            elif line.startswith("PLAN  "):
                line = "CHANGE " + line.removeprefix("PLAN  ")
            lines.append(line)
        return "\n".join(lines)

    scenarios = (
        ({CANARY}, {f"add.{register.ZONE}"}),
        ({CANARY, f"old.{register.ZONE}"}, set()),
    )
    for before, desired in scenarios:
        apply = FakeClient(before)
        dry = FakeClient(before)
        with captured() as (apply_stdout, _):
            register.converge_mtls(register.Edge(apply, False), desired)
        with captured() as (dry_stdout, _):
            register.converge_mtls(register.Edge(dry, True), desired)
        assert normalise_transcript(dry_stdout.getvalue()) == normalise_transcript(apply_stdout.getvalue())
        assert apply.writes
        assert dry.writes == []


def test_broken_access_blocks_removal_before_every_write() -> None:
    old = f"old.{register.ZONE}"
    app = good_app({CANARY, old})
    app["policies"] = []
    fake = FakeClient({CANARY, old}, app=app)
    try:
        register.converge_mtls(register.Edge(fake, False), set())
    except register.CloudflareError as error:
        assert "email_domain/otp" in str(error)
    else:
        raise AssertionError("accepted Access app without OTP/email-domain posture")
    assert fake.writes == []
    assert old in fake.dns


def test_every_unmanaged_cli_path_is_atomic() -> None:
    assert register.UNMANAGED_HOSTS == {
        register.ZONE,
        f"kasm.{register.ZONE}",
        f"www.{register.ZONE}",
        f"autoconfig.{register.ZONE}",
        f"localhost.{register.ZONE}",
    }
    argument_prefixes = (
        ["--tier", "mtls"],
        ["--tier", "mtls", "--remove"],
        ["--tier", "public"],
        ["--tier", "public", "--remove"],
    )

    def forbidden_token():
        raise AssertionError("host validation must finish before reading a token")

    with patched(register, "read_token", forbidden_token):
        for host in sorted(register.UNMANAGED_HOSTS):
            for prefix in argument_prefixes:
                with captured() as (_, stderr):
                    rc = register.main([str(SCRIPT), *prefix, host])
                assert rc != 0, (prefix, host)
                assert "reserved and unmanaged" in stderr.getvalue(), (prefix, host, stderr.getvalue())


def test_every_unmanaged_ingress_blocks_reconcile_without_writes() -> None:
    for host in sorted(register.UNMANAGED_HOSTS):
        fake = FakeClient({CANARY})
        run, _ = kubectl_result(
            [namespace("tenant-a")],
            {"tenant-a": [ingress("tenant-a", "reserved", host)]},
        )
        with patched(register.subprocess, "run", run), patched(register, "read_token", lambda: "fake-token"), patched(
            register, "Client", lambda _token: fake
        ), captured() as (_, stderr):
            rc = register.main([str(SCRIPT), "--reconcile"])
        assert rc != 0, host
        assert host in stderr.getvalue(), (host, stderr.getvalue())
        assert fake.writes == [], (host, fake.writes)


def test_both_canaries_are_refused_on_every_external_path() -> None:
    assert register.RESERVED_CANARY_HOSTS == frozenset(register.CANARIES.values())
    argument_prefixes = (
        ["--tier", "mtls"],
        ["--tier", "mtls", "--remove"],
        ["--tier", "public"],
        ["--tier", "public", "--remove"],
    )
    for host in sorted(register.RESERVED_CANARY_HOSTS):
        for prefix in argument_prefixes:
            fake = FakeClient({CANARY})
            with patched(register, "read_token", lambda: "fake-token"), patched(
                register, "Client", lambda _token: fake
            ), captured() as (_, stderr):
                rc = register.main([str(SCRIPT), *prefix, host])
            assert rc != 0, (prefix, host)
            assert "platform-reserved canary" in stderr.getvalue(), (prefix, host, stderr.getvalue())
            assert fake.writes == []

        fake = FakeClient({CANARY})
        run, _ = kubectl_result(
            [namespace("tenant-a")],
            {"tenant-a": [ingress("tenant-a", "reserved-canary", host)]},
        )
        with patched(register.subprocess, "run", run), patched(register, "read_token", lambda: "fake-token"), patched(
            register, "Client", lambda _token: fake
        ), captured() as (_, stderr):
            rc = register.main([str(SCRIPT), "--reconcile"])
        assert rc != 0, host
        assert host in stderr.getvalue(), (host, stderr.getvalue())
        assert fake.writes == []


def test_internal_pin_never_cross_claims_the_public_canary() -> None:
    public_canary = register.CANARIES["public"]
    host = f"new.{register.ZONE}"
    current = {CANARY, public_canary}
    fake = FakeClient(
        current,
        dns_hosts={CANARY},
        app=good_app(current),
        waf=good_waf(current),
        associations=sorted(current),
    )
    register.converge_mtls(register.Edge(fake, False), {host})
    desired = {CANARY, host}
    assert fake.writes == [
        ("PUT", ASSOCIATIONS, {"hostnames": sorted({*current, host})}),
        ("PATCH", ACCESS, expected_access_body(desired)),
        ("PATCH", WAF_RULE, expected_waf_body(desired)),
        ("POST", DNS_COLLECTION, cname_body(host)),
    ]
    for _, path, body in fake.writes:
        if path != ASSOCIATIONS:
            assert public_canary not in json.dumps(body)
    assert public_canary not in fake.dns

    # With no live association, external input, or DNS, only the internal mTLS
    # canary—not its public sibling—is pinned into all four managed controls.
    empty = FakeClient(set(), dns_hosts=set())
    register.converge_mtls(register.Edge(empty, False), set())
    assert empty.writes == [
        *expected_controls({CANARY}),
        ("POST", DNS_COLLECTION, cname_body(CANARY)),
    ]


def test_dns_ownership_refuses_records_before_any_write() -> None:
    host = f"app.{register.ZONE}"
    for record_type, content in (("A", "203.0.113.5"), ("CNAME", "foreign.example.net")):
        fake = FakeClient({CANARY}, dns_hosts={CANARY})
        fake.dns[host] = {
            "id": "foreign",
            "name": host,
            "type": record_type,
            "content": content,
            "proxied": True,
        }
        try:
            register.converge_mtls(register.Edge(fake, False), {host})
        except register.CloudflareError as error:
            assert "refusing to overwrite" in str(error)
        else:
            raise AssertionError(f"accepted {record_type} {content}")
        assert fake.writes == []

    www = f"www.{register.ZONE}"
    fake = FakeClient({CANARY}, dns_hosts=set())
    current = {"id": "www-a", "name": www, "type": "A", "content": "203.0.113.5", "proxied": True}
    try:
        register.Edge(fake, False).set_cname(www, "mtls", current)
    except register.CloudflareError:
        pass
    else:
        raise AssertionError("accepted unmanaged www A record")
    assert fake.writes == []


def test_stale_dns_preflight_is_atomic() -> None:
    old = f"old.{register.ZONE}"
    before = {CANARY, old}
    unsafe_records = (
        ("A", "203.0.113.5"),
        ("CNAME", "foreign.example.net"),
        ("CNAME", PUBLIC_TARGET),
    )
    for record_type, content in unsafe_records:
        fake = FakeClient(before, dns_hosts={CANARY})
        fake.dns[old] = {
            "id": "unsafe-stale",
            "name": old,
            "type": record_type,
            "content": content,
            "proxied": True,
        }
        try:
            register.converge_mtls(register.Edge(fake, False), set())
        except register.CloudflareError as error:
            assert "refusing to narrow its edge controls" in str(error)
        else:
            raise AssertionError(f"accepted stale {record_type} {content}")
        assert fake.writes == [], (record_type, content, fake.writes)

    # An absent stale record is already closed and therefore safe; controls
    # can be narrowed without issuing a DNS mutation.
    absent = FakeClient(before, dns_hosts={CANARY})
    register.converge_mtls(register.Edge(absent, False), set())
    assert absent.writes == expected_controls({CANARY})


def test_dns_ownership_allows_only_an_nwp_cname_retarget() -> None:
    host = f"move.{register.ZONE}"
    fake = FakeClient({CANARY}, dns_hosts=set())
    current = {
        "id": "public-cname",
        "name": host,
        "type": "CNAME",
        "content": PUBLIC_TARGET,
        "proxied": True,
    }
    register.Edge(fake, False).set_cname(host, "mtls", current)
    assert fake.writes == [("PUT", f"{DNS_COLLECTION}/public-cname", cname_body(host))]


def test_kasm_is_preserved_if_present_and_never_added() -> None:
    old = f"old.{register.ZONE}"
    kasm = f"kasm.{register.ZONE}"
    absent = FakeClient({CANARY}, associations=[CANARY, old])
    register.Edge(absent, False).set_associations({CANARY}, [CANARY, old])
    assert absent.writes == [("PUT", ASSOCIATIONS, {"hostnames": [CANARY]})]
    assert kasm not in absent.writes[0][2]["hostnames"]

    present = FakeClient({CANARY}, associations=[CANARY, kasm, old])
    register.Edge(present, False).set_associations({CANARY}, [CANARY, kasm, old])
    assert present.writes == [("PUT", ASSOCIATIONS, {"hostnames": sorted([CANARY, kasm])})]


def test_access_requires_otp_posture_before_writes() -> None:
    host = f"new.{register.ZONE}"
    invalid_policies = (
        [],
        [
            {
                "decision": "bypass",
                "include": [{"email_domain": {"domain": "example.test"}}],
            }
        ],
        [
            {
                "decision": "deny",
                "include": [{"email_domain": {"domain": "example.test"}}],
            }
        ],
        [{"include": [{"email_domain": {"domain": "example.test"}}]}],
        [{"decision": "allow", "include": [{"email_domain": {"domain": ""}}]}],
        [{"decision": "allow", "include": [{"otp": {}}]}],
    )
    for policies in invalid_policies:
        app = good_app({CANARY})
        app["policies"] = policies
        fake = FakeClient({CANARY}, app=app)
        try:
            register.converge_mtls(register.Edge(fake, False), {host})
        except register.CloudflareError as error:
            assert "email_domain/otp" in str(error)
        else:
            raise AssertionError(f"accepted invalid Access policies: {policies}")
        assert fake.writes == []

    app = good_app({CANARY})
    app["type"] = "saas"
    fake = FakeClient({CANARY}, app=app)
    try:
        register.converge_mtls(register.Edge(fake, False), {host})
    except register.CloudflareError as error:
        assert "not type self_hosted" in str(error)
    else:
        raise AssertionError("accepted non-self-hosted Access app")
    assert fake.writes == []

    desired = {CANARY, host}
    otp_app = good_app(desired)
    otp_app["policies"] = [
        {
            "decision": "allow",
            "include": [{"otp": {"enabled": True}}],
        }
    ]
    otp = FakeClient(desired, app=otp_app)
    register.converge_mtls(register.Edge(otp, False), {host})
    assert otp.writes == []


def test_waf_action_and_enabled_drift_are_repaired_before_dns() -> None:
    host = f"new.{register.ZONE}"
    desired = {CANARY, host}
    for action, enabled in (("block", False), ("log", True)):
        fake = FakeClient(
            desired,
            dns_hosts={CANARY},
            waf=good_waf(desired, action=action, enabled=enabled),
        )
        register.converge_mtls(register.Edge(fake, False), {host})
        assert fake.writes == [
            ("PATCH", WAF_RULE, expected_waf_body(desired)),
            ("POST", DNS_COLLECTION, cname_body(host)),
        ], (action, enabled, fake.writes)


def test_fully_converged_edge_performs_zero_writes() -> None:
    host = f"ready.{register.ZONE}"
    fake = FakeClient({CANARY, host})
    with captured():
        register.converge_mtls(register.Edge(fake, False), {host})
    assert fake.writes == []


def test_urlerror_is_concise_and_token_free() -> None:
    secret = "secret-token-must-not-appear"

    def unavailable(_request, timeout):
        assert timeout == 60
        raise urllib.error.URLError("simulated offline")

    with patched(register, "read_token", lambda: secret), patched(
        register.urllib.request, "urlopen", unavailable
    ), captured() as (stdout, stderr):
        rc = register.main([str(SCRIPT), "--tier", "mtls", f"app.{register.ZONE}"])
    output = stdout.getvalue() + stderr.getvalue()
    assert rc == 1
    assert "transport error: simulated offline" in output
    assert "Traceback" not in output
    assert secret not in output


def test_httperror_is_concise_and_token_free() -> None:
    secret = "different-secret-token-must-not-appear"

    def rejected(request, timeout):
        assert timeout == 60
        body = io.BytesIO(
            json.dumps(
                {
                    "success": False,
                    "errors": [{"code": 10000, "message": "Authentication error"}],
                }
            ).encode()
        )
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, body)

    with patched(register, "read_token", lambda: secret), patched(
        register.urllib.request, "urlopen", rejected
    ), captured() as (stdout, stderr):
        rc = register.main([str(SCRIPT), "--tier", "mtls", f"app.{register.ZONE}"])
    output = stdout.getvalue() + stderr.getvalue()
    assert rc == 1
    assert "10000: Authentication error" in output
    assert "Traceback" not in output
    assert secret not in output


def test_discovery_filters_namespaces_and_skips_malformed_nonfatally() -> None:
    valid = f"valid.{register.ZONE}"
    second = f"second.{register.ZONE}"
    missing_hosts = ingress("tenant-a", "missing-hosts", valid)
    missing_hosts["spec"]["rules"] = [{}, {"host": None}, {"host": ""}]
    namespaces = [
        namespace("tenant-z"),
        namespace("tenant-a"),
        namespace("not-a-tenant", tenant=False),
    ]
    ingresses = {
        "tenant-a": [
            ingress("tenant-a", "valid", valid.upper() + "."),
            ingress("tenant-a", "underscore", f"bad_host.{register.ZONE}"),
            ingress("tenant-a", "outside", "outside.example.net"),
            missing_hosts,
            ingress("tenant-a", "public", f"public.{register.ZONE}", "cf-tunnel-nwp-public"),
        ],
        "tenant-z": [ingress("tenant-z", "second", second)],
        # The fake would expose these if the implementation queried an
        # unlabelled namespace; the expected command list proves it does not.
        "not-a-tenant": [
            ingress("not-a-tenant", "reserved", f"kasm.{register.ZONE}"),
            ingress("not-a-tenant", "valid-but-foreign", f"foreign.{register.ZONE}"),
        ],
    }
    run, calls = kubectl_result(namespaces, ingresses)
    desired = {CANARY, valid, second}
    fake = FakeClient(desired)
    with patched(register.subprocess, "run", run), patched(register, "read_token", lambda: "fake-token"), patched(
        register, "Client", lambda _token: fake
    ), captured() as (_, stderr):
        rc = register.main([str(SCRIPT), "--reconcile"])
    assert rc == 0
    assert fake.writes == []
    assert stderr.getvalue().count("SKIP") == 5, stderr.getvalue()
    assert stderr.getvalue().count("Ingress rule has no non-empty host") == 3, stderr.getvalue()
    assert calls == [
        ["kubectl", "get", "namespaces", "--selector", f"{register.TENANT_LABEL}=true", "-o", "json"],
        ["kubectl", "get", "ingress", "--namespace", "tenant-a", "-o", "json"],
        ["kubectl", "get", "ingress", "--namespace", "tenant-z", "-o", "json"],
    ]


CASES = (
    ("add writes association, Access PATCH, WAF, then DNS", test_add_order),
    ("remove deletes stale DNS before narrowing all controls", test_remove_order),
    ("reconcile-with-drop preserves exact DNS-first order", test_reconcile_drop_order),
    (
        "dry-run prints the same add/remove plans and performs no writes",
        test_dry_run_matches_apply_plan_without_writes,
    ),
    (
        "broken Access posture blocks removal before every write",
        test_broken_access_blocks_removal_before_every_write,
    ),
    ("every unmanaged hostname is refused on every explicit CLI path", test_every_unmanaged_cli_path_is_atomic),
    (
        "every unmanaged hostname from an Ingress blocks reconcile atomically",
        test_every_unmanaged_ingress_blocks_reconcile_without_writes,
    ),
    (
        "both NWP canaries are refused on every external input path",
        test_both_canaries_are_refused_on_every_external_path,
    ),
    (
        "only the internal mTLS pin manages a canary",
        test_internal_pin_never_cross_claims_the_public_canary,
    ),
    ("A and foreign CNAME records are refused before any write", test_dns_ownership_refuses_records_before_any_write),
    ("every stale DNS record is ownership-preflighted atomically", test_stale_dns_preflight_is_atomic),
    ("only an existing NWP CNAME can be retargeted", test_dns_ownership_allows_only_an_nwp_cname_retarget),
    ("kasm association is preserved iff already present", test_kasm_is_preserved_if_present_and_never_added),
    ("Access must be self-hosted with an OTP/email-domain include", test_access_requires_otp_posture_before_writes),
    (
        "disabled or non-block WAF rules are repaired before DNS",
        test_waf_action_and_enabled_drift_are_repaired_before_dns,
    ),
    ("a fully converged edge performs zero writes", test_fully_converged_edge_performs_zero_writes),
    ("URLError becomes a concise token-free operational error", test_urlerror_is_concise_and_token_free),
    ("HTTPError becomes a concise token-free operational error", test_httperror_is_concise_and_token_free),
    (
        "discovery filters tenant namespaces and skips malformed hosts",
        test_discovery_filters_namespaces_and_skips_malformed_nonfatally,
    ),
)


def main() -> int:
    failures = 0
    for name, test in CASES:
        try:
            test()
        except Exception as error:  # noqa: BLE001 - selftest must report every case
            failures += 1
            print(f"FAIL: {name}: {type(error).__name__}: {error}")
        else:
            print(f"PASS: {name}")
    if failures:
        print(f"register-tunnel-hostname selftest: FAIL ({failures}/{len(CASES)} cases)")
        return 1
    print(f"register-tunnel-hostname selftest: PASS ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
