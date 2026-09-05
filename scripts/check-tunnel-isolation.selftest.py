#!/usr/bin/env python3
"""Regression self-test for the per-tunnel isolation guard.

Each case copies the real tunnel inventory into a temporary root, applies one
mutation that would reopen a concrete bypass, and asserts the guard rejects it.
The unmutated copy must pass, so a guard that has quietly stopped inspecting
anything cannot masquerade as a clean run.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-tunnel-isolation.py"
APPS = "clusters/talos-cluster/apps"
TEMPLATE_CNP = (
    "clusters/talos-cluster/tenants/_template/zero-touch/base/"
    "ciliumnetworkpolicy-allow-tunnel-proxy.yaml"
)

COPY_DIRS = ("cloudflared-", "traefik-")
COPY_FILES = (
    f"{APPS}/kyverno/policies/restrict-tunnel-binding.yaml",
    f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml",
    TEMPLATE_CNP,
)


@dataclass(frozen=True)
class Case:
    name: str
    expected_rc: int
    mutate: Callable[[Path], None]


def stage(destination: Path) -> None:
    apps_src = ROOT / APPS
    for entry in apps_src.iterdir():
        if entry.is_dir() and entry.name.startswith(COPY_DIRS):
            shutil.copytree(entry, destination / APPS / entry.name)
        elif entry.is_file() and entry.name.startswith("kustomization-traefik-"):
            target = destination / APPS / entry.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(entry, target)
    for relative in COPY_FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def edit(root: Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"self-test setup: {old!r} not found in {relative}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def noop(_root: Path) -> None:
    return None


def boolean_opt_in(root: Path) -> None:
    edit(
        root,
        f"{APPS}/traefik-nwp-mtls/ciliumnetworkpolicy.yaml",
        '"k8s:nwarila.io/tunnel-exposed": "nwp-mtls"',
        '"k8s:nwarila.io/tunnel-exposed": "true"',
    )


def sibling_opt_in(root: Path) -> None:
    edit(
        root,
        f"{APPS}/traefik-nwp-public/ciliumnetworkpolicy.yaml",
        '"k8s:nwarila.io/tunnel-exposed": "nwp-public"',
        '"k8s:nwarila.io/tunnel-exposed": "nwp-mtls"',
    )


def crossed_connector(root: Path) -> None:
    edit(
        root,
        f"{APPS}/cloudflared-nwp-public/ciliumnetworkpolicy.yaml",
        '"k8s:io.kubernetes.pod.namespace": traefik-nwp-public',
        '"k8s:io.kubernetes.pod.namespace": traefik-nwp-mtls',
    )


def wrong_watched_class(root: Path) -> None:
    edit(
        root,
        f"{APPS}/traefik-nwp-mtls/helmrelease.yaml",
        "ingressClass: cf-tunnel-nwp-mtls",
        "ingressClass: cf-tunnel-nwp-public",
    )


def template_allow_removed(root: Path) -> None:
    path = root / TEMPLATE_CNP
    documents = path.read_text(encoding="utf-8").split("---\n")
    kept = [d for d in documents if "allow-tunnel-proxy-nwp-mtls" not in d]
    path.write_text("---\n".join(kept), encoding="utf-8")


def template_boolean(root: Path) -> None:
    edit(root, TEMPLATE_CNP, "nwarila.io/tunnel-exposed: nwp-mtls", 'nwarila.io/tunnel-exposed: "true"')


def template_unknown_tunnel(root: Path) -> None:
    edit(root, TEMPLATE_CNP, "nwarila.io/tunnel-exposed: nwp-mtls", "nwarila.io/tunnel-exposed: nwp-ghost")


def fail_closed_rule_removed(root: Path) -> None:
    edit(
        root,
        f"{APPS}/cloudflared-nwp-public/configmap.yaml",
        "      - hostname: '*.secure.nicholaswarila.com'\n        service: http_status:404\n",
        "",
    )


def fail_closed_rule_reordered(root: Path) -> None:
    """Move the protected-zone guard behind the wildcard: first match wins."""
    path = root / f"{APPS}/cloudflared-nwp-public/configmap.yaml"
    text = path.read_text(encoding="utf-8")
    guard = "      - hostname: '*.secure.nicholaswarila.com'\n        service: http_status:404\n"
    wildcard = (
        "      - hostname: '*.nicholaswarila.com'\n"
        "        service: http://traefik-nwp-public.traefik-nwp-public.svc:80\n"
    )
    assert guard in text and wildcard in text, "self-test setup: route block changed"
    path.write_text(text.replace(guard, "", 1).replace(wildcard, wildcard + guard, 1), encoding="utf-8")


def out_of_zone_route(root: Path) -> None:
    edit(
        root,
        f"{APPS}/cloudflared-nwp-mtls/configmap.yaml",
        "      - hostname: '*.secure.nicholaswarila.com'\n        service: http://traefik-nwp-mtls",
        "      - hostname: '*.elsewhere.example.com'\n        service: http://traefik-nwp-mtls",
    )


def duplicate_tunnel_uuid(root: Path) -> None:
    public = (root / f"{APPS}/cloudflared-nwp-public/configmap.yaml").read_text(encoding="utf-8")
    uuid = [line.split("tunnel: ")[1].strip() for line in public.splitlines() if "tunnel: " in line][0]
    path = root / f"{APPS}/cloudflared-nwp-mtls/configmap.yaml"
    text = path.read_text(encoding="utf-8")
    existing = [line.split("tunnel: ")[1].strip() for line in text.splitlines() if "tunnel: " in line][0]
    path.write_text(text.replace(existing, uuid, 1), encoding="utf-8")


def class_deregistered(root: Path) -> None:
    edit(
        root,
        f"{APPS}/kyverno/policies/restrict-tunnel-binding.yaml",
        "['cf-tunnel-nwp-public', 'cf-tunnel-nwp-mtls']",
        "['cf-tunnel-nwp-public']",
    )


def protected_zone_dropped(root: Path) -> None:
    edit(
        root,
        f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml",
        "variables.class == 'cf-tunnel-nwp-public' ? 'secure.nicholaswarila.com' : ''",
        "variables.class == 'cf-tunnel-nwp-public' ? '' : ''",
    )


def zone_dropped(root: Path) -> None:
    edit(
        root,
        f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml",
        "variables.class == 'cf-tunnel-nwp-mtls' ? 'secure.nicholaswarila.com' : ''",
        "variables.class == 'cf-tunnel-nwp-mtls-absent' ? 'secure.nicholaswarila.com' : ''",
    )


def default_ingress_class(root: Path) -> None:
    edit(
        root,
        f"{APPS}/traefik-nwp-mtls/ingressclass.yaml",
        "metadata:\n  name: cf-tunnel-nwp-mtls\n",
        "metadata:\n  name: cf-tunnel-nwp-mtls\n  annotations:\n"
        '    ingressclass.kubernetes.io/is-default-class: "true"\n',
    )


CASES = (
    Case("unmutated inventory passes", 0, noop),
    Case("boolean opt-in on a proxy is rejected", 1, boolean_opt_in),
    Case("proxy selecting a sibling tunnel's origins is rejected", 1, sibling_opt_in),
    Case("connector wired to the sibling proxy is rejected", 1, crossed_connector),
    Case("proxy watching the sibling class is rejected", 1, wrong_watched_class),
    Case("missing inherited tenant allow is rejected", 1, template_allow_removed),
    Case("boolean opt-in in the tenant template is rejected", 1, template_boolean),
    Case("tenant allow for an unknown tunnel is rejected", 1, template_unknown_tunnel),
    Case("removed protected-zone fail-closed route is rejected", 1, fail_closed_rule_removed),
    Case("protected-zone route ordered after the wildcard is rejected", 1, fail_closed_rule_reordered),
    Case("connector routing outside its zone is rejected", 1, out_of_zone_route),
    Case("two connectors sharing one tunnel id is rejected", 1, duplicate_tunnel_uuid),
    Case("class with no admission registration is rejected", 1, class_deregistered),
    Case("dropped protectedZone under zone nesting is rejected", 1, protected_zone_dropped),
    Case("class with no zone is rejected", 1, zone_dropped),
    Case("default-class annotation on a tunnel class is rejected", 1, default_ingress_class),
)


def run_case(case: Case) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        stage(root)
        case.mutate(root)
        result = subprocess.run(
            [sys.executable, str(GUARD), str(root)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    passed = result.returncode == case.expected_rc
    detail = (result.stdout + result.stderr).strip().splitlines()
    return passed, (detail[-1] if detail else "<no output>")


def main() -> int:
    failures = 0
    for case in CASES:
        passed, detail = run_case(case)
        status = "OK  " if passed else "FAIL"
        print(f"{status} {case.name}")
        if not passed:
            failures += 1
            print(f"       expected rc={case.expected_rc}; last line: {detail}")
    if failures:
        print(f"check-tunnel-isolation.selftest: {failures} case(s) failed", file=sys.stderr)
        return 1
    print(f"check-tunnel-isolation.selftest: OK ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
