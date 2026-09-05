#!/usr/bin/env python3
"""Regression self-test for the per-tunnel isolation guard.

Each case copies the real tunnel inventory (shared components, overlays,
policies, tenant template) into a temporary root, applies one mutation that
would reopen a concrete bypass, and asserts the guard rejects it. The
unmutated copy must pass, so a guard that has quietly stopped inspecting
anything cannot masquerade as a clean run.

Because connectors and proxies render from shared components, a bypass that
lives in a component needs two edits to survive the render: the resource value
AND the replacement that would otherwise overwrite it. The cases below make
both edits, exactly as a "simplifying" change would.
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
CONNECTOR = f"{APPS}/_components/tunnel-connector"
PROXY = f"{APPS}/_components/tunnel-proxy"
TEMPLATE_CNP = (
    "clusters/talos-cluster/tenants/_template/zero-touch/base/"
    "ciliumnetworkpolicy-allow-tunnel-proxy.yaml"
)
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
    for entry in (ROOT / APPS).iterdir():
        if entry.is_dir() and entry.name.startswith(("cloudflared-", "traefik-", "_components")):
            shutil.copytree(entry, destination / APPS / entry.name)
        elif entry.is_file() and entry.name.startswith("kustomization-traefik-"):
            (destination / APPS).mkdir(parents=True, exist_ok=True)
            shutil.copy2(entry, destination / APPS / entry.name)
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


def proxy_boolean_opt_in(root: Path) -> None:
    edit(root, f"{PROXY}/ciliumnetworkpolicy.yaml",
         '"k8s:nwarila.io/tunnel-exposed": "tunnelplaceholder"', '"k8s:nwarila.io/tunnel-exposed": "true"')
    edit(root, f"{PROXY}/kustomization.yaml",
         "          - spec.egress.1.toEndpoints.0.matchLabels.[k8s:nwarila.io/tunnel-exposed]\n", "")


def proxy_contract_names_sibling(root: Path) -> None:
    edit(root, f"{APPS}/traefik-nwp-public/kustomization.yaml", "tunnel=nwp-public", "tunnel=nwp-mtls")


def connector_contract_names_sibling(root: Path) -> None:
    edit(root, f"{APPS}/cloudflared-nwp-public/kustomization.yaml", "tunnel=nwp-public", "tunnel=nwp-mtls")


def proxy_watches_sibling_class(root: Path) -> None:
    edit(root, f"{PROXY}/helmrelease.yaml", "ingressClass: cf-tunnel-tunnelplaceholder", "ingressClass: cf-tunnel-nwp-mtls")
    edit(root, f"{PROXY}/kustomization.yaml",
         "      - select:\n          kind: HelmRelease\n        fieldPaths:\n"
         "          - spec.values.providers.kubernetesIngress.ingressClass\n"
         "        options:\n          delimiter: '-'\n          index: 2\n", "")


def placeholder_leaks(root: Path) -> None:
    edit(root, f"{CONNECTOR}/kustomization.yaml", "          - metadata.labels.[nwarila.io/platform-addon]\n", "")


def default_ingress_class(root: Path) -> None:
    edit(root, f"{PROXY}/ingressclass.yaml", "metadata:\n  name: cf-tunnel-tunnelplaceholder\n",
         "metadata:\n  name: cf-tunnel-tunnelplaceholder\n  annotations:\n"
         '    ingressclass.kubernetes.io/is-default-class: "true"\n')


def flux_child_wrong_path(root: Path) -> None:
    edit(root, f"{APPS}/kustomization-traefik-nwp-mtls.yaml",
         f"path: ./{APPS}/traefik-nwp-mtls", f"path: ./{APPS}/traefik-nwp-public")


def template_allow_removed(root: Path) -> None:
    path = root / TEMPLATE_CNP
    documents = path.read_text(encoding="utf-8").split("---\n")
    path.write_text("---\n".join(d for d in documents if "allow-tunnel-proxy-nwp-mtls" not in d), encoding="utf-8")


def template_boolean(root: Path) -> None:
    edit(root, TEMPLATE_CNP, "nwarila.io/tunnel-exposed: nwp-mtls", 'nwarila.io/tunnel-exposed: "true"')


def template_unknown_tunnel(root: Path) -> None:
    edit(root, TEMPLATE_CNP, "nwarila.io/tunnel-exposed: nwp-mtls", "nwarila.io/tunnel-exposed: nwp-ghost")


GUARD_RULE = "      - hostname: '*.secure.nicholaswarila.com'\n        service: http_status:404\n"
WILDCARD_RULE = (
    "      - hostname: '*.nicholaswarila.com'\n"
    "        service: http://traefik-nwp-public.traefik-nwp-public.svc:80\n"
)


def fail_closed_rule_removed(root: Path) -> None:
    edit(root, f"{APPS}/cloudflared-nwp-public/configmap.yaml", GUARD_RULE, "")


def fail_closed_rule_reordered(root: Path) -> None:
    """Move the protected-zone guard behind the wildcard: first match wins."""
    path = root / f"{APPS}/cloudflared-nwp-public/configmap.yaml"
    text = path.read_text(encoding="utf-8")
    assert GUARD_RULE in text and WILDCARD_RULE in text, "self-test setup: route block changed"
    path.write_text(text.replace(GUARD_RULE, "", 1).replace(WILDCARD_RULE, WILDCARD_RULE + GUARD_RULE, 1), encoding="utf-8")


def out_of_zone_route(root: Path) -> None:
    edit(root, f"{APPS}/cloudflared-nwp-mtls/configmap.yaml",
         "      - hostname: '*.secure.nicholaswarila.com'\n        service: http://traefik-nwp-mtls",
         "      - hostname: '*.elsewhere.example.com'\n        service: http://traefik-nwp-mtls")


def duplicate_tunnel_uuid(root: Path) -> None:
    def uuid_of(relative: str) -> str:
        text = (root / relative).read_text(encoding="utf-8")
        return next(line.split("tunnel: ")[1].strip() for line in text.splitlines() if "tunnel: " in line)

    public = uuid_of(f"{APPS}/cloudflared-nwp-public/configmap.yaml")
    mtls = f"{APPS}/cloudflared-nwp-mtls/configmap.yaml"
    edit(root, mtls, uuid_of(mtls), public)


def class_deregistered(root: Path) -> None:
    edit(root, f"{APPS}/kyverno/policies/restrict-tunnel-binding.yaml",
         "['cf-tunnel-nwp-public', 'cf-tunnel-nwp-mtls']", "['cf-tunnel-nwp-public']")


def protected_zone_dropped(root: Path) -> None:
    edit(root, f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml",
         "variables.class == 'cf-tunnel-nwp-public' ? 'secure.nicholaswarila.com' : ''",
         "variables.class == 'cf-tunnel-nwp-public' ? '' : ''")


def zone_dropped(root: Path) -> None:
    edit(root, f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml",
         "variables.class == 'cf-tunnel-nwp-mtls' ? 'secure.nicholaswarila.com' : ''",
         "variables.class == 'cf-tunnel-nwp-mtls-absent' ? 'secure.nicholaswarila.com' : ''")


CASES = (
    Case("unmutated inventory passes", 0, noop),
    Case("boolean opt-in in the proxy component is rejected", 1, proxy_boolean_opt_in),
    Case("proxy overlay contract naming the sibling tunnel is rejected", 1, proxy_contract_names_sibling),
    Case("connector overlay contract naming the sibling tunnel is rejected", 1, connector_contract_names_sibling),
    Case("proxy component hardwired to the sibling class is rejected", 1, proxy_watches_sibling_class),
    Case("a placeholder surviving the render is rejected", 1, placeholder_leaks),
    Case("default-class annotation on the tunnel class is rejected", 1, default_ingress_class),
    Case("Flux child Kustomization pointing at the wrong overlay is rejected", 1, flux_child_wrong_path),
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
    lines = (result.stdout + result.stderr).strip().splitlines()
    return result.returncode == case.expected_rc, (lines[-1] if lines else "<no output>")


def main() -> int:
    failures = 0
    for case in CASES:
        passed, detail = run_case(case)
        print(f"{'OK  ' if passed else 'FAIL'} {case.name}")
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
