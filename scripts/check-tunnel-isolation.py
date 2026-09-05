#!/usr/bin/env python3
"""Guard the per-tunnel isolation contract for Cloudflare Tunnel connectors.

An organization may run several tunnels at different protection tiers over the
same tenant namespace, so namespace scoping cannot separate them. Isolation
rests on three things staying in agreement:

  * the ``nwarila.io/tunnel-exposed`` pod label carrying the TUNNEL NAME rather
    than a boolean, so one pod is reachable from exactly one proxy;
  * each connector, proxy, and inherited tenant policy referencing only its own
    tunnel; and
  * the admission policies registering every class exactly once and barring an
    unprotected class from a protected zone nested inside its own; and
  * each overlay declaring its tier, with an mTLS-tier connector carrying the
    tunnel-wide Cloudflare Access JWT check and a public-tier connector NOT
    carrying it (which would lock every public hostname out).

Connectors and proxies render from shared kustomize components, so this guard
inspects what kustomize RENDERS for each overlay -- what Flux applies -- not
the component sources. A mis-set overlay contract, a dropped replacement (a
surviving placeholder), or a component edit that brings back a boolean all
surface in the render.

Usage: check-tunnel-isolation.py [REPO_ROOT]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from shutil import which

import yaml

APPS = "clusters/talos-cluster/apps"
TEMPLATE_CNP = (
    "clusters/talos-cluster/tenants/_template/zero-touch/base/"
    "ciliumnetworkpolicy-allow-tunnel-proxy.yaml"
)
BINDING_POLICY = f"{APPS}/kyverno/policies/restrict-tunnel-binding.yaml"
HOSTNAME_POLICY = f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml"

EXPOSED = "nwarila.io/tunnel-exposed"
PROXY = "nwarila.io/tunnel-proxy"
NS_LABEL = "k8s:io.kubernetes.pod.namespace"
INSTANCE = "app.kubernetes.io/instance"
CLASS_PREFIX = "cf-tunnel-"
ORIGIN_PORT = "8080"
TIERS = ("public", "mtls")
DISABLED_VALUES = (
    ("ingressClass", "enabled"),
    ("rbac", "enabled"),
    ("providers", "kubernetesCRD", "enabled"),
    ("providers", "kubernetesGateway", "enabled"),
    ("providers", "file", "enabled"),
    ("gateway", "enabled"),
)

UUID_RE = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
TERNARY_RE = re.compile(r"variables\.class == '([^']+)' \?\s*'([^']*)'")
ORG_CLASSES_RE = re.compile(r"variables\.org == '([^']+)' \?\s*\[([^\]]*)\]")
QUOTED_RE = re.compile(r"'([^']+)'")


class RenderError(RuntimeError):
    pass


class Guard:
    def __init__(self, root: Path, kubectl: str) -> None:
        self.root = root
        self.kubectl = kubectl
        self.errors: list[str] = []

    def check(self, condition: bool, message: str) -> bool:
        if not condition:
            self.errors.append(message)
        return condition

    def render(self, relative: str) -> tuple[str, dict[tuple[str, str], dict]]:
        proc = subprocess.run(
            [self.kubectl, "kustomize", str(self.root / relative)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RenderError(f"{relative}: {proc.stderr.strip()}")
        objects = {}
        for doc in yaml.safe_load_all(proc.stdout):
            if doc:
                objects[(doc["kind"], doc["metadata"]["name"])] = doc
        return proc.stdout, objects

    def load(self, relative: str) -> list[dict]:
        text = (self.root / relative).read_text(encoding="utf-8")
        return [doc for doc in yaml.safe_load_all(text) if doc]


def endpoint_selectors(rules: list | None, key: str):
    """Yield (matchLabels, ports) for every from/toEndpoints selector."""
    for rule in rules or []:
        ports = [
            str(port.get("port"))
            for entry in rule.get("toPorts", [])
            for port in entry.get("ports", [])
        ]
        for selector in rule.get(key, []):
            yield selector.get("matchLabels", {}), ports


def nested(mapping: dict, path: tuple[str, ...]):
    node = mapping
    for key in path:
        node = node.get(key, {}) if isinstance(node, dict) else {}
    return node


def parse_ternary_map(document: dict, variable: str) -> dict[str, str]:
    for entry in document["spec"].get("variables", []):
        if entry.get("name") == variable:
            return dict(TERNARY_RE.findall(entry.get("expression", "")))
    return {}


def check_connector(g: Guard, tunnel: str) -> dict | None:
    where = f"{APPS}/cloudflared-{tunnel} (rendered)"
    text, objects = g.render(f"{APPS}/cloudflared-{tunnel}")
    g.check("placeholder" not in text, f"{where}: an unresolved placeholder survived the render")

    deployment = objects.get(("Deployment", f"cloudflared-{tunnel}"))
    if g.check(deployment is not None, f"{where}: Deployment cloudflared-{tunnel} missing"):
        labels = deployment["spec"]["template"]["metadata"]["labels"]
        g.check(
            labels.get(INSTANCE) == tunnel,
            f"{where}: connector pod instance label is {labels.get(INSTANCE)!r}, not "
            f"{tunnel!r}; the overlay contract names a different tunnel than its directory",
        )

    cnp = objects.get(("CiliumNetworkPolicy", f"cloudflared-{tunnel}-egress"))
    if g.check(cnp is not None, f"{where}: connector CiliumNetworkPolicy missing"):
        g.check(
            cnp["spec"]["endpointSelector"]["matchLabels"].get(INSTANCE) == tunnel,
            f"{where}: connector policy must select instance {tunnel!r}",
        )
        proxies = [
            labels
            for labels, _ in endpoint_selectors(cnp["spec"].get("egress"), "toEndpoints")
            if labels.get(NS_LABEL, "").startswith("traefik-")
        ]
        g.check(len(proxies) == 1, f"{where}: expected exactly one proxy egress target, found {len(proxies)}")
        for labels in proxies:
            g.check(
                labels.get(NS_LABEL) == f"traefik-{tunnel}" and labels.get(f"k8s:{PROXY}") == tunnel,
                f"{where}: connector may only reach traefik-{tunnel} with {PROXY}={tunnel!r}, "
                f"found {labels.get(NS_LABEL)!r} / {labels.get(f'k8s:{PROXY}')!r}",
            )

    configmap = objects.get(("ConfigMap", "cloudflared-config"))
    if not g.check(configmap is not None, f"{where}: cloudflared-config ConfigMap missing"):
        return None
    return yaml.safe_load(configmap["data"]["config.yaml"])


def read_tier(g: Guard, tunnel: str) -> str:
    """The overlay's declared tier, from its tunnel-contract literals."""
    relative = f"{APPS}/cloudflared-{tunnel}/kustomization.yaml"
    (document,) = g.load(relative)
    literals: list[str] = []
    for generator in document.get("configMapGenerator", []):
        if generator.get("name") == "tunnel-contract":
            literals = generator.get("literals", [])
    tiers = [item.split("=", 1)[1] for item in literals if item.startswith("tier=")]
    if not g.check(len(tiers) == 1, f"{relative}: tunnel-contract must declare exactly one tier= literal, found {tiers}"):
        return ""
    g.check(tiers[0] in TIERS, f"{relative}: tier {tiers[0]!r} is not one of {TIERS}")
    return tiers[0]


def check_connector_tier(g: Guard, tunnel: str, tier: str, config: dict) -> None:
    """Connector-side posture follows the tier, never the other way round."""
    where = f"{APPS}/cloudflared-{tunnel}/configmap.yaml"
    access = nested(config, ("originRequest", "access"))
    if tier == "mtls":
        if not g.check(
            access.get("required") is True,
            f"{where}: an mTLS-tier connector must set originRequest.access.required: true "
            f"tunnel-wide, so a hostname whose edge registration is incomplete still cannot reach an origin",
        ):
            return
        auds = access.get("audTag") or []
        g.check(
            len(auds) >= 1 and all(re.fullmatch(r"[0-9a-f]{64}", str(a)) for a in auds),
            f"{where}: originRequest.access.audTag must list at least one 64-hex Access application aud, found {auds}",
        )
        g.check(bool(access.get("teamName")), f"{where}: originRequest.access.teamName must be set")
    elif tier == "public":
        g.check(
            not access,
            f"{where}: a public-tier connector must not require Cloudflare Access; every hostname "
            f"behind it would be locked out",
        )


def check_routes(g: Guard, tunnel: str, config: dict, zone: str, protected: str, seen: dict[str, str]) -> None:
    where = f"{APPS}/cloudflared-{tunnel}/configmap.yaml"
    uuid = str(config.get("tunnel", ""))
    if g.check(bool(UUID_RE.match(uuid)), f"{where}: tunnel id {uuid!r} is not a UUID"):
        g.check(uuid not in seen, f"{where}: tunnel id {uuid} is already used by {seen.get(uuid)!r}")
        seen.setdefault(uuid, tunnel)

    rules = config.get("ingress") or []
    if not g.check(bool(rules), f"{where}: ingress rules must not be empty"):
        return
    last = rules[-1]
    g.check(
        "hostname" not in last and str(last.get("service", "")).startswith("http_status:"),
        f"{where}: the final ingress rule must be a hostname-less http_status catch-all",
    )
    for rule in rules:
        hostname, service = rule.get("hostname"), str(rule.get("service", ""))
        if hostname is None or service.startswith("http_status:"):
            continue
        bare = hostname[2:] if hostname.startswith("*.") else hostname
        g.check(
            bare == zone or bare.endswith(f".{zone}"),
            f"{where}: routed hostname {hostname!r} is outside the zone {zone!r} this connector serves",
        )
    if not protected:
        return

    # The unprotected connector must refuse the protected zone before its own
    # wildcard could swallow it, so a lost DNS route fails closed.
    def first(predicate) -> int:
        return next((i for i, rule in enumerate(rules) if predicate(rule)), -1)

    wildcard = first(lambda r: r.get("hostname") == f"*.{zone}")
    for guarded in (f"*.{protected}", protected):
        index = first(
            lambda r, host=guarded: r.get("hostname") == host
            and str(r.get("service", "")).startswith("http_status:")
        )
        if g.check(index >= 0, f"{where}: missing fail-closed http_status rule for {guarded!r}"):
            g.check(
                wildcard < 0 or index < wildcard,
                f"{where}: the {guarded!r} rule must precede the '*.{zone}' wildcard; first match wins",
            )


def check_proxy(g: Guard, tunnel: str) -> None:
    where = f"{APPS}/traefik-{tunnel} (rendered)"
    text, objects = g.render(f"{APPS}/traefik-{tunnel}")
    g.check("placeholder" not in text, f"{where}: an unresolved placeholder survived the render")

    klass = f"{CLASS_PREFIX}{tunnel}"
    ingress_class = objects.get(("IngressClass", klass))
    if g.check(ingress_class is not None, f"{where}: IngressClass {klass} missing"):
        annotations = ingress_class["metadata"].get("annotations") or {}
        g.check(
            "ingressclass.kubernetes.io/is-default-class" not in annotations,
            f"{where}: the default-class annotation must be absent from {klass}",
        )

    tenant = ""
    release = objects.get(("HelmRelease", f"traefik-{tunnel}"))
    if g.check(release is not None, f"{where}: HelmRelease traefik-{tunnel} missing"):
        values = release["spec"]["values"]
        provider = nested(values, ("providers", "kubernetesIngress"))
        g.check(
            provider.get("ingressClass") == klass,
            f"{where}: proxy must watch class {klass!r}, found {provider.get('ingressClass')!r}",
        )
        watched = provider.get("namespaces") or []
        if g.check(len(watched) == 1, f"{where}: proxy must watch exactly one tenant namespace, found {watched}"):
            tenant = watched[0]
        g.check(
            nested(values, ("deployment", "podLabels")).get(PROXY) == tunnel,
            f"{where}: proxy pod label {PROXY} must be {tunnel!r}",
        )
        for path in DISABLED_VALUES:
            g.check(nested(values, path) is False, f"{where}: values.{'.'.join(path)} must be false")

    for kind in ("Role", "RoleBinding"):
        obj = objects.get((kind, f"traefik-{tunnel}"))
        if g.check(obj is not None, f"{where}: {kind} traefik-{tunnel} missing"):
            g.check(
                obj["metadata"].get("namespace") == tenant,
                f"{where}: {kind} lives in {obj['metadata'].get('namespace')!r}, not the watched tenant {tenant!r}",
            )

    cnp = objects.get(("CiliumNetworkPolicy", f"traefik-{tunnel}-network"))
    if not g.check(cnp is not None, f"{where}: proxy CiliumNetworkPolicy missing"):
        return
    spec = cnp["spec"]
    g.check(
        spec["endpointSelector"]["matchLabels"].get(PROXY) == tunnel,
        f"{where}: proxy policy must select {PROXY}={tunnel!r}",
    )
    sources = [
        labels
        for labels, _ in endpoint_selectors(spec.get("ingress"), "fromEndpoints")
        if labels.get(NS_LABEL, "").startswith("cloudflared-")
    ]
    g.check(len(sources) == 1, f"{where}: expected exactly one connector ingress source, found {len(sources)}")
    for labels in sources:
        g.check(
            labels.get(NS_LABEL) == f"cloudflared-{tunnel}" and labels.get(f"k8s:{INSTANCE}") == tunnel,
            f"{where}: proxy may only accept traffic from cloudflared-{tunnel} instance {tunnel!r}",
        )
    origins = [
        (labels, ports)
        for labels, ports in endpoint_selectors(spec.get("egress"), "toEndpoints")
        if f"k8s:{EXPOSED}" in labels
    ]
    g.check(len(origins) == 1, f"{where}: expected exactly one {EXPOSED} egress selector, found {len(origins)}")
    for labels, ports in origins:
        value = labels.get(f"k8s:{EXPOSED}")
        g.check(
            value == tunnel,
            f"{where}: {EXPOSED} must be the tunnel name {tunnel!r}, found {value!r}; a boolean "
            f"opt-in would make this proxy reach every tunnel's origins in the same namespace",
        )
        g.check(ports == [ORIGIN_PORT], f"{where}: origin contract port must remain [{ORIGIN_PORT}], found {ports}")
        g.check(
            labels.get(NS_LABEL) == tenant,
            f"{where}: origin egress targets {labels.get(NS_LABEL)!r}, not the watched tenant {tenant!r}",
        )


def check_flux_child(g: Guard, tunnel: str) -> None:
    relative = f"{APPS}/kustomization-traefik-{tunnel}.yaml"
    if not g.check((g.root / relative).is_file(), f"{relative} is missing; the proxy overlay would never be applied"):
        return
    (document,) = g.load(relative)
    g.check(
        document["spec"].get("path") == f"./{APPS}/traefik-{tunnel}",
        f"{relative}: spec.path must be ./{APPS}/traefik-{tunnel}",
    )


def check_template(g: Guard, tunnels: list[str]) -> None:
    by_tunnel: dict[str, dict] = {}
    for document in g.load(TEMPLATE_CNP):
        value = document["spec"]["endpointSelector"]["matchLabels"].get(EXPOSED)
        g.check(value != "true", f"{TEMPLATE_CNP}: the boolean opt-in {EXPOSED}=\"true\" makes a pod reachable from every proxy")
        if value:
            g.check(value not in by_tunnel, f"{TEMPLATE_CNP}: duplicate policy for tunnel {value!r}")
            by_tunnel[value] = document
    for tunnel in tunnels:
        document = by_tunnel.get(tunnel)
        if not g.check(document is not None, f"{TEMPLATE_CNP}: no inherited allow for tunnel {tunnel!r}"):
            continue
        sources = [labels for labels, _ in endpoint_selectors(document["spec"].get("ingress"), "fromEndpoints")]
        g.check(len(sources) == 1, f"{TEMPLATE_CNP}: tunnel {tunnel!r} must allow exactly one source")
        for labels in sources:
            g.check(
                labels.get(NS_LABEL) == f"traefik-{tunnel}" and labels.get(f"k8s:{PROXY}") == tunnel,
                f"{TEMPLATE_CNP}: tunnel {tunnel!r} must accept only traefik-{tunnel} with {PROXY}={tunnel!r}",
            )
    for value in by_tunnel:
        g.check(value in tunnels, f"{TEMPLATE_CNP}: allow for unknown tunnel {value!r}; no connector exists behind it")


def check_policies(g: Guard, tunnels: list[str]) -> tuple[dict, dict]:
    (binding,) = g.load(BINDING_POLICY)
    permitted: set[str] = set()
    for entry in binding["spec"].get("variables", []):
        if entry.get("name") == "permittedClasses":
            for _org, classes in ORG_CLASSES_RE.findall(entry.get("expression", "")):
                permitted.update(QUOTED_RE.findall(classes))
    expected = {f"{CLASS_PREFIX}{tunnel}" for tunnel in tunnels}
    for missing in sorted(expected - permitted):
        g.errors.append(f"{BINDING_POLICY}: class {missing!r} has a connector and proxy but no organization may use it")
    for extra in sorted(permitted - expected):
        g.errors.append(f"{BINDING_POLICY}: class {extra!r} is registered but has no connector/proxy pair behind it")

    (hostnames,) = g.load(HOSTNAME_POLICY)
    zones = parse_ternary_map(hostnames, "zone")
    protected = parse_ternary_map(hostnames, "protectedZone")
    canaries = parse_ternary_map(hostnames, "canaryHost")
    for klass in sorted(expected):
        zone = zones.get(klass, "")
        g.check(bool(zone), f"{HOSTNAME_POLICY}: class {klass!r} has no zone; its hostnames would be unconstrained")
        canary = canaries.get(klass, "")
        if canary and zone:
            g.check(canary.endswith(f".{zone}"), f"{HOSTNAME_POLICY}: canary {canary!r} is outside zone {zone!r}")
    # A zone nested inside another class's zone is only safe while the outer,
    # less protected class is explicitly barred from it.
    for outer, outer_zone in sorted(zones.items()):
        for inner, inner_zone in sorted(zones.items()):
            if outer != inner and outer_zone and inner_zone.endswith(f".{outer_zone}"):
                g.check(
                    protected.get(outer) == inner_zone,
                    f"{HOSTNAME_POLICY}: zone {inner_zone!r} ({inner}) nests inside {outer_zone!r} ({outer}), "
                    f"so {outer} must declare protectedZone {inner_zone!r}; found {protected.get(outer)!r}",
                )
    for klass, value in sorted(protected.items()):
        g.check(not value or value in zones.values(), f"{HOSTNAME_POLICY}: {klass} protectedZone {value!r} is not any class's zone")
    return zones, protected


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    kubectl = which("kubectl")
    if not kubectl:
        print("check-tunnel-isolation: kubectl is required to render the overlays", file=sys.stderr)
        return 1
    g = Guard(root, kubectl)
    apps = root / APPS
    tunnels = sorted(p.name[len("cloudflared-"):] for p in apps.iterdir() if p.is_dir() and p.name.startswith("cloudflared-")) if apps.is_dir() else []
    if not tunnels:
        print("check-tunnel-isolation: no cloudflared-* overlays found", file=sys.stderr)
        return 1
    try:
        configs = {}
        for tunnel in tunnels:
            configs[tunnel] = check_connector(g, tunnel)
            tier = read_tier(g, tunnel)
            if configs[tunnel] is not None and tier:
                check_connector_tier(g, tunnel, tier, configs[tunnel])
            check_proxy(g, tunnel)
            check_flux_child(g, tunnel)
        zones, protected = check_policies(g, tunnels)
        seen: dict[str, str] = {}
        for tunnel, config in configs.items():
            if config is not None:
                klass = f"{CLASS_PREFIX}{tunnel}"
                check_routes(g, tunnel, config, zones.get(klass, ""), protected.get(klass, ""), seen)
        check_template(g, tunnels)
    except (RenderError, FileNotFoundError, KeyError, TypeError, ValueError, yaml.YAMLError) as error:
        print(f"check-tunnel-isolation: unreadable tunnel inventory: {error}", file=sys.stderr)
        return 1
    if g.errors:
        print("check-tunnel-isolation: FAILED", file=sys.stderr)
        for error in g.errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(
        f"check-tunnel-isolation: OK ({len(tunnels)} tunnels: {', '.join(tunnels)}; rendered "
        "connector/proxy pairing, per-tunnel label, tier posture, zone containment, and class registration verified)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
