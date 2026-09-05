#!/usr/bin/env python3
"""Guard the per-tunnel isolation contract for Cloudflare Tunnel connectors.

An organization may run several tunnels at different protection tiers against
the same tenant namespaces. Namespace scoping cannot separate those tunnels
from each other, so the separation rests on three things staying in agreement:

  * the ``nwarila.io/tunnel-exposed`` pod label carrying the TUNNEL NAME rather
    than a boolean, so one pod is reachable from exactly one proxy;
  * each connector, proxy, and inherited tenant policy referencing only its own
    tunnel; and
  * the admission policies registering every class exactly once and barring an
    unprotected class from a protected zone nested inside its own.

Any one of those drifting silently republishes a protected origin on an
unauthenticated hostname. This guard fails closed on all three.

Usage: check-tunnel-isolation.py [REPO_ROOT]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

APPS = "clusters/talos-cluster/apps"
TEMPLATE_CNP = (
    "clusters/talos-cluster/tenants/_template/zero-touch/base/"
    "ciliumnetworkpolicy-allow-tunnel-proxy.yaml"
)
BINDING_POLICY = f"{APPS}/kyverno/policies/restrict-tunnel-binding.yaml"
HOSTNAME_POLICY = f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml"

EXPOSED_LABEL = "nwarila.io/tunnel-exposed"
PROXY_LABEL = "nwarila.io/tunnel-proxy"
RETIRED_BOOLEAN = "true"
CONTRACT_PORT = "8080"
CLASS_PREFIX = "cf-tunnel-"

UUID_RE = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
# `variables.class == 'cf-tunnel-x' ? 'value' :` and the org-keyed list form.
TERNARY_RE = re.compile(r"variables\.class == '([^']+)' \?\s*'([^']*)'")
ORG_CLASSES_RE = re.compile(r"variables\.org == '([^']+)' \?\s*\[([^\]]*)\]")
QUOTED_RE = re.compile(r"'([^']+)'")


class Findings:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def check(self, condition: bool, message: str) -> bool:
        if not condition:
            self.errors.append(message)
        return condition


def load(root: Path, relative: str) -> object:
    path = root / relative
    if not path.is_file():
        raise FileNotFoundError(relative)
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_all(root: Path, relative: str) -> list[dict]:
    path = root / relative
    if not path.is_file():
        raise FileNotFoundError(relative)
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]


def discover_tunnels(root: Path) -> list[str]:
    apps = root / APPS
    if not apps.is_dir():
        return []
    names = [
        path.name[len("cloudflared-") :]
        for path in sorted(apps.iterdir())
        if path.is_dir() and path.name.startswith("cloudflared-")
    ]
    return names


def endpoint_namespaces(entries: list[dict], prefix: str) -> list[dict]:
    """Selectors whose namespace label starts with prefix."""
    out = []
    for entry in entries or []:
        labels = entry.get("matchLabels", {})
        namespace = labels.get("k8s:io.kubernetes.pod.namespace", "")
        if namespace.startswith(prefix):
            out.append(labels)
    return out


def check_connector(root: Path, tunnel: str, found: Findings) -> None:
    base = f"{APPS}/cloudflared-{tunnel}"
    cnp = load(root, f"{base}/ciliumnetworkpolicy.yaml")
    spec = cnp["spec"]

    selector = spec["endpointSelector"]["matchLabels"]
    found.check(
        selector.get("app.kubernetes.io/instance") == tunnel,
        f"{base}/ciliumnetworkpolicy.yaml: endpointSelector instance must be {tunnel!r}",
    )

    proxy_targets = endpoint_namespaces(
        [sel for rule in spec.get("egress", []) for sel in rule.get("toEndpoints", [])],
        "traefik-",
    )
    found.check(
        len(proxy_targets) == 1,
        f"{base}/ciliumnetworkpolicy.yaml: expected exactly one traefik-* egress "
        f"target, found {len(proxy_targets)}",
    )
    for labels in proxy_targets:
        found.check(
            labels.get("k8s:io.kubernetes.pod.namespace") == f"traefik-{tunnel}",
            f"{base}/ciliumnetworkpolicy.yaml: connector may only reach "
            f"traefik-{tunnel}, found "
            f"{labels.get('k8s:io.kubernetes.pod.namespace')!r}",
        )
        found.check(
            labels.get(f"k8s:{PROXY_LABEL}") == tunnel,
            f"{base}/ciliumnetworkpolicy.yaml: proxy egress must select "
            f"{PROXY_LABEL}={tunnel!r}",
        )

    deployment = load(root, f"{base}/deployment.yaml")
    pod_labels = deployment["spec"]["template"]["metadata"]["labels"]
    found.check(
        pod_labels.get("app.kubernetes.io/instance") == tunnel,
        f"{base}/deployment.yaml: pod instance label must be {tunnel!r}",
    )


def parse_connector_routes(root: Path, tunnel: str) -> list[dict]:
    configmap = load(root, f"{APPS}/cloudflared-{tunnel}/configmap.yaml")
    config = yaml.safe_load(configmap["data"]["config.yaml"])
    return config


def check_connector_routes(
    root: Path,
    tunnel: str,
    zone: str,
    protected_zone: str,
    seen_uuids: dict[str, str],
    found: Findings,
) -> None:
    where = f"{APPS}/cloudflared-{tunnel}/configmap.yaml"
    config = parse_connector_routes(root, tunnel)

    uuid = str(config.get("tunnel", ""))
    if found.check(
        bool(UUID_RE.match(uuid)), f"{where}: tunnel id {uuid!r} is not a UUID"
    ):
        found.check(
            uuid not in seen_uuids,
            f"{where}: tunnel id {uuid} is already used by {seen_uuids.get(uuid)!r}",
        )
        seen_uuids.setdefault(uuid, tunnel)

    rules = config.get("ingress", [])
    found.check(bool(rules), f"{where}: ingress rules must not be empty")
    if not rules:
        return

    last = rules[-1]
    found.check(
        "hostname" not in last and str(last.get("service", "")).startswith("http_status:"),
        f"{where}: the final ingress rule must be a hostname-less http_status catch-all",
    )

    for rule in rules:
        hostname = rule.get("hostname")
        service = str(rule.get("service", ""))
        if hostname is None or service.startswith("http_status:"):
            continue
        bare = hostname[2:] if hostname.startswith("*.") else hostname
        found.check(
            bare == zone or bare.endswith(f".{zone}"),
            f"{where}: routed hostname {hostname!r} is outside the zone {zone!r} "
            f"this connector serves",
        )

    if not protected_zone:
        return

    # The unprotected connector must refuse the protected zone before its own
    # wildcard could swallow it, so losing the more specific DNS route fails
    # closed instead of publishing protected hostnames unauthenticated.
    def first_index(predicate) -> int:
        for index, rule in enumerate(rules):
            if predicate(rule):
                return index
        return -1

    wildcard_index = first_index(lambda r: r.get("hostname") == f"*.{zone}")
    for guarded in (f"*.{protected_zone}", protected_zone):
        index = first_index(
            lambda r, g=guarded: r.get("hostname") == g
            and str(r.get("service", "")).startswith("http_status:")
        )
        if not found.check(
            index >= 0,
            f"{where}: missing fail-closed http_status rule for {guarded!r}",
        ):
            continue
        found.check(
            wildcard_index < 0 or index < wildcard_index,
            f"{where}: the {guarded!r} rule must precede the {f'*.{zone}'!r} "
            f"wildcard; first match wins",
        )


def check_proxy(root: Path, tunnel: str, found: Findings) -> None:
    base = f"{APPS}/traefik-{tunnel}"
    cnp = load(root, f"{base}/ciliumnetworkpolicy.yaml")
    spec = cnp["spec"]

    found.check(
        spec["endpointSelector"]["matchLabels"].get(PROXY_LABEL) == tunnel,
        f"{base}/ciliumnetworkpolicy.yaml: endpointSelector must select "
        f"{PROXY_LABEL}={tunnel!r}",
    )

    sources = endpoint_namespaces(
        [sel for rule in spec.get("ingress", []) for sel in rule.get("fromEndpoints", [])],
        "cloudflared-",
    )
    found.check(
        len(sources) == 1,
        f"{base}/ciliumnetworkpolicy.yaml: expected exactly one cloudflared-* "
        f"ingress source, found {len(sources)}",
    )
    for labels in sources:
        found.check(
            labels.get("k8s:io.kubernetes.pod.namespace") == f"cloudflared-{tunnel}",
            f"{base}/ciliumnetworkpolicy.yaml: proxy may only accept traffic from "
            f"cloudflared-{tunnel}",
        )
        found.check(
            labels.get("k8s:app.kubernetes.io/instance") == tunnel,
            f"{base}/ciliumnetworkpolicy.yaml: connector ingress must pin "
            f"instance={tunnel!r}",
        )

    exposed = [
        (selector.get("matchLabels", {}), rule)
        for rule in spec.get("egress", [])
        for selector in rule.get("toEndpoints", [])
        if f"k8s:{EXPOSED_LABEL}" in selector.get("matchLabels", {})
    ]
    found.check(
        len(exposed) == 1,
        f"{base}/ciliumnetworkpolicy.yaml: expected exactly one {EXPOSED_LABEL} "
        f"egress selector, found {len(exposed)}",
    )
    for labels, rule in exposed:
        value = labels.get(f"k8s:{EXPOSED_LABEL}")
        found.check(
            value == tunnel,
            f"{base}/ciliumnetworkpolicy.yaml: {EXPOSED_LABEL} must be the tunnel "
            f"name {tunnel!r}, found {value!r}. A boolean opt-in would make this "
            f"proxy reach every tunnel's origins in the same namespace.",
        )
        ports = [
            str(port.get("port"))
            for entry in rule.get("toPorts", [])
            for port in entry.get("ports", [])
        ]
        found.check(
            ports == [CONTRACT_PORT],
            f"{base}/ciliumnetworkpolicy.yaml: origin contract port must remain "
            f"[{CONTRACT_PORT}], found {ports}",
        )

    release = load(root, f"{base}/helmrelease.yaml")
    values = release["spec"]["values"]
    providers = values.get("providers", {})
    ingress_provider = providers.get("kubernetesIngress", {})
    found.check(
        ingress_provider.get("ingressClass") == f"{CLASS_PREFIX}{tunnel}",
        f"{base}/helmrelease.yaml: proxy must watch class "
        f"{CLASS_PREFIX}{tunnel!r}, found {ingress_provider.get('ingressClass')!r}",
    )
    found.check(
        values.get("deployment", {}).get("podLabels", {}).get(PROXY_LABEL) == tunnel,
        f"{base}/helmrelease.yaml: pod label {PROXY_LABEL} must be {tunnel!r}",
    )
    for path, expected in (
        (("ingressClass", "enabled"), False),
        (("rbac", "enabled"), False),
        (("providers", "kubernetesCRD", "enabled"), False),
        (("providers", "kubernetesGateway", "enabled"), False),
        (("providers", "file", "enabled"), False),
        (("gateway", "enabled"), False),
    ):
        node = values
        for key in path:
            node = node.get(key, {}) if isinstance(node, dict) else {}
        found.check(
            node is expected,
            f"{base}/helmrelease.yaml: values.{'.'.join(path)} must be {expected}",
        )

    ingress_class = load(root, f"{base}/ingressclass.yaml")
    found.check(
        ingress_class["metadata"]["name"] == f"{CLASS_PREFIX}{tunnel}",
        f"{base}/ingressclass.yaml: name must be {CLASS_PREFIX}{tunnel}",
    )
    annotations = ingress_class["metadata"].get("annotations") or {}
    found.check(
        "ingressclass.kubernetes.io/is-default-class" not in annotations,
        f"{base}/ingressclass.yaml: the default-class annotation must be absent",
    )


def check_template(root: Path, tunnels: list[str], found: Findings) -> None:
    documents = load_all(root, TEMPLATE_CNP)
    by_tunnel: dict[str, dict] = {}
    for document in documents:
        selector = document["spec"]["endpointSelector"]["matchLabels"]
        value = selector.get(EXPOSED_LABEL)
        found.check(
            value != RETIRED_BOOLEAN,
            f"{TEMPLATE_CNP}: the retired boolean {EXPOSED_LABEL}={RETIRED_BOOLEAN!r} "
            f"opt-in makes a pod reachable from every tunnel proxy",
        )
        if value:
            found.check(
                value not in by_tunnel,
                f"{TEMPLATE_CNP}: duplicate policy for tunnel {value!r}",
            )
            by_tunnel[value] = document

    for tunnel in tunnels:
        document = by_tunnel.get(tunnel)
        if not found.check(
            document is not None,
            f"{TEMPLATE_CNP}: no inherited allow for tunnel {tunnel!r}; its origins "
            f"would be unreachable and the contract would drift silently",
        ):
            continue
        sources = [
            selector.get("matchLabels", {})
            for rule in document["spec"].get("ingress", [])
            for selector in rule.get("fromEndpoints", [])
        ]
        found.check(
            len(sources) == 1,
            f"{TEMPLATE_CNP}: tunnel {tunnel!r} must allow exactly one source",
        )
        for labels in sources:
            found.check(
                labels.get("k8s:io.kubernetes.pod.namespace") == f"traefik-{tunnel}",
                f"{TEMPLATE_CNP}: tunnel {tunnel!r} must accept only traefik-{tunnel}",
            )
            found.check(
                labels.get(f"k8s:{PROXY_LABEL}") == tunnel,
                f"{TEMPLATE_CNP}: tunnel {tunnel!r} must pin {PROXY_LABEL}={tunnel!r}",
            )

    for value in by_tunnel:
        found.check(
            value in tunnels,
            f"{TEMPLATE_CNP}: allow for unknown tunnel {value!r}; every tenant would "
            f"inherit a grant with no connector behind it",
        )


def parse_ternary_map(text: str, variable: str) -> dict[str, str]:
    """Extract the class -> literal map from a chained CEL ternary variable."""
    document = yaml.safe_load(text)
    for entry in document["spec"].get("variables", []):
        if entry.get("name") == variable:
            return dict(TERNARY_RE.findall(entry.get("expression", "")))
    return {}


def check_policies(root: Path, tunnels: list[str], found: Findings) -> tuple[dict, dict]:
    binding_text = (root / BINDING_POLICY).read_text(encoding="utf-8")
    binding = yaml.safe_load(binding_text)
    permitted: set[str] = set()
    for entry in binding["spec"].get("variables", []):
        if entry.get("name") == "permittedClasses":
            for _org, classes in ORG_CLASSES_RE.findall(entry.get("expression", "")):
                permitted.update(QUOTED_RE.findall(classes))

    expected_classes = {f"{CLASS_PREFIX}{tunnel}" for tunnel in tunnels}
    for missing in sorted(expected_classes - permitted):
        found.errors.append(
            f"{BINDING_POLICY}: class {missing!r} has a connector and proxy but is "
            f"registered for no organization; every tenant Ingress using it is denied"
        )
    for extra in sorted(permitted - expected_classes):
        found.errors.append(
            f"{BINDING_POLICY}: class {extra!r} is registered but has no "
            f"cloudflared-/traefik- pair behind it"
        )

    hostnames_text = (root / HOSTNAME_POLICY).read_text(encoding="utf-8")
    zones = parse_ternary_map(hostnames_text, "zone")
    protected = parse_ternary_map(hostnames_text, "protectedZone")
    canaries = parse_ternary_map(hostnames_text, "canaryHost")

    for klass in sorted(expected_classes):
        found.check(
            bool(zones.get(klass)),
            f"{HOSTNAME_POLICY}: class {klass!r} has no zone; its hostnames would be "
            f"unconstrained",
        )
        canary = canaries.get(klass, "")
        zone = zones.get(klass, "")
        if canary and zone:
            found.check(
                canary.endswith(f".{zone}"),
                f"{HOSTNAME_POLICY}: canary {canary!r} is outside zone {zone!r}",
            )

    # A zone nested inside another class's zone is only safe while the outer,
    # less protected class is explicitly barred from it.
    for outer, outer_zone in sorted(zones.items()):
        for inner, inner_zone in sorted(zones.items()):
            if outer == inner or not outer_zone or not inner_zone:
                continue
            if not inner_zone.endswith(f".{outer_zone}"):
                continue
            found.check(
                protected.get(outer) == inner_zone,
                f"{HOSTNAME_POLICY}: zone {inner_zone!r} ({inner}) nests inside "
                f"{outer_zone!r} ({outer}), so {outer} must declare protectedZone "
                f"{inner_zone!r}; found {protected.get(outer)!r}",
            )

    for klass, value in sorted(protected.items()):
        if not value:
            continue
        found.check(
            value in zones.values(),
            f"{HOSTNAME_POLICY}: {klass} declares protectedZone {value!r}, which is "
            f"not any class's zone",
        )

    return zones, protected


def check_no_retired_boolean(root: Path, found: Findings) -> None:
    literal = f'{EXPOSED_LABEL}": "{RETIRED_BOOLEAN}"'
    alternative = f"{EXPOSED_LABEL}: \"{RETIRED_BOOLEAN}\""
    for path in sorted((root / APPS).rglob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if literal in text or alternative in text:
            found.errors.append(
                f"{path.relative_to(root)}: the retired boolean opt-in "
                f"{EXPOSED_LABEL}={RETIRED_BOOLEAN!r} must not return; it makes one "
                f"pod reachable from every tunnel proxy watching its namespace"
            )


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    found = Findings()

    tunnels = discover_tunnels(root)
    if not tunnels:
        print("check-tunnel-isolation: no cloudflared-* apps found", file=sys.stderr)
        return 1

    try:
        for tunnel in tunnels:
            for required in (f"traefik-{tunnel}", f"kustomization-traefik-{tunnel}.yaml"):
                found.check(
                    (root / APPS / required).exists(),
                    f"{APPS}/{required} is missing for tunnel {tunnel!r}",
                )
            check_connector(root, tunnel, found)
            check_proxy(root, tunnel, found)

        zones, protected = check_policies(root, tunnels, found)

        seen_uuids: dict[str, str] = {}
        for tunnel in tunnels:
            klass = f"{CLASS_PREFIX}{tunnel}"
            check_connector_routes(
                root,
                tunnel,
                zones.get(klass, ""),
                protected.get(klass, ""),
                seen_uuids,
                found,
            )

        check_template(root, tunnels, found)
        check_no_retired_boolean(root, found)
    except (FileNotFoundError, KeyError, TypeError, yaml.YAMLError) as error:
        print(f"check-tunnel-isolation: unreadable tunnel inventory: {error!r}", file=sys.stderr)
        return 1

    if found.errors:
        print("check-tunnel-isolation: FAILED", file=sys.stderr)
        for error in found.errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        "check-tunnel-isolation: OK "
        f"({len(tunnels)} tunnels: {', '.join(tunnels)}; per-tunnel label, "
        "connector/proxy pairing, zone containment, and class registration verified)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
