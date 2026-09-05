#!/usr/bin/env python3
"""Guard the per-tunnel isolation contract for Cloudflare Tunnel connectors.

An organization may run several tunnels at different protection tiers over the
same tenant namespace, so namespace scoping cannot separate them. Isolation
rests on the tunnel inventory, rendered policy objects, exact policy rule
shapes, tenant ownership, route tables, and admission-policy registrations all
staying in agreement.

Connectors and proxies render from shared kustomize components, so enforcement
checks inspect what kustomize renders for each overlay -- what Flux applies.
The pruned overlay ``tier=`` literal remains an auditable declaration, but it
must agree with the fixed ``CLASS_TIERS`` map and never defines posture itself.

Usage: check-tunnel-isolation.py [REPO_ROOT]
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from shutil import which

import yaml

APPS = "clusters/talos-cluster/apps"
TENANTS = "clusters/talos-cluster/tenants"
TEMPLATE_CNP = (
    f"{TENANTS}/_template/zero-touch/base/"
    "ciliumnetworkpolicy-allow-tunnel-proxy.yaml"
)
BINDING_POLICY = f"{APPS}/kyverno/policies/restrict-tunnel-binding.yaml"
HOSTNAME_POLICY = f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml"
APPS_INDEX = f"{APPS}/kustomization.yaml"

EXPOSED = "nwarila.io/tunnel-exposed"
PROXY = "nwarila.io/tunnel-proxy"
NS_LABEL = "k8s:io.kubernetes.pod.namespace"
INSTANCE = "app.kubernetes.io/instance"
NAME = "app.kubernetes.io/name"
CLASS_PREFIX = "cf-tunnel-"
POLICY_KINDS = {
    "CiliumNetworkPolicy",
    "CiliumClusterwideNetworkPolicy",
    "NetworkPolicy",
}
TUNNEL_TENANTS = {
    "hwg": "hwg-1268831311",
    "nwp-public": "nwp-1306985678",
    "nwp-mtls": "nwp-1306985678",
}
CLASS_TIERS = {
    "cf-tunnel-hwg": "public",
    "cf-tunnel-nwp-public": "public",
    "cf-tunnel-nwp-mtls": "mtls",
}
DISABLED_VALUES = (
    ("ingressClass", "enabled"),
    ("rbac", "enabled"),
    ("providers", "kubernetesCRD", "enabled"),
    ("providers", "kubernetesGateway", "enabled"),
    ("providers", "file", "enabled"),
    ("gateway", "enabled"),
)

UUID_RE = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
ACCESS_AUD_RE = re.compile(r"^[0-9a-f]{64}$")
TERNARY_RE = re.compile(r"variables\.class == '([^']+)' \?\s*'([^']*)'")
LIST_TERNARY_RE = re.compile(
    r"variables\.class == '([^']+)'\s*\?\s*\[([^\]]*)\]"
)
LIST_ITEM_RE = re.compile(r"\s*'([^']*)'\s*")
ORG_CLASSES_RE = re.compile(r"variables\.org == '([^']+)' \?\s*\[([^\]]*)\]")
QUOTED_RE = re.compile(r"'([^']+)'")
CHILD_RE = re.compile(r"kustomization-traefik-(.+)\.ya?ml")
CONNECTOR_INDEX_RE = re.compile(r"cloudflared-([^/]+)/?")
RETIRED_BOOLEAN_RE = re.compile(
    r"""(?:"(?:k8s:)?nwarila\.io/tunnel-exposed"|'(?:k8s:)?nwarila\.io/tunnel-exposed'|"""
    r"""(?:k8s:)?nwarila\.io/tunnel-exposed)\s*:\s*(?:"true"|'true')"""
)


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

    def render(self, relative: str) -> tuple[str, list[dict]]:
        proc = subprocess.run(
            [self.kubectl, "kustomize", str(self.root / relative)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RenderError(f"{relative}: {proc.stderr.strip()}")
        objects: list[dict] = []
        for position, document in enumerate(yaml.safe_load_all(proc.stdout), start=1):
            if document is None:
                continue
            if not isinstance(document, dict):
                raise RenderError(
                    f"{relative}: rendered document {position} is not a mapping"
                )
            objects.append(document)
        return proc.stdout, objects

    def load(self, relative: str) -> list[dict]:
        text = (self.root / relative).read_text(encoding="utf-8")
        documents: list[dict] = []
        for position, document in enumerate(yaml.safe_load_all(text), start=1):
            if document is None:
                continue
            if not isinstance(document, dict):
                raise ValueError(f"{relative}: document {position} is not a mapping")
            documents.append(document)
        return documents


def nested(mapping: dict, path: tuple[str, ...]):
    node = mapping
    for key in path:
        node = node.get(key, {}) if isinstance(node, dict) else {}
    return node


def metadata(document: dict) -> dict:
    value = document.get("metadata")
    return value if isinstance(value, dict) else {}


def object_identity(document: dict) -> tuple[str, str, str | None]:
    meta = metadata(document)
    kind = str(document.get("kind", "<missing-kind>"))
    name = str(meta.get("name", "<missing-name>"))
    namespace = meta.get("namespace")
    return kind, name, str(namespace) if namespace is not None else None


def identity_label(identity: tuple[str, str, str | None]) -> str:
    kind, name, namespace = identity
    scope = f" namespace {namespace!r}" if namespace is not None else ""
    return f"{kind}/{name}{scope}"


def find_object(
    g: Guard,
    objects: list[dict],
    kind: str,
    name: str,
    where: str,
) -> dict | None:
    matches = [
        document
        for document in objects
        if document.get("kind") == kind and metadata(document).get("name") == name
    ]
    if not g.check(
        len(matches) == 1,
        f"{where}: expected exactly one {kind}/{name}, found {len(matches)}",
    ):
        return None
    return matches[0]


def check_policy_inventory(
    g: Guard,
    where: str,
    objects: list[dict],
    expected: list[tuple[str, str, str | None]],
    *,
    all_documents: bool = False,
    noun: str = "rendered policy",
) -> None:
    actual = Counter(
        object_identity(document)
        for document in objects
        if all_documents or document.get("kind") in POLICY_KINDS
    )
    allowed = Counter(expected)
    for identity, count in sorted(
        actual.items(),
        key=lambda item: identity_label(item[0]),
    ):
        if identity not in allowed:
            g.errors.append(f"{where}: unexpected {noun} {identity_label(identity)}")
        elif count != allowed[identity]:
            g.errors.append(
                f"{where}: {noun} {identity_label(identity)} appears {count} times; "
                f"expected exactly {allowed[identity]}"
            )
    for identity, count in sorted(
        allowed.items(),
        key=lambda item: identity_label(item[0]),
    ):
        if actual[identity] < count:
            g.errors.append(f"{where}: missing {noun} {identity_label(identity)}")


def rule_signature(rule: object) -> str:
    return json.dumps(rule, sort_keys=True, separators=(",", ":"))


def exact_rule_set(actual: object, expected: list[dict]) -> bool:
    return isinstance(actual, list) and Counter(
        rule_signature(rule) for rule in actual
    ) == Counter(rule_signature(rule) for rule in expected)


def ports(port: str, protocol: str) -> list[dict]:
    return [{"ports": [{"port": port, "protocol": protocol}]}]


def connector_rules(tunnel: str) -> list[dict]:
    rules = [
        {
            "toEndpoints": [
                {
                    "matchLabels": {
                        NS_LABEL: "kube-system",
                        "k8s:k8s-app": "kube-dns",
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        {"port": "53", "protocol": "ANY"},
                    ],
                    "rules": {"dns": [{"matchPattern": "*"}]},
                }
            ],
        },
        {
            "toFQDNs": [
                {"matchName": "region1.v2.argotunnel.com"},
                {"matchName": "region2.v2.argotunnel.com"},
            ],
            "toPorts": [
                {
                    "ports": [
                        {"port": "7844", "protocol": "TCP"},
                        {"port": "7844", "protocol": "UDP"},
                    ]
                }
            ],
        },
        {
            "toEndpoints": [
                {
                    "matchLabels": {
                        NS_LABEL: f"traefik-{tunnel}",
                        f"k8s:{PROXY}": tunnel,
                    }
                }
            ],
            "toPorts": ports("8000", "TCP"),
        },
    ]
    if tunnel == "hwg":
        rules.append(
            {
                "toEndpoints": [
                    {
                        "matchLabels": {
                            "k8s:app.kubernetes.io/name": "hello-hwg",
                            NS_LABEL: "hello-hwg",
                        }
                    }
                ],
                "toPorts": ports("8080", "TCP"),
            }
        )
    return rules


def proxy_ingress_rule(tunnel: str) -> dict:
    return {
        "fromEndpoints": [
            {
                "matchLabels": {
                    f"k8s:{INSTANCE}": tunnel,
                    f"k8s:{NAME}": "cloudflared",
                    NS_LABEL: f"cloudflared-{tunnel}",
                }
            }
        ],
        "toPorts": ports("8000", "TCP"),
    }


def proxy_egress_rules(tunnel: str, tenant: str) -> list[dict]:
    return [
        {
            "toEntities": ["kube-apiserver"],
            "toPorts": ports("6443", "TCP"),
        },
        {
            "toEndpoints": [
                {
                    "matchLabels": {
                        NS_LABEL: tenant,
                        f"k8s:{EXPOSED}": tunnel,
                    }
                }
            ],
            "toPorts": ports("8080", "TCP"),
        },
    ]


def template_ingress_rule(tunnel: str) -> dict:
    return {
        "fromEndpoints": [
            {
                "matchLabels": {
                    NS_LABEL: f"traefik-{tunnel}",
                    f"k8s:{PROXY}": tunnel,
                }
            }
        ],
        "toPorts": ports("8080", "TCP"),
    }


def parse_ternary_map(document: dict, variable: str) -> dict[str, str]:
    spec = document.get("spec")
    variables = spec.get("variables", []) if isinstance(spec, dict) else []
    for entry in variables:
        if isinstance(entry, dict) and entry.get("name") == variable:
            return dict(TERNARY_RE.findall(str(entry.get("expression", ""))))
    return {}


def parse_list_ternary_map(
    document: dict,
    variable: str,
) -> dict[str, list[str]]:
    spec = document.get("spec")
    variables = spec.get("variables", []) if isinstance(spec, dict) else []
    for entry in variables:
        if isinstance(entry, dict) and entry.get("name") == variable:
            values: defaultdict[str, list[str]] = defaultdict(list)
            for klass, raw_items in LIST_TERNARY_RE.findall(
                str(entry.get("expression", ""))
            ):
                if not raw_items.strip():
                    continue
                for raw_item in raw_items.split(","):
                    match = LIST_ITEM_RE.fullmatch(raw_item)
                    values[klass].append(
                        match.group(1)
                        if match
                        else f"<invalid CEL list item: {raw_item.strip()}>"
                    )
            return dict(values)
    return {}


def check_overlay_tier(g: Guard, tunnel: str) -> None:
    """Require the overlay declaration to agree with the closed tier map."""
    relative = f"{APPS}/cloudflared-{tunnel}/kustomization.yaml"
    documents = g.load(relative)
    if not g.check(
        len(documents) == 1,
        f"{relative}: expected exactly one document, found {len(documents)}",
    ):
        return

    generators = documents[0].get("configMapGenerator")
    generators = generators if isinstance(generators, list) else []
    contracts = [
        generator
        for generator in generators
        if isinstance(generator, dict)
        and generator.get("name") == "tunnel-contract"
    ]
    if not g.check(
        len(contracts) == 1,
        f"{relative}: expected exactly one tunnel-contract generator, "
        f"found {len(contracts)}",
    ):
        return

    literals = contracts[0].get("literals")
    literals = literals if isinstance(literals, list) else []
    tiers = [
        literal.split("=", 1)[1]
        for literal in literals
        if isinstance(literal, str) and literal.startswith("tier=")
    ]
    if not g.check(
        len(tiers) == 1,
        f"{relative}: tunnel-contract must declare exactly one tier= literal, "
        f"found {tiers}",
    ):
        return

    klass = f"{CLASS_PREFIX}{tunnel}"
    expected = CLASS_TIERS.get(klass)
    if expected is None:
        return
    g.check(
        tiers[0] == expected,
        f"{relative}: overlay declares tier {tiers[0]!r}, but closed "
        f"CLASS_TIERS requires {expected!r} for class {klass!r}",
    )


def check_connector_tier(
    g: Guard,
    tunnel: str,
    tier: str,
    config: dict,
) -> None:
    """Enforce connector posture from CLASS_TIERS, never from the overlay."""
    where = f"{APPS}/cloudflared-{tunnel}/configmap.yaml"
    access = nested(config, ("originRequest", "access"))
    if tier == "mtls":
        if not g.check(
            isinstance(access, dict) and access.get("required") is True,
            f"{where}: an mTLS-tier connector must set "
            "originRequest.access.required: true tunnel-wide",
        ):
            return
        auds = access.get("audTag")
        g.check(
            isinstance(auds, list)
            and bool(auds)
            and all(ACCESS_AUD_RE.fullmatch(str(aud)) for aud in auds),
            f"{where}: originRequest.access.audTag must list at least one "
            f"64-hex Access application aud, found {auds!r}",
        )
        team_name = access.get("teamName")
        g.check(
            isinstance(team_name, str) and bool(team_name.strip()),
            f"{where}: originRequest.access.teamName must be set",
        )
    elif tier == "public":
        g.check(
            not access,
            f"{where}: a public-tier connector must not require Cloudflare "
            "Access; every hostname behind it would be locked out",
        )
    else:
        g.errors.append(
            f"{where}: closed CLASS_TIERS assigns unsupported tier {tier!r}"
        )


def check_connector(g: Guard, tunnel: str) -> dict | None:
    relative = f"{APPS}/cloudflared-{tunnel}"
    where = f"{relative} (rendered)"
    text, objects = g.render(relative)
    g.check(
        "placeholder" not in text.casefold(),
        f"{where}: an unresolved placeholder survived the render",
    )
    check_policy_inventory(
        g,
        where,
        objects,
        [
            (
                "CiliumNetworkPolicy",
                f"cloudflared-{tunnel}-egress",
                f"cloudflared-{tunnel}",
            ),
            (
                "NetworkPolicy",
                f"cloudflared-{tunnel}-default-deny",
                f"cloudflared-{tunnel}",
            ),
        ],
    )

    deployment = find_object(g, objects, "Deployment", f"cloudflared-{tunnel}", where)
    if deployment is not None:
        labels = nested(deployment, ("spec", "template", "metadata", "labels"))
        actual = labels.get(INSTANCE) if isinstance(labels, dict) else None
        g.check(
            actual == tunnel,
            f"{where}: connector pod instance label is {actual!r}, not {tunnel!r}; "
            "the overlay contract names a different tunnel than its directory",
        )

    cnp = find_object(
        g,
        objects,
        "CiliumNetworkPolicy",
        f"cloudflared-{tunnel}-egress",
        where,
    )
    if cnp is not None:
        spec = cnp.get("spec")
        spec = spec if isinstance(spec, dict) else {}
        selector = nested(spec, ("endpointSelector", "matchLabels"))
        actual = selector.get(INSTANCE) if isinstance(selector, dict) else None
        g.check(
            actual == tunnel,
            f"{where}: connector policy must select instance {tunnel!r}, found {actual!r}",
        )
        g.check(
            exact_rule_set(spec.get("egress"), connector_rules(tunnel)),
            f"{where}: connector egress rules must match the closed allow-list exactly",
        )

    configmap = find_object(g, objects, "ConfigMap", "cloudflared-config", where)
    if configmap is None:
        return None
    data = configmap.get("data")
    raw_config = data.get("config.yaml") if isinstance(data, dict) else None
    if not g.check(
        isinstance(raw_config, str),
        f"{where}: cloudflared-config data.config.yaml is missing",
    ):
        return None
    config = yaml.safe_load(raw_config)
    if not g.check(
        isinstance(config, dict),
        f"{where}: cloudflared-config data.config.yaml must be a mapping",
    ):
        return None
    return config


def check_routes(
    g: Guard,
    tunnel: str,
    config: dict,
    zone: str,
    protected: str,
    seen: dict[str, str],
) -> None:
    where = f"{APPS}/cloudflared-{tunnel}/configmap.yaml"
    uuid = str(config.get("tunnel", ""))
    if g.check(bool(UUID_RE.match(uuid)), f"{where}: tunnel id {uuid!r} is not a UUID"):
        g.check(
            uuid not in seen,
            f"{where}: tunnel id {uuid} is already used by {seen.get(uuid)!r}",
        )
        seen.setdefault(uuid, tunnel)

    rules = config.get("ingress") or []
    if not g.check(
        isinstance(rules, list) and bool(rules),
        f"{where}: ingress rules must be a non-empty list",
    ):
        return
    last = rules[-1]
    if not isinstance(last, dict):
        g.errors.append(f"{where}: the final ingress rule must be a mapping")
        return
    g.check(
        "hostname" not in last
        and str(last.get("service", "")).startswith("http_status:"),
        f"{where}: the final ingress rule must be a hostname-less http_status catch-all",
    )
    for rule in rules:
        if not isinstance(rule, dict):
            g.errors.append(f"{where}: every ingress route must be a mapping")
            continue
        hostname, service = rule.get("hostname"), str(rule.get("service", ""))
        if hostname is None or service.startswith("http_status:"):
            continue
        bare = hostname[2:] if str(hostname).startswith("*.") else str(hostname)
        g.check(
            bare == zone or bare.endswith(f".{zone}"),
            f"{where}: routed hostname {hostname!r} is outside the zone {zone!r} "
            "this connector serves",
        )
    if not protected:
        return

    def first(predicate) -> int:
        return next(
            (
                index
                for index, rule in enumerate(rules)
                if isinstance(rule, dict) and predicate(rule)
            ),
            -1,
        )

    wildcard = first(lambda rule: rule.get("hostname") == f"*.{zone}")
    for guarded in (f"*.{protected}", protected):
        index = first(
            lambda rule, host=guarded: rule.get("hostname") == host
            and str(rule.get("service", "")).startswith("http_status:")
        )
        if g.check(
            index >= 0,
            f"{where}: missing fail-closed http_status rule for {guarded!r}",
        ):
            g.check(
                wildcard < 0 or index < wildcard,
                f"{where}: the {guarded!r} rule must precede the '*.{zone}' "
                "wildcard; first match wins",
            )


def check_proxy(g: Guard, tunnel: str) -> None:
    relative = f"{APPS}/traefik-{tunnel}"
    where = f"{relative} (rendered)"
    text, objects = g.render(relative)
    g.check(
        "placeholder" not in text.casefold(),
        f"{where}: an unresolved placeholder survived the render",
    )
    check_policy_inventory(
        g,
        where,
        objects,
        [
            (
                "CiliumNetworkPolicy",
                f"traefik-{tunnel}-network",
                f"traefik-{tunnel}",
            ),
            (
                "NetworkPolicy",
                f"traefik-{tunnel}-default-deny",
                f"traefik-{tunnel}",
            ),
        ],
    )

    tenant = TUNNEL_TENANTS.get(tunnel)
    if tenant is None:
        g.errors.append(
            f"{where}: tunnel {tunnel!r} is absent from the closed TUNNEL_TENANTS map"
        )
        return

    klass = f"{CLASS_PREFIX}{tunnel}"
    ingress_class = find_object(g, objects, "IngressClass", klass, where)
    if ingress_class is not None:
        annotations = metadata(ingress_class).get("annotations")
        annotations = annotations if isinstance(annotations, dict) else {}
        g.check(
            "ingressclass.kubernetes.io/is-default-class" not in annotations,
            f"{where}: the default-class annotation must be absent from {klass}",
        )

    release = find_object(g, objects, "HelmRelease", f"traefik-{tunnel}", where)
    if release is not None:
        values = nested(release, ("spec", "values"))
        values = values if isinstance(values, dict) else {}
        provider = nested(values, ("providers", "kubernetesIngress"))
        provider = provider if isinstance(provider, dict) else {}
        g.check(
            provider.get("ingressClass") == klass,
            f"{where}: proxy must watch class {klass!r}, "
            f"found {provider.get('ingressClass')!r}",
        )
        watched = provider.get("namespaces")
        g.check(
            watched == [tenant],
            f"{where}: closed tenant map requires watched namespace {tenant!r}, "
            f"found {watched!r}",
        )
        pod_labels = nested(values, ("deployment", "podLabels"))
        actual_proxy = pod_labels.get(PROXY) if isinstance(pod_labels, dict) else None
        g.check(
            actual_proxy == tunnel,
            f"{where}: proxy pod label {PROXY} must be {tunnel!r}, "
            f"found {actual_proxy!r}",
        )
        for path in DISABLED_VALUES:
            g.check(
                nested(values, path) is False,
                f"{where}: values.{'.'.join(path)} must be false",
            )

    for kind in ("Role", "RoleBinding"):
        obj = find_object(g, objects, kind, f"traefik-{tunnel}", where)
        if obj is not None:
            actual_namespace = metadata(obj).get("namespace")
            g.check(
                actual_namespace == tenant,
                f"{where}: closed tenant map requires {kind} namespace {tenant!r}, "
                f"found {actual_namespace!r}",
            )

    cnp = find_object(
        g,
        objects,
        "CiliumNetworkPolicy",
        f"traefik-{tunnel}-network",
        where,
    )
    if cnp is None:
        return
    spec = cnp.get("spec")
    spec = spec if isinstance(spec, dict) else {}
    selector = nested(spec, ("endpointSelector", "matchLabels"))
    actual_proxy = selector.get(PROXY) if isinstance(selector, dict) else None
    g.check(
        actual_proxy == tunnel,
        f"{where}: proxy policy must select {PROXY}={tunnel!r}, "
        f"found {actual_proxy!r}",
    )
    g.check(
        exact_rule_set(spec.get("ingress"), [proxy_ingress_rule(tunnel)]),
        f"{where}: proxy ingress rules must match the closed allow-list exactly",
    )
    g.check(
        exact_rule_set(spec.get("egress"), proxy_egress_rules(tunnel, tenant)),
        f"{where}: proxy egress rules must match the closed allow-list exactly",
    )


def check_flux_child(g: Guard, tunnel: str) -> None:
    relative = f"{APPS}/kustomization-traefik-{tunnel}.yaml"
    documents = g.load(relative)
    if not g.check(
        len(documents) == 1,
        f"{relative}: expected exactly one document, found {len(documents)}",
    ):
        return
    document = documents[0]
    spec = document.get("spec")
    spec = spec if isinstance(spec, dict) else {}
    g.check(
        spec.get("path") == f"./{APPS}/traefik-{tunnel}",
        f"{relative}: spec.path must be ./{APPS}/traefik-{tunnel}",
    )


def check_tenant_namespaces(g: Guard) -> dict[str, str]:
    tenant_orgs: dict[str, str] = {}
    for tenant in sorted(set(TUNNEL_TENANTS.values())):
        relative = f"{TENANTS}/{tenant}"
        directory = g.root / relative
        if not g.check(
            directory.is_dir(),
            f"{relative}: required tenant directory is missing",
        ):
            continue
        _text, objects = g.render(relative)
        namespaces = [
            document
            for document in objects
            if document.get("kind") == "Namespace"
            and metadata(document).get("name") == tenant
        ]
        if not g.check(
            len(namespaces) == 1,
            f"{relative}: expected exactly one rendered Namespace/{tenant}, "
            f"found {len(namespaces)}",
        ):
            continue
        labels = metadata(namespaces[0]).get("labels")
        labels = labels if isinstance(labels, dict) else {}
        g.check(
            labels.get("nwarila.io/tenant") == "true",
            f"{relative}: Namespace/{tenant} must carry "
            'nwarila.io/tenant: "true"',
        )
        org = labels.get("nwarila.io/org")
        if g.check(
            isinstance(org, str) and bool(org),
            f"{relative}: Namespace/{tenant} must carry a non-empty "
            "nwarila.io/org label",
        ):
            tenant_orgs[tenant] = org
    return tenant_orgs


def check_template(g: Guard, tunnels: list[str]) -> None:
    documents = g.load(TEMPLATE_CNP)
    expected = [
        ("CiliumNetworkPolicy", f"allow-tunnel-proxy-{tunnel}", None)
        for tunnel in tunnels
    ]
    check_policy_inventory(
        g,
        TEMPLATE_CNP,
        documents,
        expected,
        all_documents=True,
        noun="template document",
    )
    for tunnel in tunnels:
        name = f"allow-tunnel-proxy-{tunnel}"
        document = find_object(
            g,
            documents,
            "CiliumNetworkPolicy",
            name,
            TEMPLATE_CNP,
        )
        if document is None:
            continue
        spec = document.get("spec")
        spec = spec if isinstance(spec, dict) else {}
        g.check(
            spec.get("endpointSelector")
            == {"matchLabels": {EXPOSED: tunnel}},
            f"{TEMPLATE_CNP}: endpoint selector for tunnel {tunnel!r} must be "
            f"exactly {EXPOSED}={tunnel!r}",
        )
        g.check(
            exact_rule_set(spec.get("ingress"), [template_ingress_rule(tunnel)]),
            f"{TEMPLATE_CNP}: template ingress rule for tunnel {tunnel!r} "
            "must match the closed allow-list exactly with 8080/TCP",
        )


def check_policies(
    g: Guard,
    tunnels: list[str],
    tenant_orgs: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    binding_documents = g.load(BINDING_POLICY)
    if not g.check(
        len(binding_documents) == 1,
        f"{BINDING_POLICY}: expected exactly one document, "
        f"found {len(binding_documents)}",
    ):
        return {}, {}
    binding = binding_documents[0]
    binding_spec = binding.get("spec")
    variables = (
        binding_spec.get("variables", [])
        if isinstance(binding_spec, dict)
        else []
    )
    owners: defaultdict[str, list[str]] = defaultdict(list)
    for entry in variables:
        if not isinstance(entry, dict) or entry.get("name") != "permittedClasses":
            continue
        for org, classes in ORG_CLASSES_RE.findall(
            str(entry.get("expression", ""))
        ):
            for klass in QUOTED_RE.findall(classes):
                owners[klass].append(org)

    for klass, class_owners in sorted(owners.items()):
        g.check(
            len(class_owners) == 1,
            f"{BINDING_POLICY}: class {klass!r} must be registered under "
            f"exactly one organization, found {class_owners!r}",
        )

    expected = {f"{CLASS_PREFIX}{tunnel}" for tunnel in tunnels}
    registered = set(owners)
    for missing in sorted(expected - registered):
        g.errors.append(
            f"{BINDING_POLICY}: class {missing!r} has a connector and proxy "
            "but no organization may use it"
        )
    for extra in sorted(registered - expected):
        g.errors.append(
            f"{BINDING_POLICY}: class {extra!r} is registered but has no "
            "connector/proxy pair behind it"
        )
    for tunnel in tunnels:
        klass = f"{CLASS_PREFIX}{tunnel}"
        class_owners = owners.get(klass, [])
        tenant = TUNNEL_TENANTS.get(tunnel)
        tenant_org = tenant_orgs.get(tenant, "") if tenant else ""
        if len(class_owners) == 1 and tenant_org:
            g.check(
                class_owners[0] == tenant_org,
                f"{BINDING_POLICY}: class {klass!r} belongs to organization "
                f"{class_owners[0]!r}, but closed tenant map points to "
                f"{tenant!r} owned by {tenant_org!r}",
            )

    hostname_documents = g.load(HOSTNAME_POLICY)
    if not g.check(
        len(hostname_documents) == 1,
        f"{HOSTNAME_POLICY}: expected exactly one document, "
        f"found {len(hostname_documents)}",
    ):
        return {}, {}
    hostnames = hostname_documents[0]
    zones = parse_ternary_map(hostnames, "zone")
    protected = parse_ternary_map(hostnames, "protectedZone")
    reserved_hosts = parse_list_ternary_map(hostnames, "reservedHosts")
    for klass in sorted(expected):
        zone = zones.get(klass, "")
        g.check(
            bool(zone),
            f"{HOSTNAME_POLICY}: class {klass!r} has no zone; "
            "its hostnames would be unconstrained",
        )
        if not zone:
            continue
        same_zone_classes = {
            sibling
            for sibling in expected
            if zones.get(sibling, "") == zone
        }
        required_hosts = [
            f"canary-{sibling.removeprefix(CLASS_PREFIX)}.{zone}"
            for sibling in sorted(same_zone_classes)
        ]
        actual_hosts = reserved_hosts.get(klass, [])
        g.check(
            Counter(actual_hosts) == Counter(required_hosts),
            f"{HOSTNAME_POLICY}: class {klass!r} reservedHosts must match "
            "the closed same-zone canary set exactly; "
            f"expected {required_hosts!r}, found {actual_hosts!r}",
        )
    for klass in sorted(set(reserved_hosts) - expected):
        g.errors.append(
            f"{HOSTNAME_POLICY}: reservedHosts registers unknown class "
            f"{klass!r}"
        )
    for outer, outer_zone in sorted(zones.items()):
        for inner, inner_zone in sorted(zones.items()):
            if (
                outer != inner
                and outer_zone
                and inner_zone.endswith(f".{outer_zone}")
            ):
                g.check(
                    protected.get(outer) == inner_zone,
                    f"{HOSTNAME_POLICY}: zone {inner_zone!r} ({inner}) nests "
                    f"inside {outer_zone!r} ({outer}), so {outer} must declare "
                    f"protectedZone {inner_zone!r}; "
                    f"found {protected.get(outer)!r}",
                )
    for klass, value in sorted(protected.items()):
        g.check(
            not value or value in zones.values(),
            f"{HOSTNAME_POLICY}: {klass} protectedZone {value!r} is not any "
            "class's zone",
        )
    return zones, protected


def check_no_retired_boolean(g: Guard) -> None:
    for tree in (APPS, TENANTS):
        directory = g.root / tree
        if not directory.is_dir():
            g.errors.append(f"{tree}: required inventory directory is missing")
            continue
        for path in sorted(directory.rglob("*.yaml")):
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(),
                start=1,
            ):
                if RETIRED_BOOLEAN_RE.search(line):
                    relative = path.relative_to(g.root)
                    g.errors.append(
                        f"{relative}:{line_number}: retired boolean opt-in "
                        f"for {EXPOSED} is forbidden"
                    )


def discover_tunnels(g: Guard) -> list[str]:
    apps = g.root / APPS
    if not apps.is_dir():
        g.errors.append(f"{APPS}: app inventory directory is missing")
        return []

    connectors = {
        path.name.removeprefix("cloudflared-")
        for path in apps.iterdir()
        if path.is_dir() and path.name.startswith("cloudflared-")
    }
    proxies = {
        path.name.removeprefix("traefik-")
        for path in apps.iterdir()
        if path.is_dir() and path.name.startswith("traefik-")
    }
    children = {
        match.group(1)
        for path in apps.glob("kustomization-traefik-*.yaml")
        if (match := CHILD_RE.fullmatch(path.name))
    }

    index_documents = g.load(APPS_INDEX)
    resources: list = []
    if g.check(
        len(index_documents) == 1,
        f"{APPS_INDEX}: expected exactly one document, found "
        f"{len(index_documents)}",
    ):
        raw_resources = index_documents[0].get("resources")
        if isinstance(raw_resources, list):
            resources = raw_resources
        else:
            g.errors.append(f"{APPS_INDEX}: resources must be a list")
    connector_index_counts: Counter[str] = Counter()
    child_index_counts: Counter[str] = Counter()
    for resource in resources:
        normalized = str(resource).removeprefix("./")
        child_match = CHILD_RE.fullmatch(normalized)
        connector_match = CONNECTOR_INDEX_RE.fullmatch(normalized)
        if child_match:
            child_index_counts[child_match.group(1)] += 1
        elif connector_match:
            connector_index_counts[connector_match.group(1)] += 1

    discovered = (
        connectors
        | proxies
        | children
        | set(connector_index_counts)
        | set(child_index_counts)
    )
    if not discovered:
        g.errors.append(
            "check-tunnel-isolation: no cloudflared/traefik tunnel inventory found"
        )
        return []

    complete: list[str] = []
    for tunnel in sorted(discovered):
        missing: list[str] = []
        if tunnel not in connectors:
            missing.append("cloudflared overlay")
        if tunnel not in proxies:
            missing.append("traefik overlay")
        if tunnel not in children:
            missing.append("Flux child file")
        connector_index_count = connector_index_counts[tunnel]
        if connector_index_count == 0:
            missing.append("apps connector entry")
        elif connector_index_count > 1:
            missing.append(
                "exactly one apps connector entry "
                f"(found {connector_index_count})"
            )
        child_index_count = child_index_counts[tunnel]
        if child_index_count == 0:
            missing.append("apps Flux-child entry")
        elif child_index_count > 1:
            missing.append(
                "exactly one apps Flux-child entry "
                f"(found {child_index_count})"
            )
        if missing:
            g.errors.append(
                f"{APPS}: tunnel {tunnel!r} violates exact 1:1 pairing; "
                f"missing {', '.join(missing)}"
            )
        else:
            complete.append(tunnel)

    for tunnel in sorted(discovered - set(TUNNEL_TENANTS)):
        g.errors.append(
            f"{APPS}: tunnel {tunnel!r} is absent from the closed "
            "TUNNEL_TENANTS map"
        )
    for tunnel in sorted(set(TUNNEL_TENANTS) - discovered):
        g.errors.append(
            f"{APPS}: closed TUNNEL_TENANTS entry {tunnel!r} has no tunnel "
            "inventory"
        )
    discovered_classes = {
        f"{CLASS_PREFIX}{tunnel}" for tunnel in discovered
    }
    for klass in sorted(discovered_classes - set(CLASS_TIERS)):
        g.errors.append(
            f"{APPS}: class {klass!r} is absent from the closed "
            "CLASS_TIERS map"
        )
    for klass in sorted(set(CLASS_TIERS) - discovered_classes):
        g.errors.append(
            f"{APPS}: closed CLASS_TIERS entry {klass!r} has no tunnel "
            "inventory"
        )
    return complete


def main(argv: list[str]) -> int:
    root = (
        Path(argv[1]).resolve()
        if len(argv) > 1
        else Path(__file__).resolve().parents[1]
    )
    kubectl = which("kubectl")
    if not kubectl:
        print(
            "check-tunnel-isolation: kubectl is required to render the overlays",
            file=sys.stderr,
        )
        return 1
    g = Guard(root, kubectl)
    try:
        check_no_retired_boolean(g)
        tunnels = discover_tunnels(g)
        tenant_orgs = check_tenant_namespaces(g)
        configs: dict[str, dict | None] = {}
        for tunnel in tunnels:
            configs[tunnel] = check_connector(g, tunnel)
            check_overlay_tier(g, tunnel)
            tier = CLASS_TIERS.get(f"{CLASS_PREFIX}{tunnel}")
            if configs[tunnel] is not None and tier is not None:
                check_connector_tier(g, tunnel, tier, configs[tunnel])
            check_proxy(g, tunnel)
            check_flux_child(g, tunnel)
        zones, protected = check_policies(g, tunnels, tenant_orgs)
        seen: dict[str, str] = {}
        for tunnel, config in configs.items():
            if config is not None:
                klass = f"{CLASS_PREFIX}{tunnel}"
                check_routes(
                    g,
                    tunnel,
                    config,
                    zones.get(klass, ""),
                    protected.get(klass, ""),
                    seen,
                )
        check_template(g, tunnels)
    except (
        RenderError,
        FileNotFoundError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        yaml.YAMLError,
    ) as error:
        print(
            f"check-tunnel-isolation: unreadable tunnel inventory: {error}",
            file=sys.stderr,
        )
        return 1
    if g.errors:
        print("check-tunnel-isolation: FAILED", file=sys.stderr)
        for error in g.errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(
        f"check-tunnel-isolation: OK ({len(tunnels)} tunnels: "
        f"{', '.join(tunnels)}; exact pairing, closed policy inventory/rule "
        "shapes, tenant ownership, canonical tier posture, routes, and policy "
        "registrations verified)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
