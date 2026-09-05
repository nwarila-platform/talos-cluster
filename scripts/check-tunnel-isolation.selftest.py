#!/usr/bin/env python3
"""Regression self-test for the per-tunnel isolation guards.

Each case copies the real bounded tunnel inventory into a temporary root,
applies one adversarial mutation, and asserts both the return code and a
finding-specific output substring. The output assertion prevents an unrelated
render or parser failure from masquerading as the intended guard rejection.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check-tunnel-isolation.py"
PLACEHOLDER_GUARD = "scripts/check-no-placeholder-leak.sh"
APPS = "clusters/talos-cluster/apps"
TENANTS = "clusters/talos-cluster/tenants"
CONNECTOR = f"{APPS}/_components/tunnel-connector"
PROXY = f"{APPS}/_components/tunnel-proxy"
TEMPLATE_CNP = (
    f"{TENANTS}/_template/zero-touch/base/"
    "ciliumnetworkpolicy-allow-tunnel-proxy.yaml"
)
COPY_FILES = (
    f"{APPS}/kustomization.yaml",
    f"{APPS}/kyverno/policies/restrict-tunnel-binding.yaml",
    f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml",
    PLACEHOLDER_GUARD,
)
TENANT_DIRS = ("_template", "hwg-1268831311", "nwp-1306985678")


@dataclass(frozen=True)
class Case:
    name: str
    expected_rc: int
    required_output: str
    mutate: Callable[[Path], None]
    checker: str = "tunnel"


def stage(destination: Path) -> None:
    for entry in (ROOT / APPS).iterdir():
        if entry.is_dir() and entry.name.startswith(
            ("cloudflared-", "traefik-", "_components")
        ):
            shutil.copytree(entry, destination / APPS / entry.name)
        elif entry.is_file() and entry.name.startswith(
            "kustomization-traefik-"
        ):
            target = destination / APPS / entry.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(entry, target)
    for tenant in TENANT_DIRS:
        shutil.copytree(
            ROOT / TENANTS / tenant,
            destination / TENANTS / tenant,
        )
    for relative in COPY_FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)

    # The shell-check case needs a local, network-free aggregate. Flux child
    # paths are still the real staged proxy paths and are enumerated separately.
    cluster_index = destination / "clusters/talos-cluster/kustomization.yaml"
    cluster_index.write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources: []\n",
        encoding="utf-8",
    )


def edit(root: Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(
            f"self-test setup: {old!r} not found in {relative}"
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def load_document(root: Path, relative: str) -> dict:
    document = yaml.safe_load((root / relative).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise AssertionError(
            f"self-test setup: {relative} is not one YAML mapping"
        )
    return document


def write_document(root: Path, relative: str, document: dict) -> None:
    (root / relative).write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )


def load_documents(root: Path, relative: str) -> list[dict]:
    documents = [
        document
        for document in yaml.safe_load_all(
            (root / relative).read_text(encoding="utf-8")
        )
        if document is not None
    ]
    if not all(isinstance(document, dict) for document in documents):
        raise AssertionError(
            f"self-test setup: {relative} contains a non-mapping document"
        )
    return documents


def write_documents(root: Path, relative: str, documents: list[dict]) -> None:
    (root / relative).write_text(
        yaml.safe_dump_all(documents, sort_keys=False),
        encoding="utf-8",
    )


def add_overlay_patch(
    root: Path,
    relative: str,
    target_kind: str,
    operations: list[dict],
) -> None:
    document = load_document(root, relative)
    patches = document.setdefault("patches", [])
    if not isinstance(patches, list):
        raise AssertionError(
            f"self-test setup: patches is not a list in {relative}"
        )
    patches.append(
        {
            "target": {"kind": target_kind},
            "patch": yaml.safe_dump(operations, sort_keys=False),
        }
    )
    write_document(root, relative, document)


def noop(_root: Path) -> None:
    return None


def proxy_boolean_opt_in(root: Path) -> None:
    edit(
        root,
        f"{PROXY}/ciliumnetworkpolicy.yaml",
        '"k8s:nwarila.io/tunnel-exposed": "tunnelplaceholder"',
        '"k8s:nwarila.io/tunnel-exposed": "true"',
    )
    edit(
        root,
        f"{PROXY}/kustomization.yaml",
        "          - spec.egress.1.toEndpoints.0.matchLabels."
        "[k8s:nwarila.io/tunnel-exposed]\n",
        "",
    )


def proxy_contract_names_sibling(root: Path) -> None:
    edit(
        root,
        f"{APPS}/traefik-nwp-public/kustomization.yaml",
        "tunnel=nwp-public",
        "tunnel=nwp-mtls",
    )


def connector_contract_names_sibling(root: Path) -> None:
    edit(
        root,
        f"{APPS}/cloudflared-nwp-public/kustomization.yaml",
        "tunnel=nwp-public",
        "tunnel=nwp-mtls",
    )


def proxy_watches_sibling_class(root: Path) -> None:
    edit(
        root,
        f"{PROXY}/helmrelease.yaml",
        "ingressClass: cf-tunnel-tunnelplaceholder",
        "ingressClass: cf-tunnel-nwp-mtls",
    )
    edit(
        root,
        f"{PROXY}/kustomization.yaml",
        "      - select:\n"
        "          kind: HelmRelease\n"
        "        fieldPaths:\n"
        "          - spec.values.providers.kubernetesIngress.ingressClass\n"
        "        options:\n"
        "          delimiter: '-'\n"
        "          index: 2\n",
        "",
    )


def placeholder_leaks(root: Path) -> None:
    edit(
        root,
        f"{CONNECTOR}/kustomization.yaml",
        "          - metadata.labels.[nwarila.io/platform-addon]\n",
        "",
    )


def default_ingress_class(root: Path) -> None:
    edit(
        root,
        f"{PROXY}/ingressclass.yaml",
        "metadata:\n  name: cf-tunnel-tunnelplaceholder\n",
        "metadata:\n"
        "  name: cf-tunnel-tunnelplaceholder\n"
        "  annotations:\n"
        '    ingressclass.kubernetes.io/is-default-class: "true"\n',
    )


def flux_child_wrong_path(root: Path) -> None:
    edit(
        root,
        f"{APPS}/kustomization-traefik-nwp-mtls.yaml",
        f"path: ./{APPS}/traefik-nwp-mtls",
        f"path: ./{APPS}/traefik-nwp-public",
    )


def template_allow_removed(root: Path) -> None:
    documents = [
        document
        for document in load_documents(root, TEMPLATE_CNP)
        if document.get("metadata", {}).get("name")
        != "allow-tunnel-proxy-nwp-mtls"
    ]
    write_documents(root, TEMPLATE_CNP, documents)


def template_boolean(root: Path) -> None:
    edit(
        root,
        TEMPLATE_CNP,
        "nwarila.io/tunnel-exposed: nwp-mtls",
        'nwarila.io/tunnel-exposed: "true"',
    )


def template_unknown_tunnel(root: Path) -> None:
    edit(
        root,
        TEMPLATE_CNP,
        "nwarila.io/tunnel-exposed: nwp-mtls",
        "nwarila.io/tunnel-exposed: nwp-ghost",
    )


GUARD_RULE = (
    "      - hostname: '*.secure.nicholaswarila.com'\n"
    "        service: http_status:404\n"
)
WILDCARD_RULE = (
    "      - hostname: '*.nicholaswarila.com'\n"
    "        service: http://traefik-nwp-public.traefik-nwp-public.svc:80\n"
)


def fail_closed_rule_removed(root: Path) -> None:
    edit(
        root,
        f"{APPS}/cloudflared-nwp-public/configmap.yaml",
        GUARD_RULE,
        "",
    )


def fail_closed_rule_reordered(root: Path) -> None:
    path = root / f"{APPS}/cloudflared-nwp-public/configmap.yaml"
    text = path.read_text(encoding="utf-8")
    if GUARD_RULE not in text or WILDCARD_RULE not in text:
        raise AssertionError("self-test setup: route block changed")
    path.write_text(
        text.replace(GUARD_RULE, "", 1).replace(
            WILDCARD_RULE,
            WILDCARD_RULE + GUARD_RULE,
            1,
        ),
        encoding="utf-8",
    )


def out_of_zone_route(root: Path) -> None:
    edit(
        root,
        f"{APPS}/cloudflared-nwp-mtls/configmap.yaml",
        "      - hostname: '*.secure.nicholaswarila.com'\n"
        "        service: http://traefik-nwp-mtls",
        "      - hostname: '*.elsewhere.example.com'\n"
        "        service: http://traefik-nwp-mtls",
    )


def duplicate_tunnel_uuid(root: Path) -> None:
    def uuid_of(relative: str) -> str:
        text = (root / relative).read_text(encoding="utf-8")
        return next(
            line.split("tunnel: ")[1].strip()
            for line in text.splitlines()
            if "tunnel: " in line
        )

    public = uuid_of(f"{APPS}/cloudflared-nwp-public/configmap.yaml")
    mtls = f"{APPS}/cloudflared-nwp-mtls/configmap.yaml"
    edit(root, mtls, uuid_of(mtls), public)


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
        "variables.class == 'cf-tunnel-nwp-public' ? "
        "'secure.nicholaswarila.com' : ''",
        "variables.class == 'cf-tunnel-nwp-public' ? '' : ''",
    )


def zone_dropped(root: Path) -> None:
    edit(
        root,
        f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml",
        "variables.class == 'cf-tunnel-nwp-mtls' ? "
        "'secure.nicholaswarila.com' : ''",
        "variables.class == 'cf-tunnel-nwp-mtls-absent' ? "
        "'secure.nicholaswarila.com' : ''",
    )


def additive_ccnp_pair(root: Path) -> None:
    documents = [
        {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumClusterwideNetworkPolicy",
            "metadata": {"name": "reviewer-tunnelplaceholder-proxy-egress"},
            "spec": {
                "endpointSelector": {
                    "matchLabels": {
                        "nwarila.io/tunnel-proxy": "nwp-public",
                    }
                },
                "egress": [
                    {
                        "toEndpoints": [
                            {
                                "matchLabels": {
                                    "k8s:io.kubernetes.pod.namespace": (
                                        "nwp-1306985678"
                                    ),
                                    "k8s:nwarila.io/tunnel-exposed": (
                                        "nwp-mtls"
                                    ),
                                }
                            }
                        ],
                        "toPorts": [
                            {
                                "ports": [
                                    {"port": "8080", "protocol": "TCP"},
                                ]
                            }
                        ],
                    }
                ],
            },
        },
        {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumClusterwideNetworkPolicy",
            "metadata": {"name": "reviewer-tunnelplaceholder-origin-ingress"},
            "spec": {
                "endpointSelector": {
                    "matchLabels": {
                        "nwarila.io/tunnel-exposed": "nwp-mtls",
                    }
                },
                "ingress": [
                    {
                        "fromEndpoints": [
                            {
                                "matchLabels": {
                                    "k8s:io.kubernetes.pod.namespace": (
                                        "traefik-nwp-public"
                                    ),
                                    "k8s:nwarila.io/tunnel-proxy": (
                                        "nwp-public"
                                    ),
                                }
                            }
                        ],
                        "toPorts": [
                            {
                                "ports": [
                                    {"port": "8080", "protocol": "TCP"},
                                ]
                            }
                        ],
                    }
                ],
            },
        },
    ]
    resource = root / PROXY / "reviewer-cross-tunnel-ccnp.yaml"
    resource.write_text(
        yaml.safe_dump_all(documents, sort_keys=False),
        encoding="utf-8",
    )
    kustomization = load_document(root, f"{PROXY}/kustomization.yaml")
    kustomization["resources"].append(resource.name)
    tunnel_replacement = next(
        replacement
        for replacement in kustomization["replacements"]
        if replacement["source"].get("fieldPath") == "data.tunnel"
    )
    tunnel_replacement["targets"].append(
        {
            "select": {"kind": "CiliumClusterwideNetworkPolicy"},
            "fieldPaths": ["metadata.name"],
            "options": {"delimiter": "-", "index": 1},
        }
    )
    write_document(root, f"{PROXY}/kustomization.yaml", kustomization)


def unexpected_overlay_cnp(root: Path) -> None:
    add_overlay_patch(
        root,
        f"{APPS}/cloudflared-nwp-public/kustomization.yaml",
        "PodDisruptionBudget",
        [
            {
                "op": "replace",
                "path": "/apiVersion",
                "value": "cilium.io/v2",
            },
            {
                "op": "replace",
                "path": "/kind",
                "value": "CiliumNetworkPolicy",
            },
            {
                "op": "replace",
                "path": "/metadata/name",
                "value": "reviewer-extra-cnp",
            },
            {
                "op": "replace",
                "path": "/spec",
                "value": {
                    "endpointSelector": {
                        "matchLabels": {"reviewer": "extra"}
                    },
                    "egress": [],
                },
            },
        ],
    )


def namespace_only_overlay_rule(root: Path) -> None:
    add_overlay_patch(
        root,
        f"{APPS}/traefik-nwp-public/kustomization.yaml",
        "CiliumNetworkPolicy",
        [
            {
                "op": "add",
                "path": "/spec/egress/-",
                "value": {
                    "toEndpoints": [
                        {
                            "matchLabels": {
                                "k8s:io.kubernetes.pod.namespace": (
                                    "nwp-1306985678"
                                )
                            }
                        }
                    ],
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "8080", "protocol": "TCP"},
                            ]
                        }
                    ],
                },
            }
        ],
    )


def namespace_only_component_rule(root: Path) -> None:
    relative = f"{PROXY}/ciliumnetworkpolicy.yaml"
    document = load_document(root, relative)
    document["spec"]["egress"].append(
        {
            "toEndpoints": [
                {
                    "matchLabels": {
                        "k8s:io.kubernetes.pod.namespace": (
                            "tenantnsplaceholder"
                        )
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        {"port": "8080", "protocol": "TCP"},
                    ]
                }
            ],
        }
    )
    write_document(root, relative, document)

    kustomization = load_document(root, f"{PROXY}/kustomization.yaml")
    tenant_replacement = next(
        replacement
        for replacement in kustomization["replacements"]
        if replacement["source"].get("fieldPath") == "data.tenantNamespace"
    )
    cnp_target = next(
        target
        for target in tenant_replacement["targets"]
        if target["select"].get("kind") == "CiliumNetworkPolicy"
    )
    cnp_target["fieldPaths"].append(
        "spec.egress.2.toEndpoints.0.matchLabels."
        "[k8s:io.kubernetes.pod.namespace]"
    )
    write_document(root, f"{PROXY}/kustomization.yaml", kustomization)


def template_unkeyed_document(root: Path) -> None:
    documents = load_documents(root, TEMPLATE_CNP)
    documents.append(
        {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "allow-tunnel-proxy-any"},
            "spec": {
                "endpointSelector": {
                    "matchLabels": {"nwarila.io/org": "nwp"}
                },
                "ingress": [
                    {
                        "fromEndpoints": [
                            {
                                "matchLabels": {
                                    "k8s:io.kubernetes.pod.namespace": (
                                        "traefik-nwp-public"
                                    ),
                                    "k8s:nwarila.io/tunnel-proxy": (
                                        "nwp-public"
                                    ),
                                }
                            }
                        ],
                        "toPorts": [
                            {
                                "ports": [
                                    {"port": "8080", "protocol": "TCP"},
                                ]
                            }
                        ],
                    }
                ],
            },
        }
    )
    write_documents(root, TEMPLATE_CNP, documents)


def cross_tunnel_additive_rules(root: Path) -> None:
    add_overlay_patch(
        root,
        f"{APPS}/cloudflared-nwp-public/kustomization.yaml",
        "CiliumNetworkPolicy",
        [
            {
                "op": "add",
                "path": "/spec/egress/-",
                "value": {
                    "toEndpoints": [
                        {
                            "matchLabels": {
                                "k8s:nwarila.io/tunnel-proxy": "nwp-mtls"
                            }
                        }
                    ],
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "8000", "protocol": "TCP"},
                            ]
                        }
                    ],
                },
            }
        ],
    )
    add_overlay_patch(
        root,
        f"{APPS}/traefik-nwp-mtls/kustomization.yaml",
        "CiliumNetworkPolicy",
        [
            {
                "op": "add",
                "path": "/spec/ingress/-",
                "value": {
                    "fromEndpoints": [
                        {
                            "matchLabels": {
                                "k8s:app.kubernetes.io/instance": (
                                    "nwp-public"
                                )
                            }
                        }
                    ],
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "8000", "protocol": "TCP"},
                            ]
                        }
                    ],
                },
            }
        ],
    )

    relative = f"{APPS}/cloudflared-nwp-public/configmap.yaml"
    configmap = load_document(root, relative)
    config = yaml.safe_load(configmap["data"]["config.yaml"])
    config["ingress"].insert(
        -1,
        {
            "hostname": "leak.nicholaswarila.com",
            "service": (
                "http://traefik-nwp-mtls.traefik-nwp-mtls.svc:80"
            ),
            "originRequest": {
                "httpHostHeader": "app.secure.nicholaswarila.com"
            },
        },
    )
    configmap["data"]["config.yaml"] = yaml.safe_dump(
        config,
        sort_keys=False,
    )
    write_document(root, relative, configmap)


def tenant_namespace_other_org(root: Path) -> None:
    edit(
        root,
        f"{APPS}/traefik-nwp-public/kustomization.yaml",
        "tenantNamespace=nwp-1306985678",
        "tenantNamespace=hwg-1268831311",
    )


def tenant_namespace_kube_system(root: Path) -> None:
    edit(
        root,
        f"{APPS}/traefik-nwp-public/kustomization.yaml",
        "tenantNamespace=nwp-1306985678",
        "tenantNamespace=kube-system",
    )


def sibling_opt_in(root: Path) -> None:
    add_overlay_patch(
        root,
        f"{APPS}/traefik-nwp-public/kustomization.yaml",
        "CiliumNetworkPolicy",
        [
            {
                "op": "replace",
                "path": (
                    "/spec/egress/1/toEndpoints/0/matchLabels/"
                    "k8s:nwarila.io~1tunnel-exposed"
                ),
                "value": "nwp-mtls",
            }
        ],
    )


def crossed_connector(root: Path) -> None:
    add_overlay_patch(
        root,
        f"{APPS}/cloudflared-nwp-public/kustomization.yaml",
        "CiliumNetworkPolicy",
        [
            {
                "op": "replace",
                "path": (
                    "/spec/egress/2/toEndpoints/0/matchLabels/"
                    "k8s:io.kubernetes.pod.namespace"
                ),
                "value": "traefik-nwp-mtls",
            }
        ],
    )


def mixed_case_placeholder(root: Path) -> None:
    edit(
        root,
        f"{APPS}/traefik-nwp-public/kustomization.yaml",
        "tenantNamespace=nwp-1306985678",
        "tenantNamespace=tenantnsPlaceholder",
    )


def stray_retired_boolean(root: Path) -> None:
    (root / APPS / "reviewer-stray-policy.yaml").write_text(
        "apiVersion: cilium.io/v2\n"
        "kind: CiliumNetworkPolicy\n"
        "metadata:\n"
        "  name: reviewer-stray\n"
        "spec:\n"
        "  endpointSelector:\n"
        "    matchLabels:\n"
        '      nwarila.io/tunnel-exposed: "true"\n',
        encoding="utf-8",
    )


def orphan_proxy_overlay(root: Path) -> None:
    source = root / APPS / "traefik-nwp-public"
    orphan = root / APPS / "traefik-nwp-orphan"
    shutil.copytree(source, orphan)
    for path in orphan.rglob("*"):
        if path.is_file():
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "nwp-public",
                    "nwp-orphan",
                ),
                encoding="utf-8",
            )

    source_child = root / APPS / "kustomization-traefik-nwp-public.yaml"
    orphan_child = root / APPS / "kustomization-traefik-nwp-orphan.yaml"
    orphan_child.write_text(
        source_child.read_text(encoding="utf-8").replace(
            "nwp-public",
            "nwp-orphan",
        ),
        encoding="utf-8",
    )
    edit(
        root,
        f"{APPS}/kustomization.yaml",
        "  - kustomization-traefik-nwp-public.yaml\n",
        "  - kustomization-traefik-nwp-public.yaml\n"
        "  - kustomization-traefik-nwp-orphan.yaml\n",
    )


def missing_connector_index_entry(root: Path) -> None:
    edit(
        root,
        f"{APPS}/kustomization.yaml",
        "  - cloudflared-nwp-public\n",
        "",
    )


def class_registered_to_two_orgs(root: Path) -> None:
    edit(
        root,
        f"{APPS}/kyverno/policies/restrict-tunnel-binding.yaml",
        "['cf-tunnel-nwp-public', 'cf-tunnel-nwp-mtls']",
        "['cf-tunnel-nwp-public', 'cf-tunnel-nwp-mtls', 'cf-tunnel-hwg']",
    )


def template_without_to_ports(root: Path) -> None:
    documents = load_documents(root, TEMPLATE_CNP)
    document = next(
        item
        for item in documents
        if item["metadata"]["name"] == "allow-tunnel-proxy-nwp-public"
    )
    document["spec"]["ingress"][0].pop("toPorts")
    write_documents(root, TEMPLATE_CNP, documents)


CASES = (
    Case(
        "unmutated inventory passes",
        0,
        "check-tunnel-isolation: OK (3 tunnels:",
        noop,
    ),
    Case(
        "boolean opt-in in the proxy component is rejected",
        1,
        "proxy egress rules must match the closed allow-list exactly",
        proxy_boolean_opt_in,
    ),
    Case(
        "proxy overlay contract naming the sibling tunnel is rejected",
        1,
        "expected exactly one IngressClass/cf-tunnel-nwp-public, found 0",
        proxy_contract_names_sibling,
    ),
    Case(
        "connector overlay contract naming the sibling tunnel is rejected",
        1,
        "expected exactly one Deployment/cloudflared-nwp-public, found 0",
        connector_contract_names_sibling,
    ),
    Case(
        "proxy component hardwired to the sibling class is rejected",
        1,
        "proxy must watch class",
        proxy_watches_sibling_class,
    ),
    Case(
        "a placeholder surviving the connector render is rejected",
        1,
        "unresolved placeholder survived the render",
        placeholder_leaks,
    ),
    Case(
        "default-class annotation on the tunnel class is rejected",
        1,
        "default-class annotation",
        default_ingress_class,
    ),
    Case(
        "Flux child Kustomization pointing at the wrong overlay is rejected",
        1,
        "spec.path must be",
        flux_child_wrong_path,
    ),
    Case(
        "missing inherited tenant allow is rejected",
        1,
        "missing template document CiliumNetworkPolicy/"
        "allow-tunnel-proxy-nwp-mtls",
        template_allow_removed,
    ),
    Case(
        "boolean opt-in in the tenant template is rejected",
        1,
        "endpoint selector for tunnel 'nwp-mtls' must be exactly",
        template_boolean,
    ),
    Case(
        "tenant allow for an unknown tunnel is rejected",
        1,
        "endpoint selector for tunnel 'nwp-mtls' must be exactly",
        template_unknown_tunnel,
    ),
    Case(
        "removed protected-zone fail-closed route is rejected",
        1,
        "missing fail-closed http_status rule",
        fail_closed_rule_removed,
    ),
    Case(
        "protected-zone route ordered after the wildcard is rejected",
        1,
        "must precede",
        fail_closed_rule_reordered,
    ),
    Case(
        "connector routing outside its zone is rejected",
        1,
        "outside the zone",
        out_of_zone_route,
    ),
    Case(
        "two connectors sharing one tunnel id is rejected",
        1,
        "already used by",
        duplicate_tunnel_uuid,
    ),
    Case(
        "class with no admission registration is rejected",
        1,
        "no organization may use it",
        class_deregistered,
    ),
    Case(
        "dropped protectedZone under zone nesting is rejected",
        1,
        "must declare protectedZone",
        protected_zone_dropped,
    ),
    Case(
        "class with no zone is rejected",
        1,
        "has no zone",
        zone_dropped,
    ),
    Case(
        "reviewer B additive cross-tunnel CCNP pair is rejected",
        1,
        "unexpected rendered policy CiliumClusterwideNetworkPolicy/",
        additive_ccnp_pair,
    ),
    Case(
        "an extra CNP produced by an overlay patch is rejected",
        1,
        "unexpected rendered policy CiliumNetworkPolicy/reviewer-extra-cnp",
        unexpected_overlay_cnp,
    ),
    Case(
        "S1a namespace-only proxy egress overlay rule is rejected",
        1,
        "proxy egress rules must match the closed allow-list exactly",
        namespace_only_overlay_rule,
    ),
    Case(
        "S1b namespace-only proxy egress component rule is rejected",
        1,
        "proxy egress rules must match the closed allow-list exactly",
        namespace_only_component_rule,
    ),
    Case(
        "S1c unkeyed tenant template document is rejected",
        1,
        "unexpected template document CiliumNetworkPolicy/"
        "allow-tunnel-proxy-any",
        template_unkeyed_document,
    ),
    Case(
        "S3 connector-to-sibling additive rule pair is rejected",
        1,
        "connector egress rules must match the closed allow-list exactly",
        cross_tunnel_additive_rules,
    ),
    Case(
        "nwp proxy targeting another organization's tenant is rejected",
        1,
        "closed tenant map requires watched namespace 'nwp-1306985678'",
        tenant_namespace_other_org,
    ),
    Case(
        "nwp proxy targeting kube-system is rejected",
        1,
        "closed tenant map requires watched namespace 'nwp-1306985678'",
        tenant_namespace_kube_system,
    ),
    Case(
        "proxy selecting a sibling tunnel's origins is rejected",
        1,
        "proxy egress rules must match the closed allow-list exactly",
        sibling_opt_in,
    ),
    Case(
        "connector wired to the sibling proxy is rejected",
        1,
        "connector egress rules must match the closed allow-list exactly",
        crossed_connector,
    ),
    Case(
        "placeholder shell guard renders and rejects a proxy child path",
        1,
        "ERROR: Flux child ./clusters/talos-cluster/apps/"
        "traefik-nwp-public:",
        mixed_case_placeholder,
        "placeholder",
    ),
    Case(
        "mixed-case placeholder survivor is rejected",
        1,
        "unresolved placeholder survived the render",
        mixed_case_placeholder,
    ),
    Case(
        "stray retired boolean manifest is rejected tree-wide",
        1,
        "retired boolean opt-in",
        stray_retired_boolean,
    ),
    Case(
        "orphan proxy overlay and Flux child are rejected",
        1,
        "tunnel 'nwp-orphan' violates exact 1:1 pairing; "
        "missing cloudflared overlay",
        orphan_proxy_overlay,
    ),
    Case(
        "connector missing from the apps index is rejected",
        1,
        "tunnel 'nwp-public' violates exact 1:1 pairing; "
        "missing apps connector entry",
        missing_connector_index_entry,
    ),
    Case(
        "class registered to two organizations is rejected",
        1,
        "class 'cf-tunnel-hwg' must be registered under exactly one "
        "organization",
        class_registered_to_two_orgs,
    ),
    Case(
        "tenant template rule without toPorts is rejected",
        1,
        "template ingress rule for tunnel 'nwp-public' must match the "
        "closed allow-list exactly",
        template_without_to_ports,
    ),
)


def run_case(case: Case) -> tuple[bool, int, str]:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        stage(root)
        case.mutate(root)
        if case.checker == "tunnel":
            command = [sys.executable, str(GUARD), str(root)]
        elif case.checker == "placeholder":
            command = ["bash", str(root / PLACEHOLDER_GUARD)]
        else:
            raise AssertionError(
                f"self-test setup: unknown checker {case.checker!r}"
            )
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    output = result.stdout + result.stderr
    passed = (
        result.returncode == case.expected_rc
        and case.required_output in output
    )
    return passed, result.returncode, output


def main() -> int:
    failures = 0
    for case in CASES:
        passed, actual_rc, output = run_case(case)
        if passed:
            print(
                f"OK   {case.name} "
                f"(rc={actual_rc}; matched {case.required_output!r})"
            )
            continue
        failures += 1
        print(f"FAIL {case.name}")
        print(
            f"       expected rc={case.expected_rc} and output containing "
            f"{case.required_output!r}; actual rc={actual_rc}"
        )
        print("       combined output:")
        for line in output.rstrip().splitlines() or ["<no output>"]:
            print(f"         {line}")
    if failures:
        print(
            f"check-tunnel-isolation.selftest: {failures} case(s) failed",
            file=sys.stderr,
        )
        return 1
    print(f"check-tunnel-isolation.selftest: OK ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
