#!/usr/bin/env python3
"""Guard the per-tunnel isolation contract for Cloudflare Tunnel connectors.

An organization may run several tunnels at different protection tiers over the
same tenant namespace, so namespace scoping cannot separate them. Isolation
rests on the tunnel inventory, rendered policy objects, exact policy rule
shapes, tenant ownership, route tables, and admission-policy registrations all
staying in agreement.

The guard compares closed connector, tenant, Namespace, route, and policy
objects across the local renders and the root aggregate Flux applies. It admits
only exact content-hashed build indexes, enumerates every Flux Kustomization by
resolved path, and pins host-namespace and Kyverno enforcement posture.

Usage: check-tunnel-isolation.py [REPO_ROOT]
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from runpy import run_path
from shutil import which

import yaml

APPS = "clusters/talos-cluster/apps"
TENANTS = "clusters/talos-cluster/tenants"
ROOT_CLUSTER = "clusters/talos-cluster"
ROOT_INDEX = f"{ROOT_CLUSTER}/kustomization.yaml"
TENANTS_INDEX = f"{TENANTS}/kustomization.yaml"
TEMPLATE_CNP = (
    f"{TENANTS}/_template/zero-touch/base/"
    "ciliumnetworkpolicy-allow-tunnel-proxy.yaml"
)
BINDING_POLICY = f"{APPS}/kyverno/policies/restrict-tunnel-binding.yaml"
HOSTNAME_POLICY = f"{APPS}/kyverno/policies/restrict-tunnel-hostnames.yaml"
APPS_INDEX = f"{APPS}/kustomization.yaml"
ROOT_FLUX_SYNC = "clusters/talos-cluster/flux-system/gotk-sync.yaml"

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
BUILD_CONTENT_KEYS = frozenset(
    run_path(str(Path(__file__).with_name("rendered-inventory.py")))[
        "BUILD_CONTENT_KEYS"
    ]
)
TUNNEL_TENANTS = {
    "hwg": "hwg-1268831311",
    "nwp-public": "nwp-1306985678",
    "nwp-mtls": "nwp-1306985678",
}
TENANT_CONTRACTS = {
    "hwg-1268831311": {
        "deploy_repo": "deploy-herowars-engine-porter",
        "org": "the-hero-wars-guys",
        "repo_id": "1268831311",
    },
    "nwp-1306985678": {
        "deploy_repo": "deploy-platform-canary",
        "org": "nwarila-platform",
        "repo_id": "1306985678",
    },
}
PSS_LABELS = {
    "pod-security.kubernetes.io/audit": "restricted",
    "pod-security.kubernetes.io/audit-version": "latest",
    "pod-security.kubernetes.io/enforce": "restricted",
    "pod-security.kubernetes.io/enforce-version": "latest",
    "pod-security.kubernetes.io/warn": "restricted",
    "pod-security.kubernetes.io/warn-version": "latest",
}
# Each digest is SHA-256 over the canonical JSON value of one current build key.
# Any index change therefore requires an explicit, reviewable guard update.
INDEX_BUILD_KEY_HASHES = {
    ROOT_INDEX: {
        "resources": "d3c8704ae394df15ee06aa437283a483ff96c00a279a68fa8999f9647ed0468f",
        "patches": "95ba8013aa3bba6d766ac1dd17d809be32f257f59c226386eb4864632e4284b6",
    },
    APPS_INDEX: {
        "resources": "4e2113a4ebaf09b1efcf6ebd18db93e7285ac2e033f06ecd374d1dab35cf0995",
    },
    TENANTS_INDEX: {
        "resources": "30cadcb0565e15da6a0aab468b3ea58d1b46bb79405f8593f7457d4bf53bf4cd",
    },
    f"{TENANTS}/hwg-1268831311/kustomization.yaml": {
        "namespace": "2981fc1034cc29dbb6be2e246b2b247a7eaa35a0bbcb79eec42a796370c55a24",
        "resources": "be029c396fd984c1763772347517577d39609c95ba1c933d35c74429c0d9a277",
        "configMapGenerator": "eb9ebcfea631268b710aa333e18bd8bb8fee2ea31a5258df64bb514a0fe43558",
        "generatorOptions": "b4657318540eee66f84ada741e32c4b3769f5b04b712abbb80455b4e778a8390",
        "patches": "d464bfb4d21d10350815894d3de6a52e008135aacec36851f3f11a0fb2c8f5ce",
        "replacements": "f895b147ec2881fc6cfee6dcc585c7f1390b2502f26d3e2e588d95b8ca5d4f26",
    },
    f"{TENANTS}/nwp-1306985678/kustomization.yaml": {
        "namespace": "eb0d383386a08e195afa838201ef91e7e1ce422771d3cdd5e25ccb3c15c94143",
        "resources": "be029c396fd984c1763772347517577d39609c95ba1c933d35c74429c0d9a277",
        "configMapGenerator": "b58f7d9abb4be95e29302f8b130d89e466af8cd2f800c3cbdb6224a29bf33272",
        "generatorOptions": "b4657318540eee66f84ada741e32c4b3769f5b04b712abbb80455b4e778a8390",
        "patches": "b04ba6b426f145ae7123514d7eb3e502c3b856441b19dcead0d0a0348077271a",
        "replacements": "f895b147ec2881fc6cfee6dcc585c7f1390b2502f26d3e2e588d95b8ca5d4f26",
    },
}
ROUTE_OBJECT_HASHES = {
    "hwg": "1e3e2ae9a4c3fb14475bda27acb06c9268040e627b0eff70cf309bac9e0af09a",
    "nwp-mtls": "51adb1a3c3d15036bdafa8f828c8423106a943ec80541a961e87e796a4032d45",
    "nwp-public": "f942f5f8681cf60eb443455df3390ac700ccf8326ccabc13041c5b81ab55789c",
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
TERNARY_RE = re.compile(r"variables\.class == '([^']+)' \?\s*'([^']*)'")
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

    def load_candidate_mappings(self, relative: str) -> list[tuple[int, dict]]:
        # Kustomize accepts extensionless and arbitrary-suffix resource files.
        # Decode or parse failures cannot be Kubernetes manifest documents.
        try:
            text = (self.root / relative).read_text(encoding="utf-8")
            documents = list(yaml.safe_load_all(text))
        except (UnicodeDecodeError, yaml.YAMLError):
            return []
        return [
            (position, document)
            for position, document in enumerate(documents, start=1)
            if isinstance(document, dict)
        ]


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


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def namespace_object(name: str, labels: dict[str, str]) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"labels": labels, "name": name},
    }


def tunnel_namespace_object(prefix: str, tunnel: str) -> dict:
    name = f"{prefix}-{tunnel}"
    return namespace_object(
        name,
        {**PSS_LABELS, "nwarila.io/platform-addon": name},
    )


def tenant_namespace_object(tenant: str) -> dict:
    contract = TENANT_CONTRACTS[tenant]
    return namespace_object(
        tenant,
        {
            **PSS_LABELS,
            "nwarila.io/deploy-repo": contract["deploy_repo"],
            "nwarila.io/org": contract["org"],
            "nwarila.io/repo-id": contract["repo_id"],
            "nwarila.io/tenant": "true",
        },
    )


def tenant_flux_child(tenant: str) -> dict:
    source = TENANT_CONTRACTS[tenant]["deploy_repo"]
    return {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": {
            "labels": {"nwarila.io/deploy-repo": "true"},
            "name": tenant,
            "namespace": tenant,
        },
        "spec": {
            "interval": "10m",
            "path": "./kubernetes/overlays/talos-cluster",
            "prune": True,
            "serviceAccountName": "deploy-reconciler",
            "sourceRef": {"kind": "GitRepository", "name": source},
            "targetNamespace": tenant,
            "timeout": "10m",
            "wait": True,
        },
    }


def difference_paths(actual: object, expected: object, path: str = "") -> list[str]:
    if type(actual) is not type(expected):
        return [path or "<object>"]
    if isinstance(expected, dict):
        paths: list[str] = []
        actual_keys = set(actual)
        expected_keys = set(expected)
        for key in sorted(actual_keys ^ expected_keys):
            paths.append(f"{path}.{key}" if path else str(key))
        for key in sorted(actual_keys & expected_keys):
            child = f"{path}.{key}" if path else str(key)
            paths.extend(difference_paths(actual[key], expected[key], child))
        return paths
    if isinstance(expected, list):
        if len(actual) != len(expected):
            return [path or "<object>"]
        paths = []
        for index, (actual_item, expected_item) in enumerate(
            zip(actual, expected, strict=True)
        ):
            child = f"{path}[{index}]" if path else f"[{index}]"
            paths.extend(difference_paths(actual_item, expected_item, child))
        return paths
    return [] if actual == expected else [path or "<object>"]


def check_policy_objects(
    g: Guard,
    where: str,
    objects: list[dict],
    expected: list[dict],
    *,
    all_documents: bool = False,
    noun: str = "rendered policy",
) -> None:
    expected_by_identity = {
        object_identity(document): document for document in expected
    }
    if len(expected_by_identity) != len(expected):
        raise ValueError(f"{where}: closed expected policy inventory is duplicated")
    check_policy_inventory(
        g,
        where,
        objects,
        list(expected_by_identity),
        all_documents=all_documents,
        noun=noun,
    )
    actual_by_identity: defaultdict[
        tuple[str, str, str | None], list[dict]
    ] = defaultdict(list)
    for document in objects:
        if all_documents or document.get("kind") in POLICY_KINDS:
            actual_by_identity[object_identity(document)].append(document)
    for identity, expected_document in expected_by_identity.items():
        matches = actual_by_identity.get(identity, [])
        if len(matches) != 1:
            continue
        actual_document = matches[0]
        if canonical_json(actual_document) == canonical_json(expected_document):
            continue
        paths = difference_paths(actual_document, expected_document)
        g.errors.append(
            f"{where}: {noun} {identity_label(identity)} differs from its "
            f"closed expected object at {', '.join(paths)}"
        )


def check_namespace_object(g: Guard, where: str, objects: list[dict], expected: dict) -> None:
    namespaces = [document for document in objects if document.get("kind") == "Namespace"]
    check_policy_objects(
        g,
        where,
        namespaces,
        [expected],
        all_documents=True,
        noun="namespace object",
    )


def check_connector_pod_posture(g: Guard, where: str, deployment: dict) -> None:
    pod_spec = nested(deployment, ("spec", "template", "spec"))
    if not g.check(
        isinstance(pod_spec, dict),
        f"{where}: connector pod spec must be a mapping",
    ):
        return
    g.check(
        "hostNetwork" not in pod_spec or pod_spec.get("hostNetwork") is False,
        f"{where}: connector pod spec hostNetwork must be absent or false",
    )
    for key in ("hostPID", "hostIPC"):
        g.check(
            key not in pod_spec,
            f"{where}: connector pod spec {key} must be absent",
        )
    g.check(
        pod_spec.get("automountServiceAccountToken") is False,
        f"{where}: connector pod spec automountServiceAccountToken must be false",
    )


def check_proxy_host_posture(g: Guard, where: str, values: dict) -> None:
    g.check(
        "hostNetwork" not in values or values.get("hostNetwork") is False,
        f"{where}: proxy HelmRelease values.hostNetwork must be absent or false",
    )
    for key in ("hostPID", "hostIPC"):
        g.check(
            key not in values,
            f"{where}: proxy HelmRelease values.{key} must be absent",
        )


def check_route_object(g: Guard, where: str, tunnel: str, objects: list[dict]) -> None:
    configmap = find_object(g, objects, "ConfigMap", "cloudflared-config", where)
    if configmap is None:
        return
    actual = content_digest(configmap)
    expected = ROUTE_OBJECT_HASHES[tunnel]
    g.check(
        actual == expected,
        f"{where}: route ConfigMap/cloudflared-config differs from its closed "
        f"expected object (sha256 {actual}, expected {expected})",
    )


def check_build_indexes(g: Guard) -> None:
    structural = {"apiVersion", "kind"}
    for relative, expected_hashes in INDEX_BUILD_KEY_HASHES.items():
        documents = g.load(relative)
        if not g.check(
            len(documents) == 1,
            f"{relative}: expected exactly one Kustomize index document, "
            f"found {len(documents)}",
        ):
            continue
        document = documents[0]
        g.check(
            document.get("apiVersion") == "kustomize.config.k8s.io/v1beta1",
            f"{relative}: apiVersion must be kustomize.config.k8s.io/v1beta1",
        )
        g.check(
            document.get("kind") == "Kustomization",
            f"{relative}: kind must be Kustomization",
        )
        actual_keys = set(document) - structural
        expected_keys = set(expected_hashes)
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        g.check(
            not missing,
            f"{relative}: missing recorded build key(s): {missing!r}",
        )
        g.check(
            not extra,
            f"{relative}: unexpected build key(s): {extra!r}",
        )
        for key in sorted(actual_keys & expected_keys):
            actual = content_digest(document[key])
            expected = expected_hashes[key]
            g.check(
                actual == expected,
                f"{relative}: build key {key!r} differs from its recorded "
                f"content hash (sha256 {actual}, expected {expected})",
            )


def rule_signature(rule: object) -> str:
    return canonical_json(rule)


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
    rules.append(
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


def policy_metadata(name: str, namespace: str | None = None) -> dict:
    value = {"name": name}
    if namespace is not None:
        value["namespace"] = namespace
    return value


def default_deny_policy(name: str, namespace: str) -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": policy_metadata(name, namespace),
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


def connector_policy(tunnel: str) -> dict:
    namespace = f"cloudflared-{tunnel}"
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": policy_metadata(f"cloudflared-{tunnel}-egress", namespace),
        "spec": {
            "egress": connector_rules(tunnel),
            "endpointSelector": {
                "matchLabels": {
                    INSTANCE: tunnel,
                    NAME: "cloudflared",
                }
            },
        },
    }


def proxy_policy(tunnel: str, tenant: str) -> dict:
    namespace = f"traefik-{tunnel}"
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": policy_metadata(f"traefik-{tunnel}-network", namespace),
        "spec": {
            "egress": proxy_egress_rules(tunnel, tenant),
            "endpointSelector": {"matchLabels": {PROXY: tunnel}},
            "ingress": [proxy_ingress_rule(tunnel)],
        },
    }


def tunnel_allow_policy(tunnel: str, namespace: str | None = None) -> dict:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": policy_metadata(f"allow-tunnel-proxy-{tunnel}", namespace),
        "spec": {
            "endpointSelector": {"matchLabels": {EXPOSED: tunnel}},
            "ingress": [template_ingress_rule(tunnel)],
        },
    }


def tenant_base_policies(tenant: str) -> list[dict]:
    return [
        {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": policy_metadata("allow-dns-visibility", tenant),
            "spec": {
                "egress": [
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
                                    {"port": "53", "protocol": "UDP"},
                                    {"port": "53", "protocol": "TCP"},
                                ],
                                "rules": {"dns": [{"matchPattern": "*"}]},
                            }
                        ],
                    }
                ],
                "endpointSelector": {},
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": policy_metadata("allow-dns-egress", tenant),
            "spec": {
                "egress": [
                    {
                        "ports": [
                            {"port": 53, "protocol": "UDP"},
                            {"port": 53, "protocol": "TCP"},
                        ],
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "kube-system"
                                    }
                                },
                                "podSelector": {
                                    "matchLabels": {"k8s-app": "kube-dns"}
                                },
                            }
                        ],
                    }
                ],
                "podSelector": {},
                "policyTypes": ["Egress"],
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": policy_metadata("allow-vault-egress", tenant),
            "spec": {
                "egress": [
                    {
                        "ports": [{"port": 8200, "protocol": "TCP"}],
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "deploy-vault"
                                    }
                                },
                                "podSelector": {
                                    "matchLabels": {
                                        "app.kubernetes.io/name": "vault"
                                    }
                                },
                            }
                        ],
                    }
                ],
                "podSelector": {"matchLabels": {"vault-client": "true"}},
                "policyTypes": ["Egress"],
            },
        },
        default_deny_policy("default-deny-all", tenant),
    ]


def tenant_policies(tenant: str) -> list[dict]:
    return tenant_base_policies(tenant) + [
        tunnel_allow_policy(tunnel, tenant) for tunnel in sorted(TUNNEL_TENANTS)
    ]


def parse_ternary_map(document: dict, variable: str) -> dict[str, str]:
    spec = document.get("spec")
    variables = spec.get("variables", []) if isinstance(spec, dict) else []
    for entry in variables:
        if isinstance(entry, dict) and entry.get("name") == variable:
            return dict(TERNARY_RE.findall(str(entry.get("expression", ""))))
    return {}


def check_connector(g: Guard, tunnel: str) -> tuple[dict | None, list[dict]]:
    relative = f"{APPS}/cloudflared-{tunnel}"
    where = f"{relative} (rendered)"
    text, objects = g.render(relative)
    g.check(
        "placeholder" not in text.casefold(),
        f"{where}: an unresolved placeholder survived the render",
    )
    namespace = f"cloudflared-{tunnel}"
    check_policy_objects(
        g,
        where,
        objects,
        [
            connector_policy(tunnel),
            default_deny_policy(
                f"cloudflared-{tunnel}-default-deny",
                namespace,
            ),
        ],
    )
    check_namespace_object(
        g,
        where,
        objects,
        tunnel_namespace_object("cloudflared", tunnel),
    )
    check_route_object(g, where, tunnel, objects)

    deployment = find_object(g, objects, "Deployment", f"cloudflared-{tunnel}", where)
    if deployment is not None:
        check_connector_pod_posture(g, where, deployment)
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
        return None, objects
    data = configmap.get("data")
    raw_config = data.get("config.yaml") if isinstance(data, dict) else None
    if not g.check(
        isinstance(raw_config, str),
        f"{where}: cloudflared-config data.config.yaml is missing",
    ):
        return None, objects
    config = yaml.safe_load(raw_config)
    if not g.check(
        isinstance(config, dict),
        f"{where}: cloudflared-config data.config.yaml must be a mapping",
    ):
        return None, objects
    return config, objects


def check_routes(
    g: Guard,
    tunnel: str,
    config: dict,
    zone: str,
    protected: str,
    seen: dict[str, str],
) -> None:
    where = f"{APPS}/cloudflared-{tunnel}/configmap.yaml"
    root_origin_request = config.get("originRequest")
    g.check(
        not isinstance(root_origin_request, dict)
        or "httpHostHeader" not in root_origin_request,
        f"{where}: top-level originRequest.httpHostHeader is forbidden",
    )
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
    tunnel_service = f"http://traefik-{tunnel}.traefik-{tunnel}.svc:80"
    allowed_services = {tunnel_service}
    if tunnel == "hwg":
        allowed_services.add("http://hello-hwg.hello-hwg.svc:8080")
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            g.errors.append(f"{where}: every ingress route must be a mapping")
            continue
        origin_request = rule.get("originRequest")
        g.check(
            not isinstance(origin_request, dict)
            or "httpHostHeader" not in origin_request,
            f"{where}: ingress route {index} must not set "
            "originRequest.httpHostHeader",
        )
        hostname, service = rule.get("hostname"), str(rule.get("service", ""))
        if service.startswith("http_status:"):
            continue
        g.check(
            service in allowed_services,
            f"{where}: routed hostname {hostname!r} service must be exactly "
            f"{tunnel_service!r} for tunnel {tunnel!r}"
            + (
                " or the declared hwg hello-hwg exception"
                if tunnel == "hwg"
                else ""
            ),
        )
        if hostname is None:
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
    tenant = TUNNEL_TENANTS.get(tunnel)
    if tenant is None:
        g.errors.append(
            f"{where}: tunnel {tunnel!r} is absent from the closed TUNNEL_TENANTS map"
        )
        return
    check_policy_objects(
        g,
        where,
        objects,
        [
            proxy_policy(tunnel, tenant),
            default_deny_policy(
                f"traefik-{tunnel}-default-deny",
                f"traefik-{tunnel}",
            ),
        ],
    )
    check_namespace_object(
        g,
        where,
        objects,
        tunnel_namespace_object("traefik", tunnel),
    )

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
        check_proxy_host_posture(g, where, values)
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


def forbidden_build_content_keys(
    spec: dict,
    *,
    allowed: frozenset[str] = frozenset(),
) -> list[str]:
    return sorted(
        key
        for key in spec
        if (
            key in BUILD_CONTENT_KEYS or key == "patchesStrategicMerge"
        )
        and key not in allowed
    )


def internal_source_ref(value: object, owner_namespace: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get("kind") == "GitRepository"
        and value.get("name") == "flux-system"
        and value.get("namespace", owner_namespace) == "flux-system"
    )


def is_flux_kustomization(document: dict) -> bool:
    api_version = document.get("apiVersion")
    return (
        isinstance(api_version, str)
        and api_version.split("/", 1)[0] == "kustomize.toolkit.fluxcd.io"
        and document.get("kind") == "Kustomization"
    )


def normalize_flux_path(root: Path, value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute():
        return None
    normalized = posixpath.normpath(value)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        return None
    resolved_root = root.resolve()
    resolved = (resolved_root / normalized).resolve()
    try:
        return resolved.relative_to(resolved_root).as_posix()
    except ValueError:
        return None


def paths_intersect(left: str, right: str) -> bool:
    left_parts = PurePosixPath(left).parts
    right_parts = PurePosixPath(right).parts
    shortest = min(len(left_parts), len(right_parts))
    return left_parts[:shortest] == right_parts[:shortest]


def expand_list_document(
    document: dict,
    where: str,
) -> list[tuple[str, dict]]:
    if document.get("kind") != "List":
        return [(where, document)]
    items = document.get("items")
    if not isinstance(items, list):
        raise ValueError(f"{where}: List.items must be a list")
    expanded: list[tuple[str, dict]] = []
    for index, item in enumerate(items):
        item_where = f"{where}.items[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{item_where}: List item must be a mapping")
        expanded.extend(expand_list_document(item, item_where))
    return expanded


def check_flux_kustomizations(g: Guard, tunnels: list[str]) -> None:
    protected_paths = {
        f"{APPS}/_components/tunnel-connector",
        f"{APPS}/_components/tunnel-proxy",
        *(f"{APPS}/cloudflared-{tunnel}" for tunnel in tunnels),
        *(f"{APPS}/traefik-{tunnel}" for tunnel in tunnels),
        *(f"{TENANTS}/{tenant}" for tenant in set(TUNNEL_TENANTS.values())),
    }
    expected = {
        ROOT_CLUSTER: (ROOT_FLUX_SYNC, "flux-system", "flux-system"),
        **{
            f"{APPS}/traefik-{tunnel}": (
                f"{APPS}/kustomization-traefik-{tunnel}.yaml",
                f"traefik-{tunnel}",
                "flux-system",
            )
            for tunnel in tunnels
        },
    }
    counts: Counter[str] = Counter()
    cluster = g.root / ROOT_CLUSTER
    paths = sorted(
        path
        for path in cluster.rglob("*")
        if path.is_file()
    )
    for path in paths:
        relative = path.relative_to(g.root).as_posix()
        strict_manifest = path.suffix.casefold() in {".json", ".yaml", ".yml"}
        candidates = (
            list(enumerate(g.load(relative), start=1))
            if strict_manifest
            else g.load_candidate_mappings(relative)
        )
        for position, document in candidates:
            document_where = f"{relative}: document {position}"
            for where, candidate in expand_list_document(
                document,
                document_where,
            ):
                if not is_flux_kustomization(candidate):
                    continue
                spec = candidate.get("spec")
                if not g.check(
                    isinstance(spec, dict),
                    f"{where}: Flux Kustomization spec must be a mapping",
                ):
                    continue
                raw_path = spec.get("path")
                normalized = normalize_flux_path(g.root, raw_path)
                if not g.check(
                    normalized is not None,
                    f"{where}: Flux Kustomization spec.path {raw_path!r} must "
                    "resolve to a non-empty path inside the repository",
                ):
                    continue
                touches_protected = any(
                    paths_intersect(normalized, protected)
                    for protected in protected_paths
                )
                if not touches_protected:
                    continue
                counts[normalized] += 1
                identity = object_identity(candidate)
                contract = expected.get(normalized)
                if contract is None:
                    g.errors.append(
                        f"{where}: unexpected Flux Kustomization "
                        f"{identity_label(identity)} targets protected path "
                        f"{raw_path!r}"
                    )
                else:
                    expected_file, expected_name, expected_namespace = contract
                    g.check(
                        relative == expected_file
                        and identity
                        == ("Kustomization", expected_name, expected_namespace),
                        f"{where}: unexpected Flux Kustomization "
                        f"{identity_label(identity)} targets protected path "
                        f"{raw_path!r}; only Kustomization/{expected_name} "
                        f"namespace {expected_namespace!r} in {expected_file} "
                        "may own it",
                    )
                allowed = (
                    frozenset({"decryption"})
                    if normalized == ROOT_CLUSTER
                    else frozenset()
                )
                forbidden = forbidden_build_content_keys(spec, allowed=allowed)
                g.check(
                    not forbidden,
                    f"{where}: Flux Kustomization targeting protected path "
                    f"{raw_path!r} contains forbidden build-affecting key(s): "
                    f"{forbidden!r}",
                )
                g.check(
                    internal_source_ref(
                        spec.get("sourceRef"),
                        metadata(candidate).get("namespace"),
                    ),
                    f"{where}: Flux Kustomization targeting protected path "
                    f"{raw_path!r} must reference GitRepository/flux-system "
                    "in namespace 'flux-system'",
                )
    for path, (_file, name, namespace) in sorted(expected.items()):
        g.check(
            counts[path] == 1,
            f"{ROOT_CLUSTER}: protected path './{path}' must have exactly one "
            f"Flux Kustomization owner {name!r} in namespace {namespace!r}; "
            f"found {counts[path]}",
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
    if not g.check(
        isinstance(spec, dict),
        f"{relative}: Flux child spec must be a mapping",
    ):
        return
    forbidden = forbidden_build_content_keys(spec)
    g.check(
        not forbidden,
        f"{relative}: Flux child spec contains forbidden build-affecting "
        f"key(s): {forbidden!r}",
    )
    g.check(
        spec.get("path") == f"./{APPS}/traefik-{tunnel}",
        f"{relative}: spec.path must be ./{APPS}/traefik-{tunnel}",
    )
    g.check(
        internal_source_ref(
            spec.get("sourceRef"),
            metadata(document).get("namespace"),
        ),
        f"{relative}: spec.sourceRef must reference GitRepository/flux-system "
        "in namespace 'flux-system'",
    )


def check_root_flux_build(g: Guard) -> None:
    documents = g.load(ROOT_FLUX_SYNC)
    matches = [
        document
        for document in documents
        if document.get("apiVersion") == "kustomize.toolkit.fluxcd.io/v1"
        and document.get("kind") == "Kustomization"
        and metadata(document).get("name") == "flux-system"
        and metadata(document).get("namespace") == "flux-system"
    ]
    if not g.check(
        len(matches) == 1,
        f"{ROOT_FLUX_SYNC}: expected exactly one root Flux "
        f"Kustomization/flux-system, found {len(matches)}",
    ):
        return
    spec = matches[0].get("spec")
    if not g.check(
        isinstance(spec, dict),
        f"{ROOT_FLUX_SYNC}: root Flux Kustomization spec must be a mapping",
    ):
        return
    # Root SOPS decryption is pre-existing and required. It is not one of C3's
    # enumerated mutation surfaces; every other shared build-content key is
    # forbidden so the aggregate connector render remains the applied build.
    forbidden = forbidden_build_content_keys(
        spec,
        allowed=frozenset({"decryption"}),
    )
    g.check(
        not forbidden,
        f"{ROOT_FLUX_SYNC}: root Flux Kustomization spec contains forbidden "
        f"build-affecting key(s): {forbidden!r}",
    )


def check_tenant_namespaces(
    g: Guard,
) -> tuple[dict[str, str], dict[str, list[dict]]]:
    tenant_orgs: dict[str, str] = {}
    rendered: dict[str, list[dict]] = {}
    for tenant in sorted(set(TUNNEL_TENANTS.values())):
        relative = f"{TENANTS}/{tenant}"
        directory = g.root / relative
        if not g.check(
            directory.is_dir(),
            f"{relative}: required tenant directory is missing",
        ):
            continue
        _text, objects = g.render(relative)
        rendered[tenant] = objects
        check_policy_objects(
            g,
            f"{relative} (rendered)",
            objects,
            tenant_policies(tenant),
        )
        check_namespace_object(
            g,
            f"{relative} (rendered)",
            objects,
            tenant_namespace_object(tenant),
        )
        flux_children = [
            document
            for document in objects
            if is_flux_kustomization(document)
        ]
        check_policy_objects(
            g,
            f"{relative} (rendered)",
            flux_children,
            [tenant_flux_child(tenant)],
            all_documents=True,
            noun="rendered Flux Kustomization",
        )
        tenant_orgs[tenant] = TENANT_CONTRACTS[tenant]["org"]
    return tenant_orgs, rendered


def namespace_scope(objects: list[dict], namespace: str) -> list[dict]:
    return [
        document
        for document in objects
        if metadata(document).get("namespace") == namespace
        or (
            document.get("kind") == "Namespace"
            and metadata(document).get("name") == namespace
        )
    ]


def check_root_aggregate(
    g: Guard,
    tunnels: list[str],
    connector_renders: dict[str, list[dict]],
    tenant_renders: dict[str, list[dict]],
) -> None:
    _text, aggregate = g.render(ROOT_CLUSTER)
    where = f"{ROOT_CLUSTER} (aggregate)"
    for tunnel in tunnels:
        namespace = f"cloudflared-{tunnel}"
        applied = namespace_scope(aggregate, namespace)
        expected = namespace_scope(connector_renders[tunnel], namespace)
        check_policy_objects(
            g,
            where,
            applied,
            expected,
            all_documents=True,
            noun="aggregate object",
        )
        check_route_object(g, where, tunnel, applied)
        deployment = find_object(
            g,
            applied,
            "Deployment",
            f"cloudflared-{tunnel}",
            where,
        )
        if deployment is not None:
            check_connector_pod_posture(g, where, deployment)

        proxy_namespace = f"traefik-{tunnel}"
        check_policy_objects(
            g,
            where,
            namespace_scope(aggregate, proxy_namespace),
            [],
            all_documents=True,
            noun="root-applied proxy object",
        )

    for tenant, expected_objects in sorted(tenant_renders.items()):
        check_policy_objects(
            g,
            where,
            namespace_scope(aggregate, tenant),
            namespace_scope(expected_objects, tenant),
            all_documents=True,
            noun="aggregate object",
        )

    guarded_namespaces = {
        *(f"cloudflared-{tunnel}" for tunnel in tunnels),
        *(f"traefik-{tunnel}" for tunnel in tunnels),
        *tenant_renders,
    }
    applied_policies = [
        document
        for document in aggregate
        if document.get("kind") == "CiliumClusterwideNetworkPolicy"
        or (
            document.get("kind") in POLICY_KINDS
            and metadata(document).get("namespace") in guarded_namespaces
        )
    ]
    expected_policies = [
        policy
        for tunnel in tunnels
        for policy in (
            connector_policy(tunnel),
            default_deny_policy(
                f"cloudflared-{tunnel}-default-deny",
                f"cloudflared-{tunnel}",
            ),
        )
    ]
    expected_policies.extend(
        policy
        for tenant in sorted(tenant_renders)
        for policy in tenant_policies(tenant)
    )
    check_policy_objects(
        g,
        where,
        applied_policies,
        expected_policies,
        noun="aggregate policy",
    )


def check_template(g: Guard, tunnels: list[str]) -> None:
    documents = g.load(TEMPLATE_CNP)
    expected = [tunnel_allow_policy(tunnel) for tunnel in tunnels]
    check_policy_objects(
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


def ingress_resource_rule(
    operations: list[str],
    resource: str,
) -> dict:
    return {
        "apiGroups": ["networking.k8s.io"],
        "apiVersions": ["v1"],
        "operations": operations,
        "resources": [resource],
    }


def check_kyverno_posture(
    g: Guard,
    relative: str,
    document: dict,
    resource_rules: list[dict],
) -> None:
    spec = document.get("spec")
    if not g.check(
        isinstance(spec, dict),
        f"{relative}: spec must be a mapping",
    ):
        return
    g.check(
        spec.get("validationActions") == ["Deny"],
        f"{relative}: spec.validationActions must be exactly ['Deny']",
    )
    g.check(
        spec.get("failurePolicy") == "Fail",
        f"{relative}: spec.failurePolicy must be exactly 'Fail'",
    )
    constraints = spec.get("matchConstraints")
    constraints = constraints if isinstance(constraints, dict) else {}
    g.check(
        constraints.get("namespaceSelector")
        == {"matchLabels": {"nwarila.io/tenant": "true"}},
        f"{relative}: spec.matchConstraints.namespaceSelector must match the "
        "closed tenant selector exactly",
    )
    g.check(
        constraints.get("resourceRules") == resource_rules,
        f"{relative}: spec.matchConstraints.resourceRules must match the "
        "closed rules exactly",
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
    check_kyverno_posture(
        g,
        BINDING_POLICY,
        binding,
        [
            ingress_resource_rule(["CREATE", "UPDATE"], "ingresses"),
            ingress_resource_rule(["UPDATE"], "ingresses/status"),
            ingress_resource_rule(["CREATE", "UPDATE"], "ingressclasses"),
        ],
    )
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
    check_kyverno_posture(
        g,
        HOSTNAME_POLICY,
        hostnames,
        [ingress_resource_rule(["CREATE", "UPDATE"], "ingresses")],
    )
    zones = parse_ternary_map(hostnames, "zone")
    protected = parse_ternary_map(hostnames, "protectedZone")
    canaries = parse_ternary_map(hostnames, "canaryHost")
    for klass in sorted(expected):
        zone = zones.get(klass, "")
        g.check(
            bool(zone),
            f"{HOSTNAME_POLICY}: class {klass!r} has no zone; "
            "its hostnames would be unconstrained",
        )
        canary = canaries.get(klass, "")
        if canary and zone:
            g.check(
                canary.endswith(f".{zone}"),
                f"{HOSTNAME_POLICY}: canary {canary!r} is outside zone {zone!r}",
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
        paths = sorted(
            path
            for path in directory.rglob("*")
            if path.is_file() and path.suffix in {".yaml", ".yml"}
        )
        for path in paths:
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
        check_build_indexes(g)
        tunnels = discover_tunnels(g)
        check_root_flux_build(g)
        check_flux_kustomizations(g, tunnels)
        tenant_orgs, tenant_renders = check_tenant_namespaces(g)
        configs: dict[str, dict | None] = {}
        connector_renders: dict[str, list[dict]] = {}
        for tunnel in tunnels:
            configs[tunnel], connector_renders[tunnel] = check_connector(g, tunnel)
            check_proxy(g, tunnel)
            check_flux_child(g, tunnel)
        check_root_aggregate(
            g,
            tunnels,
            connector_renders,
            tenant_renders,
        )
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
    except RenderError as error:
        if g.errors:
            print("check-tunnel-isolation: FAILED", file=sys.stderr)
            for finding in g.errors:
                print(f"  - {finding}", file=sys.stderr)
            print(
                f"  - {ROOT_CLUSTER}: aggregate render also failed: {error}",
                file=sys.stderr,
            )
        else:
            print(
                f"check-tunnel-isolation: unreadable tunnel inventory: {error}",
                file=sys.stderr,
            )
        return 1
    except (
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
        f"{', '.join(tunnels)}; exact pairing; closed aggregate, tunnel, tenant, "
        "Namespace, route, and policy objects; content-hashed indexes; all Flux "
        "paths; host posture; tenant ownership; and Kyverno enforcement verified)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
