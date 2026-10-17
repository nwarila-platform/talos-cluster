#!/usr/bin/env python3
"""Every RBAC object and admission webhook the Keycloak platform installs: exactly the reviewed ones.

Usage: check-rbac.py --accepted ACCEPTED.json --cert-manager RENDER --cnpg RENDER --keycloak-operator RENDER [--write]

RENDER files are the rendered manifests (helm template with the installed release names; kubectl kustomize).
From each render — with every object whose top-level `items` is an array expanded recursively (Kubernetes'
unstructured list rule, whatever the kind, as the installer flattens them), and a duplicated identity an error — the checker takes every ClusterRole, ClusterRoleBinding, Role,
RoleBinding, MutatingWebhookConfiguration and ValidatingWebhookConfiguration, normalizes it (names, namespace, rules with
sorted lists, roleRef, sorted subjects; for webhooks: rules, namespace and object selectors, failure and match
policy, side effects, the target service — not the CA bundle the controllers inject) and compares the whole
inventory with ACCEPTED.json, the reviewed fingerprint committed next to this file. Any added, removed or
changed object fails: a chart or manifest bump that widens a grant cannot pass until the fingerprint is
regenerated (--write) and that diff is reviewed. On top of the exact comparison, policy checks state the
reasons the fingerprint was accepted, so a regenerated fingerprint cannot quietly break them:
  - no rule anywhere has `*` in apiGroups, resources or verbs;
  - CloudNativePG: exactly one ClusterRoleBinding, to its own service account in keycloak, whose ClusterRole
    has exactly the three accepted rule groups (nodes read; webhook configurations get/patch; cluster image
    catalogs read) and no Secret rule; no other CloudNativePG ClusterRole touches Secrets;
  - Keycloak operator: no ClusterRoleBinding; each of its ClusterRoles bound only by RoleBindings in keycloak
    whose only subject is the keycloak-operator service account;
  - cert-manager: every ClusterRoleBinding's subjects are service accounts in cert-manager.
"""
import json
import sys

import yaml

RBAC_KINDS = ("ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding")
WEBHOOK_KINDS = ("MutatingWebhookConfiguration", "ValidatingWebhookConfiguration")
CNPG_RULES = [
    {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get", "list", "watch"]},
    {"apiGroups": ["admissionregistration.k8s.io"],
     "resources": ["mutatingwebhookconfigurations", "validatingwebhookconfigurations"], "verbs": ["get", "patch"]},
    {"apiGroups": ["postgresql.cnpg.io"], "resources": ["clusterimagecatalogs"], "verbs": ["get", "list", "watch"]},
]
SOURCES = ("cert-manager", "cnpg", "keycloak-operator")

errors = []


def error(message):
    errors.append(message)
    print(f"ERROR: {message}", file=sys.stderr)


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def norm_rule(rule):
    out = {key: sorted(rule[key]) for key in ("apiGroups", "resources", "verbs", "resourceNames", "nonResourceURLs") if rule.get(key)}
    return out


def norm_rules(rules):
    return sorted((norm_rule(r) for r in rules or []), key=canon)


def norm_webhook(hook):
    client = hook.get("clientConfig", {})
    service = client.get("service")
    return {
        "name": hook.get("name"),
        "rules": sorted(({**r, "apiGroups": sorted(r.get("apiGroups", [])), "apiVersions": sorted(r.get("apiVersions", [])),
                          "operations": sorted(r.get("operations", [])), "resources": sorted(r.get("resources", []))}
                         for r in hook.get("rules") or []), key=canon),
        "namespaceSelector": hook.get("namespaceSelector"),
        "objectSelector": hook.get("objectSelector"),
        "failurePolicy": hook.get("failurePolicy"),
        "matchPolicy": hook.get("matchPolicy"),
        "sideEffects": hook.get("sideEffects"),
        "timeoutSeconds": hook.get("timeoutSeconds"),
        "reinvocationPolicy": hook.get("reinvocationPolicy"),
        "matchConditions": hook.get("matchConditions"),
        "service": {k: service.get(k) for k in ("namespace", "name", "path", "port")} if service else None,
        "url": client.get("url"),
        "admissionReviewVersions": sorted(hook.get("admissionReviewVersions") or []),
    }


def normalize(document):
    kind, meta = document["kind"], document.get("metadata", {})
    entry = {"kind": kind, "name": meta.get("name"), "namespace": meta.get("namespace")}
    if kind in ("ClusterRole", "Role"):
        entry["rules"] = norm_rules(document.get("rules"))
        entry["aggregationRule"] = document.get("aggregationRule")
    elif kind in ("ClusterRoleBinding", "RoleBinding"):
        entry["roleRef"] = document.get("roleRef")
        entry["subjects"] = sorted(document.get("subjects") or [], key=canon)
    else:
        entry["webhooks"] = sorted((norm_webhook(h) for h in document.get("webhooks") or []), key=canon)
    return entry


def flatten(document, where):
    """Every object the installer would create from DOCUMENT. Kubernetes' unstructured rule (Unstructured.IsList)
    treats ANY object whose top-level `items` is an array as a list, whatever its kind, and Helm's resource
    builder flattens every such object before create/update; so does this, recursively. A list item that is not
    an object with a kind fails closed — null, scalar and kindless children included (an empty YAML document is
    skipped by the caller, never here); a List/*List kind whose `items` is missing or not an array is malformed."""
    if not isinstance(document, dict) or not isinstance(document.get("kind"), str):
        error(f"{where}: a document or list item is not an object with a kind")
        return []
    if isinstance(document.get("items"), list):
        out = []
        for index, item in enumerate(document["items"]):
            out.extend(flatten(item, f"{where} {document['kind']}.items[{index}]"))
        return out
    if document["kind"] == "List" or document["kind"].endswith("List"):
        error(f"{where}: {document['kind']} items is missing or not a list")
        return []
    return [document]


def inventory(path, source):
    with open(path, encoding="utf-8") as stream:
        objects = [o for d in yaml.safe_load_all(stream) if d is not None for o in flatten(d, f"{source} render")]
    entries = [normalize(o) for o in objects if o.get("kind") in RBAC_KINDS + WEBHOOK_KINDS]
    seen = set()
    for e in entries:
        key = (e["kind"], e["namespace"] or "", e["name"] or "")
        if key in seen:
            error(f"{source}: {e['kind']} {e['namespace'] or ''}/{e['name']} occurs more than once in the render")
        seen.add(key)
    return sorted(entries, key=lambda e: (e["kind"], e["namespace"] or "", e["name"] or ""))


def wildcard(rule):
    return any("*" in rule.get(key, []) for key in ("apiGroups", "resources", "verbs"))


def touches_secrets(rules):
    return any(("secrets" in r.get("resources", []) or "*" in r.get("resources", [])) and
               ("" in r.get("apiGroups", []) or "*" in r.get("apiGroups", [])) for r in rules or [])


def policy(source, entries):
    by = lambda kind: [e for e in entries if e["kind"] == kind]
    for e in entries:
        for rule in e.get("rules") or []:
            if wildcard(rule):
                error(f"{source}: {e['kind']} {e['name']} has a wildcard rule {canon(rule)}")
    roles = {e["name"]: e for e in by("ClusterRole")}
    if source == "cnpg":
        crbs = by("ClusterRoleBinding")
        if [c["name"] for c in crbs] != ["cnpg-cloudnative-pg"]:
            error(f"cnpg: ClusterRoleBindings {[c['name'] for c in crbs]} != ['cnpg-cloudnative-pg']")
        for c in crbs:
            if c["subjects"] != [{"kind": "ServiceAccount", "name": "cnpg-cloudnative-pg", "namespace": "keycloak"}] or \
               c["roleRef"] != {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cnpg-cloudnative-pg"}:
                error(f"cnpg: ClusterRoleBinding {c['name']} binds {canon(c['roleRef'])} to {canon(c['subjects'])}")
        role = roles.get("cnpg-cloudnative-pg")
        if role is None or role["rules"] != norm_rules(CNPG_RULES):
            error(f"cnpg: ClusterRole cnpg-cloudnative-pg rules are not the accepted three groups: {canon(role and role['rules'])}")
        for name, r in roles.items():
            if touches_secrets(r["rules"]):
                error(f"cnpg: ClusterRole {name} touches Secrets")
    if source == "keycloak-operator":
        if by("ClusterRoleBinding"):
            error(f"keycloak-operator: ClusterRoleBinding(s) present: {[c['name'] for c in by('ClusterRoleBinding')]}")
        for rb in by("RoleBinding"):
            if rb["namespace"] != "keycloak" or rb["subjects"] != [{"kind": "ServiceAccount", "name": "keycloak-operator", "namespace": "keycloak"}]:
                error(f"keycloak-operator: RoleBinding {rb['namespace']}/{rb['name']} subjects {canon(rb['subjects'])} (only the keycloak-operator service account in keycloak is accepted)")
        bound = {rb["roleRef"]["name"] for rb in by("RoleBinding") if rb["roleRef"].get("kind") == "ClusterRole"}
        for name in roles:
            if name not in bound:
                error(f"keycloak-operator: ClusterRole {name} is not bound by a RoleBinding in keycloak")
    if source == "cert-manager":
        for c in by("ClusterRoleBinding"):
            if not c["subjects"] or any(s.get("kind") != "ServiceAccount" or s.get("namespace") != "cert-manager" for s in c["subjects"]):
                error(f"cert-manager: ClusterRoleBinding {c['name']} has subjects outside cert-manager's service accounts: {canon(c['subjects'])}")


def main(argv):
    options, write = {}, False
    while argv:
        flag = argv.pop(0)
        if flag == "--write":
            write = True
            continue
        if flag not in ("--accepted", "--cert-manager", "--cnpg", "--keycloak-operator") or not argv:
            sys.exit("usage: check-rbac.py --accepted FILE --cert-manager R --cnpg R --keycloak-operator R [--write]")
        options[flag] = argv.pop(0)
    if set(options) != {"--accepted", "--cert-manager", "--cnpg", "--keycloak-operator"}:
        sys.exit("ERROR: --accepted and all three renders are required")
    current = {source: inventory(options[f"--{source}"], source) for source in SOURCES}
    for source in SOURCES:
        if not current[source]:
            error(f"{source}: the render holds no RBAC or webhook object (wrong file?)")
        policy(source, current[source])
    if write:
        if errors:
            sys.exit("ERROR: refusing to write a fingerprint that violates the policy")
        with open(options["--accepted"], "w", encoding="utf-8") as stream:
            json.dump(current, stream, indent=1, sort_keys=True)
            stream.write("\n")
        print(f"wrote {options['--accepted']}: " + ", ".join(f"{s} {len(current[s])}" for s in SOURCES))
        return
    with open(options["--accepted"], encoding="utf-8") as stream:
        accepted = json.load(stream)
    for source in SOURCES:
        want = {canon({k: e[k] for k in ("kind", "namespace", "name")}): e for e in accepted.get(source, [])}
        have = {canon({k: e[k] for k in ("kind", "namespace", "name")}): e for e in current[source]}
        for key in sorted(set(want) | set(have)):
            if key not in have:
                error(f"{source}: reviewed object missing from the render: {key}")
            elif key not in want:
                error(f"{source}: object not in the reviewed fingerprint: {key} {canon(have[key])}")
            elif canon(have[key]) != canon(want[key]):
                error(f"{source}: object differs from the reviewed fingerprint: {key}\n  render:   {canon(have[key])}\n  reviewed: {canon(want[key])}")
    if errors:
        sys.exit(f"ERROR: {len(errors)} RBAC/webhook check(s) failed")
    print("check-rbac: RBAC objects and admission webhooks are exactly the reviewed fingerprint ("
          + ", ".join(f"{s} {len(current[s])}" for s in SOURCES) + "); policy holds")


if __name__ == "__main__":
    main(sys.argv[1:])
