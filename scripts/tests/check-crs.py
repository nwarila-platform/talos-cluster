#!/usr/bin/env python3
"""Pre-check custom resources against the CustomResourceDefinitions that will admit them.

Usage: check-crs.py --require Kind.group/version... CRD-FILE... -- MANIFEST-FILE...

This is a PRE-FILTER, not API-server conformance. The authoritative check is the API server itself: the live
rollout runs `kubectl apply --dry-run=server --validate=strict` on every custom resource before it is applied,
and scripts/keycloak.sh runs `kubectl create --dry-run=server --validate=strict` on the realm import before it
creates it — schema, unknown fields, list semantics and CEL rules are all evaluated there.

Offline, every --require entry must be served by exactly one loaded CRD schema and occur in the manifests at
least once (a missing or ambiguous schema or document is an error, never a pass). Each document of a required
kind is checked against that version's openAPIV3Schema made strict the way a structural schema prunes: an
object schema that is not a map (additionalProperties) and not x-kubernetes-preserve-unknown-fields is CLOSED,
with or without listed properties (apiVersion/kind/metadata are allowed at the root and in
x-kubernetes-embedded-resource objects); int-or-string and nullable are honoured; types, required, enums,
patterns and bounds apply (Draft 2020-12); arrays marked x-kubernetes-list-type set must have unique items and
map must have unique x-kubernetes-list-map-keys tuples. CEL rules (x-kubernetes-validations) are LISTED as
deferred to the server-side dry-run; transition rules (oldSelf) apply to updates only and are counted apart.
"""
import copy
import json
import sys

import jsonschema
import yaml


def parse_gvk(text):
    """Kind.group/version -> ((group/version), Kind)."""
    kind, _, group_version = text.partition(".")
    if not kind or "/" not in group_version:
        sys.exit(f"ERROR: --require wants Kind.group/version, got {text}")
    return group_version, kind


def strict(schema, root=False):
    """A copy of a structural CRD schema in which unknown fields are rejected unless preserved.

    The API server always accepts apiVersion, kind and metadata at the root (it validates metadata
    itself), whether or not the CRD's schema lists them, so the root gets those three before the
    unknown-field rule is applied."""
    if not isinstance(schema, dict):
        return schema
    result = dict(schema)
    if root or result.get("x-kubernetes-embedded-resource"):
        result["properties"] = dict(result.get("properties") or {})
        for name in ("apiVersion", "kind"):
            result["properties"].setdefault(name, {"type": "string"})
        # ObjectMeta is validated by the API server itself, whatever the CRD lists for it.
        result["properties"]["metadata"] = {"type": "object", "x-kubernetes-preserve-unknown-fields": True}
    if result.get("x-kubernetes-int-or-string") and "type" not in result:
        result["type"] = ["integer", "string"]
    if result.get("nullable") and result.get("type"):
        kinds = result["type"] if isinstance(result["type"], list) else [result["type"]]
        result["type"] = [*kinds, "null"]
    if isinstance(result.get("properties"), dict):
        result["properties"] = {name: strict(value) for name, value in result["properties"].items()}
    # A structural object that is neither a map nor preserved accepts only its listed properties — none if it
    # lists none (the API server prunes, and strict validation reports, anything else).
    is_object = result.get("type") == "object" or (isinstance(result.get("type"), list) and "object" in result["type"])
    if is_object and "additionalProperties" not in result and not result.get("x-kubernetes-preserve-unknown-fields"):
        result["additionalProperties"] = False
    if isinstance(result.get("additionalProperties"), dict):
        result["additionalProperties"] = strict(result["additionalProperties"])
    if isinstance(result.get("items"), dict):
        result["items"] = strict(result["items"])
    for key in ("allOf", "anyOf", "oneOf"):
        if isinstance(result.get(key), list):
            result[key] = [strict(value) for value in result[key]]
    if isinstance(result.get("not"), dict):
        result["not"] = strict(result["not"])
    return result


def flatten(document, where, out, problems):
    """Kubernetes' unstructured list rule, as the installer flattens: ANY object whose top-level `items` is an array is
    expanded recursively, whatever its kind. Every child that is not an object with a kind (null, a scalar, a
    kindless mapping) is a problem, never skipped; a List/*List kind whose `items` is missing or not an array is malformed."""
    if not isinstance(document, dict) or not isinstance(document.get("kind"), str):
        problems.append(f"{where}: a document or list item is not an object with a kind ({type(document).__name__})")
        return
    if isinstance(document.get("items"), list):
        for index, item in enumerate(document["items"]):
            flatten(item, f"{where} {document['kind']}.items[{index}]", out, problems)
        return
    if document["kind"] == "List" or document["kind"].endswith("List"):
        problems.append(f"{where}: {document['kind']} items is missing or not a list")
        return
    out.append(document)


def list_semantics(schema, value, path, problems):
    """x-kubernetes-list-type set/map: unique items / unique key tuples (the API server rejects duplicates)."""
    if not isinstance(schema, dict):
        return
    if isinstance(value, list):
        kind = schema.get("x-kubernetes-list-type")
        if kind == "set":
            seen = set()
            for item in value:
                key = json.dumps(item, sort_keys=True)
                if key in seen:
                    problems.append(f"{path}: duplicate item {key} in a list-type set")
                seen.add(key)
        elif kind == "map":
            keys, seen = schema.get("x-kubernetes-list-map-keys") or [], set()
            for item in value:
                key = json.dumps([item.get(k) if isinstance(item, dict) else None for k in keys])
                if key in seen:
                    problems.append(f"{path}: duplicate map key {dict(zip(keys, json.loads(key)))} in a list-type map")
                seen.add(key)
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                list_semantics(schema["items"], item, f"{path}[{index}]", problems)
    elif isinstance(value, dict):
        properties = schema.get("properties") or {}
        extra = schema.get("additionalProperties")
        for key, item in value.items():
            if key in properties:
                list_semantics(properties[key], item, f"{path}.{key}", problems)
            elif isinstance(extra, dict):
                list_semantics(extra, item, f"{path}.{key}", problems)


def cel_rules(schema, value, path, create, transition):
    """Collect the x-kubernetes-validations rules the API server would evaluate for this document."""
    if not isinstance(schema, dict):
        return
    for rule in schema.get("x-kubernetes-validations") or []:
        expression = rule.get("rule", "")
        target = transition if "oldSelf" in expression else create
        target.append((path or "(root)", expression))
    if isinstance(value, dict):
        properties = schema.get("properties") or {}
        extra = schema.get("additionalProperties")
        for key, item in value.items():
            if key in properties:
                cel_rules(properties[key], item, f"{path}.{key}", create, transition)
            elif isinstance(extra, dict):
                cel_rules(extra, item, f"{path}.{key}", create, transition)
    elif isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            cel_rules(schema["items"], item, f"{path}[{index}]", create, transition)


def load_schemas(crd_files):
    schemas = {}
    duplicates = set()
    for path in crd_files:
        with open(path, encoding="utf-8") as stream:
            for document in yaml.safe_load_all(stream):
                if not document or document.get("kind") != "CustomResourceDefinition":
                    continue
                spec = document["spec"]
                group, kind = spec["group"], spec["names"]["kind"]
                for version in spec["versions"]:
                    schema = version.get("schema", {}).get("openAPIV3Schema")
                    if not schema or not version.get("served", True):
                        continue
                    key = (f"{group}/{version['name']}", kind)
                    if key in schemas:
                        duplicates.add(key)
                    schemas[key] = schema
    return schemas, duplicates


def main(argv):
    required = []
    while argv[:1] == ["--require"]:
        if len(argv) < 2:
            sys.exit("ERROR: --require needs a value")
        required.append(parse_gvk(argv[1]))
        argv = argv[2:]
    try:
        split = argv.index("--")
    except ValueError:
        sys.exit("usage: check-crs.py --require Kind.group/version... CRD-FILE... -- MANIFEST-FILE...")
    crd_files, manifest_files = argv[:split], argv[split + 1:]
    if not required:
        sys.exit("ERROR: at least one --require Kind.group/version is needed (the kinds this call must validate)")
    if not crd_files or not manifest_files:
        sys.exit("ERROR: CRD files and manifest files are both required")

    schemas, duplicates = load_schemas(crd_files)
    failed = 0
    for key in required:
        if key in duplicates:
            print(f"ERROR: {key[1]} {key[0]} is served by more than one loaded CRD (ambiguous schema)", file=sys.stderr)
            failed += 1
        elif key not in schemas:
            print(f"ERROR: no served schema loaded for {key[1]} {key[0]} (CRD missing or version not served)", file=sys.stderr)
            failed += 1
    if failed:
        sys.exit(f"ERROR: {failed} required schema(s) unavailable; nothing was validated")

    validators = {key: jsonschema.Draft202012Validator(strict(copy.deepcopy(schemas[key]), root=True)) for key in required}
    seen = {key: 0 for key in required}
    required_kinds = {kind for _, kind in required}
    checked = deferred_total = 0
    identities = set()
    for path in manifest_files:
        with open(path, encoding="utf-8") as stream:
            documents = list(yaml.safe_load_all(stream))
        expanded, problems = [], []
        for index, document in enumerate(documents):
            if document is not None:  # an empty YAML document; a null LIST CHILD is an error in flatten()
                flatten(document, f"{path} document {index}", expanded, problems)
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
            failed += 1
        for document in expanded:
            key = (document.get("apiVersion", ""), document["kind"])
            name = document.get("metadata", {}).get("name", "?")
            if key not in validators:
                if document["kind"] in required_kinds:
                    print(f"ERROR: {path}: {key[1]} {name}: apiVersion {key[0]} is not the required served version", file=sys.stderr)
                    failed += 1
                continue
            identity = (key[0], key[1], document.get("metadata", {}).get("namespace", ""), name)
            if identity in identities:
                print(f"ERROR: {path}: {key[1]} {name} occurs more than once (apiVersion {key[0]}, namespace {identity[2] or '-'})", file=sys.stderr)
                failed += 1
                continue
            identities.add(identity)
            seen[key] += 1
            checked += 1
            errors = sorted(validators[key].iter_errors(document), key=lambda e: list(e.absolute_path))
            problems = []
            list_semantics(schemas[key], document, "", problems)
            if errors or problems:
                failed += 1
                for error in errors:
                    location = ".".join(str(p) for p in error.absolute_path) or "(root)"
                    print(f"ERROR: {path}: {key[1]} {name}: {location}: {error.message}", file=sys.stderr)
                for problem in problems:
                    print(f"ERROR: {path}: {key[1]} {name}: {problem}", file=sys.stderr)
                continue
            create, transition = [], []
            cel_rules(schemas[key], document, "", create, transition)
            deferred_total += len(create)
            print(f"ok: {key[1]} {name} against {key[0]} (pre-check: closed objects, list semantics; "
                  f"{len(create)} CEL rule(s) deferred to the server-side dry-run, {len(transition)} update-only)")
            for location, expression in create:
                print(f"   deferred: {key[1]} {name}: {location}: {expression}")
    for key, count in seen.items():
        if count == 0:
            print(f"ERROR: no {key[1]} {key[0]} document found in the manifests (required)", file=sys.stderr)
            failed += 1
    if checked == 0:
        sys.exit("ERROR: no custom resource was checked")
    if failed:
        sys.exit(f"ERROR: {failed} custom resource check(s) failed")
    print(f"check-crs: {checked} custom resource(s) pass the pre-check; the API server's strict dry-run is authoritative "
          f"({deferred_total} CEL rule(s) evaluated only there)")


if __name__ == "__main__":
    main(sys.argv[1:])
