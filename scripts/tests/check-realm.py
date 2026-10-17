#!/usr/bin/env python3
"""The realm import must be one KeycloakRealmImport whose placeholders all name the realm Secret, whose LDAP
provider is in the reviewed branch, and which declares, byte-exact, the reviewed set of LDAP mappers.

Usage: check-realm.py REALM-IMPORT.yaml [--print-mappers | --print-provider-branch]

Keycloak creates an LDAP provider's mappers only in LDAPStorageProviderFactory.onCreate, which runs for the admin
API/console and not for a realm import through `components`; the realm therefore declares them itself. The
reviewed set is the seven NON-KERBEROS mappers onCreate (26.8.1) creates for this provider's settings (vendor ad,
editMode READ_ONLY, usernameLDAPAttribute sAMAccountName, rdnLDAPAttribute cn): it is deliberately not the complete
onCreate set, because onCreate also creates a Kerberos principal mapper whenever krbPrincipalAttribute is set (it
defaults that attribute itself). This import keeps Kerberos out entirely: allowKerberosAuthentication and
useKerberosForPasswordAuthentication absent or false, krbPrincipalAttribute absent. The mapper list is compared whole
(count, names, providerIds, config key sets, string-array values).
--print-mappers prints the declared mapper list as canonical JSON and --print-provider-branch the provider settings
that select the branch (the live rollout compares the realm Keycloak holds against both).
"""
import json
import re
import sys

import yaml

EXPECTED_PROVIDER_INPUTS = {
    "vendor": ["ad"],
    "editMode": ["READ_ONLY"],
    "usernameLDAPAttribute": ["sAMAccountName"],
    "rdnLDAPAttribute": ["cn"],
}
# Keys whose presence with a true value would turn Kerberos on; the principal attribute must be absent too.
KERBEROS_FLAGS = ("allowKerberosAuthentication", "useKerberosForPasswordAuthentication")
KERBEROS_ATTRIBUTE = "krbPrincipalAttribute"
EXPECTED_MAPPERS = [
    {"name": "username", "providerId": "user-attribute-ldap-mapper", "config": {
        "user.model.attribute": ["username"], "ldap.attribute": ["sAMAccountName"], "read.only": ["true"],
        "always.read.value.from.ldap": ["false"], "is.mandatory.in.ldap": ["true"]}},
    {"name": "full name", "providerId": "full-name-ldap-mapper", "config": {
        "ldap.full.name.attribute": ["cn"], "read.only": ["true"], "write.only": ["false"]}},
    {"name": "last name", "providerId": "user-attribute-ldap-mapper", "config": {
        "user.model.attribute": ["lastName"], "ldap.attribute": ["sn"], "read.only": ["true"],
        "always.read.value.from.ldap": ["true"], "is.mandatory.in.ldap": ["true"]}},
    {"name": "email", "providerId": "user-attribute-ldap-mapper", "config": {
        "user.model.attribute": ["email"], "ldap.attribute": ["mail"], "read.only": ["true"],
        "always.read.value.from.ldap": ["false"], "is.mandatory.in.ldap": ["false"]}},
    {"name": "creation date", "providerId": "user-attribute-ldap-mapper", "config": {
        "user.model.attribute": ["createTimestamp"], "ldap.attribute": ["whenCreated"], "read.only": ["true"],
        "always.read.value.from.ldap": ["true"], "is.mandatory.in.ldap": ["false"]}},
    {"name": "modify date", "providerId": "user-attribute-ldap-mapper", "config": {
        "user.model.attribute": ["modifyTimestamp"], "ldap.attribute": ["whenChanged"], "read.only": ["true"],
        "always.read.value.from.ldap": ["true"], "is.mandatory.in.ldap": ["false"]}},
    {"name": "MSAD account controls", "providerId": "msad-user-account-control-mapper", "config": {
        "always.read.enabled.value.from.ldap": ["true"]}},
]


def canonical(mappers):
    return sorted(({"name": m.get("name"), "providerId": m.get("providerId"), "config": m.get("config")} for m in mappers),
                  key=lambda m: str(m["name"]))


def main(argv):
    if not argv or len(argv) > 2 or (len(argv) == 2 and argv[1] not in ("--print-mappers", "--print-provider-branch")):
        sys.exit("usage: check-realm.py REALM-IMPORT.yaml [--print-mappers | --print-provider-branch]")
    with open(argv[0], encoding="utf-8") as stream:
        documents = list(yaml.safe_load_all(stream))
    if len(documents) != 1 or documents[0].get("kind") != "KeycloakRealmImport":
        sys.exit("ERROR: realm-import.yaml must hold exactly one KeycloakRealmImport")
    spec = documents[0]["spec"]
    placeholders = spec.get("placeholders", {})
    used = set(re.findall(r"\$\{([A-Z_]+)\}", yaml.safe_dump(spec["realm"])))
    declared = set(placeholders)
    if used != declared:
        sys.exit(f"ERROR: realm placeholders used {sorted(used)} != declared {sorted(declared)}")
    for name, placeholder in placeholders.items():
        secret = placeholder.get("secret", {})
        if secret.get("name") != "keycloak-realm-secrets" or secret.get("key") != name:
            sys.exit(f"ERROR: placeholder {name} must come from Secret keycloak-realm-secrets key {name}")

    providers = spec["realm"].get("components", {}).get("org.keycloak.storage.UserStorageProvider", [])
    if len(providers) != 1 or providers[0].get("providerId") != "ldap":
        sys.exit("ERROR: the realm must declare exactly one LDAP user storage provider")
    config = providers[0].get("config", {})
    for key, value in EXPECTED_PROVIDER_INPUTS.items():
        if config.get(key) != value:
            sys.exit(f"ERROR: LDAP provider {key} must be {value} (the mapper set below is onCreate's for these inputs); got {config.get(key)}")
    for flag in KERBEROS_FLAGS:
        if config.get(flag) not in (None, ["false"]):
            sys.exit(f"ERROR: LDAP provider {flag} must be absent or [\"false\"] (Kerberos stays off); got {config.get(flag)}")
    if KERBEROS_ATTRIBUTE in config:
        sys.exit(f"ERROR: LDAP provider {KERBEROS_ATTRIBUTE} must be absent (with it onCreate's branch adds a Kerberos principal mapper); got {config[KERBEROS_ATTRIBUTE]}")
    mappers = providers[0].get("subComponents", {}).get("org.keycloak.storage.ldap.mappers.LDAPStorageMapper", [])
    declared_mappers, expected = canonical(mappers), canonical(EXPECTED_MAPPERS)
    if declared_mappers != expected:
        names = [m["name"] for m in declared_mappers]
        for want in expected:
            got = next((m for m in declared_mappers if m["name"] == want["name"]), None)
            if got is None:
                print(f"ERROR: mapper '{want['name']}' missing", file=sys.stderr)
            elif got != want:
                print(f"ERROR: mapper '{want['name']}' differs: declared {json.dumps(got, sort_keys=True)} "
                      f"expected {json.dumps(want, sort_keys=True)}", file=sys.stderr)
        for extra in [m for m in declared_mappers if m["name"] not in {w["name"] for w in expected}]:
            print(f"ERROR: unexpected mapper '{extra['name']}'", file=sys.stderr)
        sys.exit(f"ERROR: the LDAP provider must declare exactly the seven reviewed non-Kerberos mappers; declared {len(names)}: {names}")
    if len(argv) == 2 and argv[1] == "--print-mappers":
        print(json.dumps(declared_mappers, sort_keys=True, separators=(",", ":")))
    elif len(argv) == 2:
        print(json.dumps(EXPECTED_PROVIDER_INPUTS, sort_keys=True, separators=(",", ":")))
    else:
        print("ok: realm import: placeholders bound to keycloak-realm-secrets; LDAP provider (ad, READ_ONLY, sAMAccountName, cn; "
              "Kerberos flags off, no krbPrincipalAttribute) declares exactly the seven reviewed non-Kerberos mappers")


if __name__ == "__main__":
    main(sys.argv[1:])
