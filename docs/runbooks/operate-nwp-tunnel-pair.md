# Operate The nwarila-platform Tunnel Pair

`nwarila-platform` runs two Cloudflare Tunnels over the same tenant namespace,
at two protection tiers:

| Tunnel | Cloudflare tunnel id | Zone | Protection |
|---|---|---|---|
| `nwp-public` | `1f59f78a-16f8-4e3c-8567-de0235e39871` | `nicholaswarila.com` | none |
| `nwp-mtls` | `fb6932d9-c6e4-4ccb-8e4c-dee47aa05313` | `secure.nicholaswarila.com` | client certificate at the Cloudflare edge |

Both tunnels watch the same tenant namespace `nwp-1306985678`, so namespace
scoping cannot separate them. The separation is the `nwarila.io/tunnel-exposed`
pod label carrying the tunnel *name*: a Kubernetes label holds one value per
key, so a pod is reachable from exactly one proxy. Three independent layers
enforce the boundary, and `scripts/check-tunnel-isolation.py` fails CI if any of
them drifts:

1. **Admission** — `restrict-tunnel-binding` permits the org only its two
   registered classes; `restrict-tunnel-hostnames` pins each class to its zone
   and bars `cf-tunnel-nwp-public` from `secure.nicholaswarila.com` entirely.
2. **Connector routing** — `cloudflared-nwp-public` answers `http_status:404`
   for the protected zone in a rule ordered *ahead* of its own wildcard, so a
   lost DNS route fails closed rather than serving protected hostnames
   unauthenticated. `cloudflared-nwp-mtls` serves nothing outside the protected
   zone.
3. **Network policy** — each Traefik proxy may egress only to pods labelled
   with its own tunnel name, on TCP 8080.

## Status

The Git side is complete and the tunnels exist in Cloudflare. Two Cloudflare
edge steps remain owner-gated and are **not** yet done:

- neither tunnel has a DNS route, so no hostname resolves to either connector;
- the `nwp-mtls` client-certificate configuration is not chosen or applied, so
  the protected zone is currently protected only by having no DNS route.

Until both land, `nwp-mtls` must be treated as unproven, not as protected.

## Reconcile And Prove The Rollout

```bash
flux reconcile kustomization flux-system -n flux-system --with-source
flux reconcile kustomization traefik-nwp-public -n flux-system
flux reconcile kustomization traefik-nwp-mtls -n flux-system
flux reconcile kustomization kyverno-policies -n flux-system
kubectl rollout status deployment/cloudflared-nwp-public -n cloudflared-nwp-public --timeout=10m
kubectl rollout status deployment/cloudflared-nwp-mtls -n cloudflared-nwp-mtls --timeout=10m
kubectl rollout status deployment/traefik-nwp-public -n traefik-nwp-public --timeout=10m
kubectl rollout status deployment/traefik-nwp-mtls -n traefik-nwp-mtls --timeout=10m
```

All four Deployments must report two Ready pods. Confirm both hand-authored
classes carry the stock controller string and no default-class annotation:

```bash
for class in cf-tunnel-nwp-public cf-tunnel-nwp-mtls; do
  kubectl get ingressclass "${class}" -o json | jq -e '
    .spec.controller == "traefik.io/ingress-controller" and
    (.metadata.annotations["ingressclass.kubernetes.io/is-default-class"] == null)
  '
done
```

Confirm the hwg tunnel is untouched — its connector and proxy must not have
rolled:

```bash
kubectl get pods -n cloudflared-hwg -l app.kubernetes.io/instance=hwg -o wide
kubectl get pods -n traefik-hwg -l nwarila.io/tunnel-proxy=hwg -o wide
```

## Owner-Gated: DNS Routes

Not yet run. Each command claims the wildcard for one tunnel; the more specific
`*.secure` wildcard must exist before or with the broader one, so protected
hostnames never transit the unprotected connector:

```bash
cloudflared tunnel route dns fb6932d9-c6e4-4ccb-8e4c-dee47aa05313 '*.secure.nicholaswarila.com'
cloudflared tunnel route dns fb6932d9-c6e4-4ccb-8e4c-dee47aa05313 canary-nwp-mtls.secure.nicholaswarila.com
cloudflared tunnel route dns 1f59f78a-16f8-4e3c-8567-de0235e39871 '*.nicholaswarila.com'
cloudflared tunnel route dns 1f59f78a-16f8-4e3c-8567-de0235e39871 canary-nwp-public.nicholaswarila.com
```

Record any pre-existing answer for each owner name before changing it; the
tunnel command cannot reconstruct a replaced record:

```bash
dig +noall +answer '*.nicholaswarila.com' A
dig +noall +answer '*.secure.nicholaswarila.com' A
```

Add `--overwrite-dns` only for a name that already exists, and only after its
current answer is recorded in the change evidence.

## Owner-Gated: Client-Certificate Enforcement

Deferred pending a decision, and pending access to inspect how the existing
account already does this. Both candidate mechanisms are edge-side and need no
in-cluster change:

- **Zero Trust Access mTLS** — upload a root CA under Access controls > Service
  credentials > Mutual TLS, list the protected FQDNs as associated hostnames,
  and write an Access policy using the `Valid Certificate` or `Common Name`
  selector. Accepts a self-signed or private CA, so Vault PKI can be the
  issuer, which matches ADR-0013.
- **Zone client certificates** — enable mTLS for the hostname under
  SSL/TLS > Client Certificates and enforce it with a WAF custom rule. Bringing
  your own CA on this path is Enterprise-only, so Cloudflare's managed CA would
  issue the client certificates instead of Vault.

Hostname associations are per-FQDN, not wildcards. Whichever mechanism is
chosen, decide before first use whether the protected tier keeps the hwg
zero-touch property (any subdomain, no platform edit) by automating hostname
association through the Cloudflare API, or accepts per-hostname registration.

## Canary Proof

After the DNS routes exist, both canaries must answer 418 from the built-in
responder with no origin behind them. Use a unique query value so no cached
response is reused:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  "https://canary-nwp-public.nicholaswarila.com/?nwp=$(date +%s)"
curl -sS -o /dev/null -w '%{http_code}\n' \
  "https://canary-nwp-mtls.secure.nicholaswarila.com/?nwp=$(date +%s)"
```

Once client-certificate enforcement is live, the second request must instead
fail without a client certificate and return 418 with one. A protected canary
that still answers 418 to an unauthenticated client means enforcement is not
in effect.

## Publishing An App

In the `deploy-platform-canary` tenant repository, an app needs exactly two
things and no platform edit:

1. `nwarila.io/tunnel-exposed: nwp-public` or `nwarila.io/tunnel-exposed:
   nwp-mtls` on its pod template, serving TCP 8080; and
2. an Ingress using the matching class, a host inside that tunnel's zone, at
   least one HTTP path, and a numeric Service backend port of 8080.

The label and the class must name the same tunnel. Mismatching them yields a
route with no reachable origin rather than a cross-tier leak: admission accepts
the Ingress because the class is registered to the org, but the proxy's egress
policy does not select the pod.

## Rollback

Revert the Git change and reconcile Flux. That prunes both connectors, both
proxies, both classes, their scoped RBAC, both sides of each network-policy
contract, and the per-tunnel entries in the tenant template, while restoring
`restrict-tunnel-binding` and `restrict-tunnel-hostnames` to their hwg-only
form. The hwg tunnel is untouched throughout; assert its empty diff.

Reverting Git does not delete the Cloudflare tunnels or any DNS route. Remove
those explicitly if the rollback is permanent:

```bash
cloudflared tunnel delete nwp-public
cloudflared tunnel delete nwp-mtls
```

Deleting a tunnel does not remove its DNS records; delete those through the
zone's DNS provider or they become dangling CNAMEs to a dead tunnel.
