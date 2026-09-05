# Operate The nwarila-platform Tunnel Pair

`nwarila-platform` runs two Cloudflare Tunnels over the same tenant namespace
and the same DNS zone, at two protection tiers:

| Tunnel | Cloudflare tunnel id | Tier | Edge controls |
|---|---|---|---|
| `nwp-public` | `1f59f78a-16f8-4e3c-8567-de0235e39871` | public | none; owns the `*.nickwarila.com` wildcard |
| `nwp-mtls` | `fb6932d9-c6e4-4ccb-8e4c-dee47aa05313` | mTLS | client certificate, Access OTP, WAF block, connector-side Access JWT |

Both watch tenant namespace `nwp-1306985678` and both serve `nickwarila.com`,
so neither namespace scoping nor the hostname can separate them. The
separation is the `nwarila.io/tunnel-exposed` pod label carrying the tunnel
*name*: a Kubernetes label holds one value per key, so a pod is reachable from
exactly one proxy. `scripts/check-tunnel-isolation.py` fails CI if any part of
that contract, or the per-tier connector posture, drifts.

## How A Hostname Becomes Live

**Public tier** works exactly like hwg. A tenant labels its pod
`nwarila.io/tunnel-exposed: nwp-public`, declares an Ingress of class
`cf-tunnel-nwp-public` with any in-zone host, and the wildcard DNS record
delivers traffic the moment the Ingress is admitted. Nothing is registered
anywhere.

**mTLS tier** needs the pod label `nwarila.io/tunnel-exposed: nwp-mtls`, an
Ingress of class `cf-tunnel-nwp-mtls`, *and* per-hostname registration at the
Cloudflare edge, because every primitive that makes a hostname protected is
per-FQDN. `scripts/register-tunnel-hostname.py` converges those in the only
safe order:

1. zone mTLS hostname association — the edge starts demanding a client cert;
2. the multi-domain Access application `nwp-mtls` — OTP, and the aud the
   connector pins;
3. the WAF block entry — `cert_verified` false is rejected at the edge;
4. the explicit DNS CNAME to the mTLS tunnel.

DNS is last. Until it exists the hostname resolves through the wildcard to the
**public** connector, whose proxy cannot select an mTLS-tier pod, so the
hostname answers 404 instead of exposing the origin. Removal runs the same
steps in reverse, DNS first. The connector additionally requires a valid
Access JWT for the `nwp-mtls` application on every request, so a hostname that
reaches the tunnel with an incomplete registration still cannot reach an
origin.

The Access application `nwp-mtls` is the repurposed `tmp.nickwarila.com` app
(`9bea7759-a20e-4496-afb5-efb454eeec50`). Its aud is pinned in
`clusters/talos-cluster/apps/cloudflared-nwp-mtls/configmap.yaml`; do not
create a second application for this tier, and bump the overlay's
`configRevision` whenever that ConfigMap changes.

Client certificates are validated at the account level, so a certificate
issued for `tmp.nickwarila.com` works for every mTLS-tier hostname.
`kasm.nickwarila.com` stays associated but is not managed by this pair.

### Register or remove a protected hostname

```bash
python3 scripts/register-tunnel-hostname.py --tier mtls --dry-run guacd.nickwarila.com
python3 scripts/register-tunnel-hostname.py --tier mtls guacd.nickwarila.com
python3 scripts/register-tunnel-hostname.py --tier mtls --remove guacd.nickwarila.com
```

`--reconcile` converges the edge to exactly the set of hosts declared by live
`cf-tunnel-nwp-mtls` Ingresses plus the canary; it is the loop the scheduled
reconciler runs. The token comes from `CLOUDFLARE_API_TOKEN` or
`~/.cloudflare/api-token` and is never printed. Every write prints the live
before/after for the change evidence.

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

All four Deployments must report two Ready pods. Confirm both classes carry
the stock controller string and no default-class annotation:

```bash
for class in cf-tunnel-nwp-public cf-tunnel-nwp-mtls; do
  kubectl get ingressclass "${class}" -o json | jq -e '
    .spec.controller == "traefik.io/ingress-controller" and
    (.metadata.annotations["ingressclass.kubernetes.io/is-default-class"] == null)
  '
done
```

Confirm hwg did not roll:

```bash
kubectl get pods -n cloudflared-hwg -l app.kubernetes.io/instance=hwg -o wide
kubectl get pods -n traefik-hwg -l nwarila.io/tunnel-proxy=hwg -o wide
```

## Canary Proof

Public: the built-in responder answers with no origin behind it.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  "https://canary-nwp-public.nickwarila.com/?nwp=$(date +%s)"
```

Expected `418`.

mTLS: without a client certificate the edge must refuse before anything
reaches the tunnel. With the certificate, Access then demands the OTP login;
after that the responder answers.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  "https://canary-nwp-mtls.nickwarila.com/?nwp=$(date +%s)"
```

Expected `403` without a certificate (the WAF block). A `418` here means
enforcement is not in effect, and the tier is not protected.

## DNS Layout

Explicit records always beat the wildcard, so pre-existing names on the zone
(`kasm`, `www`, `autoconfig`, `localhost`, the apex) are unaffected by
`*.nickwarila.com`.

| Name | Points at | Managed by |
|---|---|---|
| `*.nickwarila.com` | `nwp-public` tunnel | this runbook (one-time) |
| `canary-nwp-public.nickwarila.com` | `nwp-public` tunnel | this runbook (one-time) |
| `canary-nwp-mtls.nickwarila.com` | `nwp-mtls` tunnel | register script |
| `tmp.nickwarila.com` | `nwp-mtls` tunnel | register script |
| `guacd.nickwarila.com` | `nwp-mtls` tunnel | register script |
| `kasm.nickwarila.com` | legacy `TCNHQ-KASM01` tunnel | untouched |

## Rollback

Revert the Git change and reconcile Flux. That restores the previous connector
route tables and policy zones under the same prune boundaries. Then remove the
edge registrations DNS-first:

```bash
python3 scripts/register-tunnel-hostname.py --tier mtls --remove guacd.nickwarila.com
```

`tmp.nickwarila.com` keeps its association, WAF entry, and Access app whatever
happens; only its CNAME target changes. Reverting Git deletes neither the
Cloudflare tunnels nor any DNS record; delete those explicitly if the rollback
is permanent:

```bash
cloudflared tunnel delete nwp-public
cloudflared tunnel delete nwp-mtls
```
