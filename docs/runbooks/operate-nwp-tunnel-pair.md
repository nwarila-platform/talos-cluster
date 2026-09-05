# Operate The nwarila-platform Tunnel Pair

`nwarila-platform` runs two Cloudflare Tunnels over the same tenant namespace
and the same DNS zone, at two protection tiers:

| Tunnel | Cloudflare tunnel ID | Tier | Required or intended edge posture |
|---|---|---|---|
| `nwp-public` | `1f59f78a-16f8-4e3c-8567-de0235e39871` | public | no per-host security controls; owner-gated wildcard and public-canary DNS routes |
| `nwp-mtls` | `fb6932d9-c6e4-4ccb-8e4c-dee47aa05313` | mTLS | client certificate, Access OTP, WAF block, and configured connector-side Access JWT |

Both stacks are configured to watch tenant namespace `nwp-1306985678` and
serve `nickwarila.com`, so neither namespace nor hostname alone separates them. The
`nwarila.io/tunnel-exposed` pod label carries the tunnel name; because a
Kubernetes label has one value per key, a pod is reachable from exactly one
proxy. Admission, exact network-policy rules, connector routes, and the fixed
class-to-tier map are checked by `scripts/check-tunnel-isolation.py`.

## How A Hostname Becomes Live

After the owner-gated wildcard route is provisioned, the public tier is
zero-touch per hostname. A tenant labels its pod
`nwarila.io/tunnel-exposed: nwp-public` and declares an Ingress of class
`cf-tunnel-nwp-public` with an admitted in-zone hostname. The wildcard then
routes the hostname to that connector.

The mTLS tier needs the matching `nwp-mtls` label and Ingress class plus four
per-hostname Cloudflare controls. `scripts/register-tunnel-hostname.py`
converges them in this order:

1. add the zone mTLS hostname association;
2. add the hostname to the existing multi-domain Access application;
3. add the hostname to the WAF client-certificate block rule;
4. create the explicit CNAME to the mTLS tunnel.

DNS is last. Once the public wildcard has been provisioned, it receives the
request until the explicit CNAME exists, but the public proxy does not watch an
mTLS-class Ingress and cannot select an mTLS-labelled pod. The request
therefore cannot reach the protected origin.
Removal reverses the safety boundary: the script deletes every stale mTLS CNAME
first, then narrows the association, Access domains, and WAF rule in that
order. Its offline fake-client selftest asserts the exact write order for add,
remove, and reconcile-with-drop paths; that is not evidence of live edge state.

The mTLS connector is configured to require a valid Access JWT for the intended
`nwp-mtls` Access application (`9bea7759-a20e-4496-afb5-efb454eeec50`) on every
request. Its aud is pinned in
`clusters/talos-cluster/apps/cloudflared-nwp-mtls/configmap.yaml`. The
registration script updates only the application's multi-domain fields and
fails closed unless the live application is self-hosted and has an allow
policy containing a nonempty email-domain or OTP include rule.

This offline change does not prove that the pinned aud belongs to that live
application or that its live OTP, certificate, and WAF controls are active.

### Register, remove, or reconcile protected hostnames

These are owner-gated edge operations. Use the registration script with
`--tier mtls` and one or more hostnames; add `--dry-run` to inspect the plan or
`--remove` to deregister them. Use `--reconcile`, optionally with `--dry-run`,
to derive the full desired set from the cluster. Consult the script's `--help`
output before an approved run. No registration, removal, or reconciliation
command was executed against the edge in this offline change window.

`--reconcile` derives the desired set only from Ingresses in namespaces labelled
`nwarila.io/tenant=true`, using class `cf-tunnel-nwp-mtls`, then pins the mTLS
canary. Malformed hostnames are reported and skipped so one bad Ingress does
not hide valid desired hosts. A reserved hostname makes the reconciliation
fail before any write.

A direct registration keeps `tmp.nickwarila.com` registered until explicit
removal or a later reconciliation omits it. Only a live eligible Ingress
preserves it across reconciliations. No scheduler is added in this change;
`--reconcile` is operator-invoked until the follow-up reconciler exists.

The script refuses the zone apex and the reserved names `kasm`, `www`,
`autoconfig`, and `localhost` on every input path. If `kasm.nickwarila.com` is
already present in the mTLS association it is preserved, but the script never
adds it. An existing DNS record is updated only when it is a CNAME already
pointing to one of the two NWP tunnel targets.

The token comes from `CLOUDFLARE_API_TOKEN` or
`~/.cloudflare/api-token` and is never printed. Every planned or applied change
prints its before and after state.

## Reconcile And Prove The Rollout

After an approved Git deployment, reconcile Flux and wait for the two NWP
connector Deployments whose `configRevision` changed. Separately confirm both
Traefik Deployments remain Ready, both IngressClasses retain the stock
controller without a default-class annotation, and the hwg connector and proxy
pod identities did not change. Exact commands and captured results belong in
the deployment change evidence; this offline window did not deploy anything.

## Owner-Gated One-Time Public DNS

The public wildcard and public canary require these one-time routes. They were
not executed in this offline change window:

```bash
cloudflared tunnel route dns 1f59f78a-16f8-4e3c-8567-de0235e39871 '*.nickwarila.com'
cloudflared tunnel route dns 1f59f78a-16f8-4e3c-8567-de0235e39871 canary-nwp-public.nickwarila.com
```

Do not add `--overwrite-dns`. The work order records that neither name exists;
the operator must still recheck immediately before an approved execution.

## Canary Proof

After the owner-gated public DNS commands run, probe the public canary with a
unique query value. The built-in responder should answer `418` without an
origin behind it.

The registration script is designed to manage
`canary-nwp-mtls.nickwarila.com`. Without a client certificate, the intended
WAF result is `403`; with a certificate and successful Access authentication,
the intended connector response is `418`. Both expectations are **UNPROVEN**
until an approved live run reaches and verifies the WAF and connector steps.
Do not interpret any current response as proof of mTLS posture from this
offline change alone.

## DNS Layout

| Name | Points at | Managed by |
|---|---|---|
| `*.nickwarila.com` | intended `nwp-public` tunnel target | owner-gated one-time command above |
| `canary-nwp-public.nickwarila.com` | intended `nwp-public` tunnel target | owner-gated one-time command above |
| `canary-nwp-mtls.nickwarila.com` | intended `nwp-mtls` tunnel target | register script |
| `tmp.nickwarila.com` | intended `nwp-mtls` target while desired | register script |
| `guacd.nickwarila.com` | intended `nwp-mtls` target while desired | register script |
| `kasm.nickwarila.com` | external to this automation | reserved; existing association preserved |

## Rollback

Revert this Git change and reconcile Flux to restore the previous connector
route tables and admission zones. Before permanently removing an mTLS hostname,
run the registration script's dry-run and approved removal; it deletes the
explicit DNS record before dropping its three edge controls. Reverting Git does
not delete Cloudflare tunnels or DNS records.

Do not remove `tmp.nickwarila.com` unless it is absent from the desired mTLS
Ingress set and its registration is intentionally retired. Do not pass any
reserved hostname to the script.
