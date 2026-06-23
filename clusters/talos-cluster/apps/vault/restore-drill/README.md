# Vault recovery drill — isolated scratch Vault (Step 152a / 152b)

A **repeatable, kubectl-applied (NOT Flux-reconciled)** harness that stands up an
isolated, single-node scratch Vault in namespace `vault-drill` to rehearse
disaster recovery against the live `deploy-vault` Vault **without any risk to it**.

- **Part 1 (152a, this harness):** stand up an **empty** scratch Vault, prove it
  auto-unseals with the shared KMS CMK, and **prove it cannot reach or join the
  live Vault**. No snapshot, no restore, no live data.
- **Part 2 (152b):** restore a real `deploy-vault` snapshot into this same
  isolated Vault and validate the data — only after Part 1's isolation is audited.

## Why this is safe to run against the production cluster

The scratch Vault lives in its own namespace and is isolated at **three**
independent layers, so it can never discover, reach, or join the live Raft:

1. **Storage layer** — `vault-drill.hcl` has **zero `retry_join`** blocks. With no
   join targets it bootstraps a brand-new single-member Raft of itself.
2. **Network layer (authoritative, CNI-independent DENY)** — a native Kubernetes
   `default-deny` NetworkPolicy (Ingress+Egress) with **no native egress allow**.
   This is the deny floor: with the CNI bypassed the drill egresses **nothing**
   (fail-closed — it cannot reach the public internet, AWS, or any in-cluster
   address). The drill therefore has no L4 route to any in-cluster address on any
   port — including the live Vault pods and ClusterIP. *(Prior to Step 152a-fix
   this layer also carried a `0.0.0.0/0:443`-except-cluster allow; because native
   and Cilium policies are additive, that left :443 open to the whole public
   internet, so it was removed — see `networkpolicies.yaml`.)*
3. **DNS + egress allow layer (the sole egress path)** — a `CiliumNetworkPolicy`
   is the **only** thing that opens egress through the default-deny floor: DNS
   only for the exact AWS endpoint names (`matchName` kms/sts/rolesanywhere.
   us-east-1.amazonaws.com) via the L7 DNS proxy, and TCP/443 only to those same
   FQDNs (`toFQDNs`). Effective egress is therefore **AWS-only**; the drill
   cannot even **resolve** the live Vault's cluster-internal name, and the public
   internet is unreachable on :443.

Identity hygiene: the namespace is **never** labeled `nwarila.io/tenant=true` and
the pod is **never** labeled `vault-client=true`. Either would make the live
`allow-tenant-vault-api-ingress` policy admit the drill as a Vault client. The
drill uses a distinct workload name (`app.kubernetes.io/name: vault-drill`) so it
can never be selected by, or select, the live `vault` workload.

KMS/credentials: the drill auto-unseals with the **same** CMK
(`alias/vault-unseal-talos`) via IAM Roles Anywhere, reusing a runtime copy of
the live `vault-ra-cert`. The backing role `vault-unseal-runtime` is **KMS-only**
(`kms:Encrypt/Decrypt/DescribeKey` on the one CMK; **no `ssm:*`** — the same CMK
also guards the SSM escrow, which the drill must not touch).

The listener uses `tls_disable=1` because the drill is reached **only** via
`kubectl port-forward` (loopback) and namespace ingress is default-deny.

## Files

| File | Purpose |
|------|---------|
| `namespace.yaml` | `vault-drill` ns, PSA `restricted`, **no** tenant label |
| `serviceaccount.yaml` | SA with token automount disabled (drill needs no API access) |
| `vault-drill.hcl` | Vault config: KMS seal, single-node Raft, **no retry_join**, `tls_disable` |
| `services.yaml` | headless `vault-drill-internal` + ClusterIP `vault-drill` (port-forward target) |
| `networkpolicies.yaml` | native default-deny (deny floor) + Cilium AWS DNS/FQDN allow (sole egress: kube-dns + :443 to the 3 AWS endpoints, AWS-only) |
| `statefulset.yaml` | single-replica Vault, signing-helper sidecar+bootstrap, RA-cert mount, `ndots:1` |
| `kustomization.yaml` | self-contained; **never** referenced by any Flux Kustomization |
| `guard.sh` | PRE-APPLY GUARD — refuses to apply unless every isolation invariant holds |
| `drill-run.sh` | end-to-end driver: guard → apply → copy RA cert → init → prove isolation |

> **`ndots:1`** is required: with the default `ndots:5`, the resolver tries the
> cluster search-domains first for the 3-dot AWS names; the strict L7 DNS proxy
> REFUSES those non-AWS names and the Go resolver aborts on REFUSED before
> reaching the absolute name. `ndots:1` sends the AWS lookups straight through
> while the live Vault name (does not match the allow-list) stays REFUSED.

## Run (Part 1)

```bash
export MSYS_NO_PATHCONV=1
export KUBECONFIG=.s3/configs/kubeconfig
cd clusters/talos-cluster/apps/vault/restore-drill
bash drill-run.sh
```

`drill-run.sh` aborts (non-zero) on any isolation failure. The drill Vault's
recovery key + root token are written **only** to a transient file
(`C:/tmp/vault-drill-init.json` by default), never printed and never committed.

## Teardown

```bash
kubectl delete ns vault-drill          # removes Vault, PVC, policies, RA-cert copy
rm -f /c/tmp/vault-drill-init.json      # discard the drill's transient recovery material
```

The drill Vault's recovery material is meaningless after teardown (it unlocks
only the now-deleted barrier). If a run is ever interrupted after init but before
the transient file is written, **wipe the PVC and re-init** rather than trusting
any leaked material.
