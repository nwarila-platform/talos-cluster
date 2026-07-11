# Architecture Diagrams

This explanation records the current architecture from committed manifests and
accepted decision records. When a decision record's earlier convention differs
from the current manifests, the diagrams follow the current manifests.

## GitOps Reconciliation Flow

Source files verified for this diagram:
`clusters/talos-cluster/flux-system/gotk-sync.yaml`,
`clusters/talos-cluster/kustomization.yaml`,
`clusters/talos-cluster/apps/kustomization.yaml`,
`clusters/talos-cluster/tenants/kustomization.yaml`,
`clusters/talos-cluster/apps/vault-kustomization.yaml`,
`clusters/talos-cluster/apps/longhorn/kustomization-flux.yaml`,
`clusters/talos-cluster/apps/kyverno/kustomization-flux.yaml`,
`clusters/talos-cluster/apps/kyverno/kustomization-policies.yaml`,
`clusters/talos-cluster/apps/vault-secrets-operator/kustomization-controller.yaml`,
`clusters/talos-cluster/apps/vault-secrets-operator/kustomization-org-pull.yaml`,
`clusters/talos-cluster/apps/vault-secrets-operator/kustomization-tenant.yaml`,
`clusters/talos-cluster/apps/kustomization-source-rotator.yaml`,
`clusters/talos-cluster/tenants/hwg-1268831311/kustomization.yaml`, and
`clusters/talos-cluster/tenants/_template/zero-touch/base/gitrepository.yaml`,
`clusters/talos-cluster/tenants/_template/zero-touch/base/kustomization-flux.yaml`,
and `clusters/talos-cluster/tenants/_template/zero-touch/base/kustomization.yaml`.

```mermaid
flowchart TD
  Repo["Git repo<br/>nwarila-platform/talos-cluster"]
  FluxGitRepo["GitRepository flux-system<br/>namespace flux-system<br/>url ssh://git@github.com/nwarila-platform/talos-cluster.git"]
  FluxRoot["Kustomization flux-system<br/>path ./clusters/talos-cluster<br/>prune true"]
  SopsAge["Secret sops-age<br/>namespace flux-system"]
  RootIndex["clusters/talos-cluster/kustomization.yaml<br/>resources: flux-system, apps, tenants"]
  AppsIndex["clusters/talos-cluster/apps/kustomization.yaml<br/>platform app index"]
  TenantsIndex["clusters/talos-cluster/tenants/kustomization.yaml<br/>tenant envelope index"]
  VaultK["Kustomization vault<br/>path apps/vault<br/>targetNamespace deploy-vault"]
  LonghornK["Kustomization longhorn<br/>path apps/longhorn/release"]
  KyvernoK["Kustomization kyverno<br/>path apps/kyverno/release"]
  KyvernoPoliciesK["Kustomization kyverno-policies<br/>path apps/kyverno/policies"]
  VSOK["Kustomizations vault-secrets-operator<br/>controller, org-pull, tenant"]
  SourceRotatorK["Kustomization source-rotator<br/>path apps/source-rotator"]
  HwgTenant["tenants/hwg-1268831311<br/>zero-touch tenant envelope"]
  HwgRepo["GitRepository deploy-herowars-engine-porter<br/>namespace hwg-1268831311"]
  HwgK["Kustomization hwg-1268831311<br/>serviceAccount deploy-reconciler"]
  ClusterResources["Applied Kubernetes resources<br/>from the listed manifests"]

  Repo --> FluxGitRepo
  FluxGitRepo --> FluxRoot
  SopsAge -->|"SOPS decrypt at reconcile"| FluxRoot
  FluxRoot --> RootIndex
  RootIndex --> AppsIndex
  RootIndex --> TenantsIndex
  AppsIndex --> VaultK
  AppsIndex --> LonghornK
  AppsIndex --> KyvernoK
  AppsIndex --> VSOK
  AppsIndex --> SourceRotatorK
  KyvernoK --> KyvernoPoliciesK
  TenantsIndex --> HwgTenant
  HwgTenant --> HwgRepo
  HwgTenant --> HwgK
  HwgRepo --> HwgK
  VaultK --> ClusterResources
  LonghornK --> ClusterResources
  KyvernoPoliciesK --> ClusterResources
  VSOK --> ClusterResources
  SourceRotatorK --> ClusterResources
  HwgK --> ClusterResources
```

## Trust Boundaries

Source files verified for this diagram:
`clusters/talos-cluster/tenants/deploy-vault/namespace.yaml`,
`clusters/talos-cluster/apps/vault/base/kustomization.yaml`,
`clusters/talos-cluster/apps/vault/base/allow-tenant-vault-api-ingress.yaml`,
`clusters/talos-cluster/tenants/hwg-1268831311/kustomization.yaml`,
`clusters/talos-cluster/tenants/_template/zero-touch/base/namespace.yaml`,
`clusters/talos-cluster/tenants/_template/zero-touch/base/networkpolicy-default-deny.yaml`,
`clusters/talos-cluster/tenants/_template/zero-touch/base/networkpolicy-allow-vault-egress.yaml`,
`clusters/talos-cluster/tenants/_template/zero-touch/base/vault-client-serviceaccount.yaml`,
`clusters/talos-cluster/tenants/_template/zero-touch/base/deploy-reconciler-rbac.yaml`,
`clusters/talos-cluster/apps/vault/vault-config/auth/kubernetes/roles/tenant.json`,
`clusters/talos-cluster/apps/vault/vault-config/policies/tenant-read.hcl`,
`clusters/talos-cluster/apps/vault/vault-config/policies/tenant-write.hcl`,
`clusters/talos-cluster/apps/kyverno/policies/protect-tenant-label.yaml`,
`clusters/talos-cluster/apps/kyverno/policies/protect-vault-client-serviceaccount.yaml`,
`clusters/talos-cluster/apps/kyverno/policies/restrict-vso-org-pull-secrets.yaml`,
`clusters/talos-cluster/apps/kyverno/policies/protect-source-minter.yaml`,
`clusters/talos-cluster/apps/vault-restore-validator/validatingadmissionpolicy.yaml`,
`clusters/talos-cluster/apps/vault-restore-validator/ciliumnetworkpolicy-egress.yaml`,
`docs/decision-records/repo/0011-auto-discover-deploy-repositories.md`,
`docs/decision-records/repo/0015-use-vault-secrets-operator-for-workload-secrets.md`,
`docs/decision-records/repo/0017-fold-vault-into-talos-cluster-as-a-platform-service.md`,
`docs/decision-records/repo/0020-automate-vault-restore-validation.md`, and
`docs/decision-records/repo/0024-two-layer-enforcement-of-restore-validator-boundary.md`.

The exact tenant Vault policy paths in the current files are
`secret/data/<ns>/provisioned/*` for tenant reads and
`secret/data/<ns>/state/*` for tenant writes, where the policy template derives
`<ns>` from the authenticated service account namespace.

```mermaid
flowchart LR
  subgraph Platform["Platform-owned control namespaces"]
    Flux["flux-system<br/>Flux controllers"]
    DeployVault["deploy-vault<br/>Vault platform service<br/>retained namespace envelope"]
    Kyverno["kyverno<br/>admission policies"]
    VSO["vault-secrets-operator<br/>controller and platform VaultAuths"]
    Longhorn["longhorn-system<br/>Longhorn storage and backups"]
    SourceRotator["source-rotator<br/>source token minter"]
    DRValidate["dr-validate<br/>suspended restore validator"]
    KubeAPI["kube-apiserver<br/>Cilium toEntities target"]
  end

  subgraph Tenant["Tenant namespace hwg-1268831311<br/>nwarila.io/tenant=true<br/>source deploy-herowars-engine-porter"]
    TenantNs["Namespace hwg-1268831311"]
    TenantDefaultDeny["NetworkPolicy default-deny-all"]
    DeployReconciler["ServiceAccount deploy-reconciler<br/>namespace-scoped Role"]
    VaultClient["ServiceAccount vault-client<br/>platform-owned"]
    TenantVSS["VaultStaticSecret pointers<br/>source-auth and ghcr-pull"]
  end

  subgraph VaultBoundary["Vault KV per-tenant isolation"]
    TenantRead["read: secret/data/&lt;ns&gt;/provisioned/*"]
    TenantWrite["write: secret/data/&lt;ns&gt;/state/*"]
    OtherTenant["other tenant KV path"]
  end

  Flux -->|"applies platform and tenant trees"| Kyverno
  Flux -->|"applies Vault workload"| DeployVault
  Flux -->|"applies tenant envelope"| TenantNs
  TenantDefaultDeny -->|"explicit Vault API egress only for vault-client pods"| DeployVault
  DeployReconciler -->|"namespaced workload verbs; no core Secret create"| TenantNs
  VaultClient -->|"Vault role tenant"| TenantRead
  VaultClient -->|"Vault role tenant"| TenantWrite
  VaultClient -. "cannot cross-read" .-> OtherTenant
  VSO -->|"syncs constrained VaultStaticSecret resources"| TenantVSS
  Kyverno -. "denies non-platform tenant label changes" .-> TenantNs
  Kyverno -. "denies non-platform vault-client mutation" .-> VaultClient
  Kyverno -. "constrains VSO pointers and tenant auth objects" .-> TenantVSS
  Kyverno -. "protects source minter identity and workload" .-> SourceRotator
  DRValidate -->|"VAP allows only scratch Longhorn volume create"| Longhorn
  DRValidate -->|"Cilium egress only"| KubeAPI
  KubeAPI -->|"Longhorn Volume CRs"| Longhorn
```

## Secret Flow

Source files verified for this diagram:
`.sops.yaml`, `clusters/talos-cluster/flux-system/gotk-sync.yaml`,
`clusters/talos-cluster/apps/actions-runner-controller/kustomization-scale-set.yaml`,
`clusters/talos-cluster/apps/vault-aws-access/kustomization.yaml`,
`clusters/talos-cluster/apps/vault-tls/kustomization.yaml`,
`clusters/talos-cluster/apps/vault-secrets-operator/tenant/vaultauth-tenant.yaml`,
`clusters/talos-cluster/apps/vault-secrets-operator/org-pull/vaultauth-org-pull-hwg.yaml`,
`clusters/talos-cluster/apps/vault-secrets-operator/org-pull/vaultauth-org-pull-nwp.yaml`,
`clusters/talos-cluster/tenants/_template/zero-touch/base/vaultstaticsecret-gitops-source-auth.yaml`,
`clusters/talos-cluster/tenants/_template/zero-touch/base/vaultstaticsecret-ghcr-pull.yaml`,
`clusters/talos-cluster/tenants/hwg-1268831311/kustomization.yaml`,
`clusters/talos-cluster/apps/source-rotator/cronjob.yaml`,
`clusters/talos-cluster/apps/source-rotator/configmap.yaml`,
`clusters/talos-cluster/apps/source-rotator/serviceaccount.yaml`,
`clusters/talos-cluster/apps/vault/vault-config/auth/kubernetes/roles/tenant.json`,
`clusters/talos-cluster/apps/vault/vault-config/auth/kubernetes/roles/source-minter-hwg.json`,
`clusters/talos-cluster/apps/vault/vault-config/policies/tenant-read.hcl`,
`clusters/talos-cluster/apps/vault/vault-config/policies/tenant-write.hcl`, and
`clusters/talos-cluster/apps/vault/vault-config/policies/source-minter-hwg.hcl`.

```mermaid
flowchart TD
  subgraph SOPSPath["Path A: SOPS-encrypted Secret manifests in git"]
    SopsRules[".sops.yaml<br/>encrypt data and stringData with age"]
    SopsFiles["*.sops.yaml Secret manifests<br/>vault-ra-cert, vault-serving-cert,<br/>ARC keys, talos-reader"]
    FluxDecrypt["Flux kustomize decryption<br/>provider sops"]
    SopsSecret["Secret sops-age<br/>namespace flux-system"]
    SopsK8sSecrets["Kubernetes Secrets<br/>created at reconcile"]
  end

  subgraph VaultPath["Path B: Vault-backed runtime Secrets"]
    Vault["Vault service<br/>namespace deploy-vault"]
    VaultAuthTenant["VaultAuth tenant<br/>namespace vault-secrets-operator<br/>serviceAccount vault-client"]
    TenantRole["Vault Kubernetes role tenant<br/>bound ServiceAccount vault-client<br/>namespaceSelector nwarila.io/tenant=true"]
    TenantPolicies["tenant-read and tenant-write<br/>read secret/data/&lt;ns&gt;/provisioned/*<br/>write secret/data/&lt;ns&gt;/state/*"]
    VSSSource["VaultStaticSecret hwg-1268831311-gitops-source-auth<br/>path hwg-1268831311/provisioned/source-auth"]
    VSSGhcr["VaultStaticSecret ghcr-pull<br/>path platform/org-pull/hwg/ghcr-pull"]
    SourceAuthPath["Vault KV source-auth<br/>secret/data/hwg-1268831311/provisioned/source-auth"]
    TenantStatePath["Vault KV tenant state<br/>secret/data/hwg-1268831311/state/*"]
    GhcrPath["Vault KV org-pull ghcr-pull<br/>secret/data/platform/org-pull/hwg/ghcr-pull"]
    TenantK8sSecrets["Kubernetes Secrets in hwg-1268831311<br/>gitops source-auth and ghcr-pull"]
    HwgGitRepo["GitRepository deploy-herowars-engine-porter<br/>secretRef hwg-1268831311-gitops-source-auth"]
  end

  subgraph Rotation["Source token rotation"]
    RotatorCron["CronJob source-rotator-hwg<br/>ServiceAccount source-rotator-hwg"]
    SourceMinterRole["Vault role source-minter-hwg<br/>policy source-minter-hwg"]
    OrgPullKey["secret/data/platform/org-pull/hwg/gitops-source-auth"]
    GitHubToken["per-repo contents:read GitHub App token"]
  end

  SopsRules --> SopsFiles
  SopsFiles --> FluxDecrypt
  SopsSecret -->|"age private key"| FluxDecrypt
  FluxDecrypt --> SopsK8sSecrets

  VSSSource -->|"vaultAuthRef vault-secrets-operator/tenant"| VaultAuthTenant
  VaultAuthTenant -->|"Kubernetes auth as vault-client"| TenantRole
  TenantRole --> TenantPolicies
  TenantPolicies -->|"read provisioned source-auth"| SourceAuthPath
  TenantPolicies -->|"write tenant state path allowed"| TenantStatePath
  SourceAuthPath -->|"VSO writes destination Secret"| TenantK8sSecrets
  VSSGhcr -->|"vaultAuthRef vault-secrets-operator/org-pull-hwg"| GhcrPath
  GhcrPath -->|"VSO writes destination Secret"| TenantK8sSecrets
  TenantK8sSecrets --> HwgGitRepo

  RotatorCron -->|"Kubernetes auth"| SourceMinterRole
  SourceMinterRole -->|"read App key"| OrgPullKey
  RotatorCron -->|"mint token"| GitHubToken
  GitHubToken -->|"CAS write"| SourceAuthPath
```

## DR Tiers

Source files verified for this diagram:
`cluster/config.env`, `scripts/s3-sync.sh`,
`docs/decision-records/repo/0006-etcd-snapshot-automation.md`,
`docs/decision-records/repo/0014-use-stage-1-local-backup-server-for-dr.md`,
`docs/decision-records/repo/0021-synology-nfs-backup-target-for-longhorn.md`,
`docs/runbooks/dr-stage1-backup.md`,
`docs/runbooks/restore-drill-backup-dr.md`,
`docs/decision-records/repo/0026-in-cluster-etcd-snapshot-pipeline.md`,
`clusters/talos-cluster/apps/dr-etcd-backup/cronjob.yaml`,
`clusters/talos-cluster/apps/dr-etcd-backup/ciliumnetworkpolicy-egress.yaml`,
`clusters/talos-cluster/apps/longhorn-etcd-storage/storageclass.yaml`,
`clusters/talos-cluster/apps/longhorn-etcd-storage/recurringjob.yaml`,
`clusters/talos-cluster/apps/vault/base/vault-statefulset.yaml`,
`clusters/talos-cluster/apps/vault/base/vault.hcl`,
`clusters/talos-cluster/apps/longhorn-vault-storage/storageclass.yaml`,
`clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml`,
`clusters/talos-cluster/apps/longhorn/release/helmrelease.yaml`,
`clusters/talos-cluster/apps/dr-backup/namespace.yaml`,
`clusters/talos-cluster/apps/dr-backup/serviceaccount.yaml`,
`clusters/talos-cluster/apps/dr-backup/ciliumnetworkpolicy-egress.yaml`,
`clusters/talos-cluster/apps/vault/vault-config/auth/kubernetes/roles/vault-snapshot-backup.json`,
`clusters/talos-cluster/apps/vault/vault-config/policies/vault-snapshot-backup.hcl`,
`clusters/talos-cluster/apps/vault-restore-validator/README.md`,
`clusters/talos-cluster/apps/vault-restore-validator/cronjob.yaml`,
`clusters/talos-cluster/apps/vault-restore-validator/validatingadmissionpolicy.yaml`,
`clusters/talos-cluster/apps/vault-restore-validator/ciliumnetworkpolicy-egress.yaml`, and
`clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml`.

Solid arrows are live today. Dashed arrows are accepted or present as
implementation material, but not live scheduled DR.

```mermaid
flowchart TD
  subgraph Legend["Legend"]
    LiveLegend["LIVE: solid node and edge"]
    NotLiveLegend["NOT LIVE: dashed edge and dashed node border"]
    LiveLegend -. "not live edge style" .-> NotLiveLegend
  end

  subgraph Live["LIVE today"]
    Stage0Local["Stage 0 local .s3 mirror<br/>secrets.yaml, age.agekey,<br/>talosconfig, kubeconfig, generated configs"]
    S3Sync["scripts/s3-sync.sh<br/>aws s3 sync --sse aws:kms"]
    S3Bucket["S3 793496711039-terraform<br/>prefix nwarila-platform/talos-cluster<br/>rebuild-critical material only"]
    VaultPVC["Vault StatefulSet data PVCs<br/>storageClassName longhorn-vault<br/>Raft storage at /vault/data"]
    LonghornVault["StorageClass longhorn-vault<br/>3 replicas, nodeSelector vault"]
    VaultDailyBackup["Longhorn RecurringJob vault-daily-backup<br/>backup cron 17 8 daily, retain 14"]
    Synology["TCNHQ-BKUP01 Synology NFS<br/>10.69.128.115:/volume1/longhorn-backup<br/>Btrfs RAID6 with immutable snapshots"]
    CurrentVaultDR["Current Vault DR artifact<br/>Longhorn volume backups<br/>no retained Raft snapshots today"]
    EtcdCronJob["CronJob etcd-snapshot in dr-etcd-backup<br/>talosctl os:etcd:backup role, 03:00 daily<br/>whole-file age encryption, escrowed key"]
    EtcdPVC["PVC etcd-snapshots<br/>storageClassName longhorn-etcd-snapshot<br/>14 encrypted local dailies"]
    EtcdDailyBackup["Longhorn RecurringJob etcd-daily-backup<br/>backup cron 47 3 daily, retain 14<br/>detached-volume backup enabled"]
  end

  subgraph NotLive["Accepted or present, but NOT LIVE"]
    VaultSnapshotRole["vault-snapshot-backup role and policy<br/>read sys/storage/raft/snapshot"]
    VaultRaftSnapshots["Vault Raft snapshots<br/>none retained today"]
    RestoreValidator["CronJob dr-restore-driver<br/>suspend true<br/>schedule 0 6 31 2 *"]
    ValidatorGuard["VAP plus Kyverno Audit guard<br/>scratch volume only; boundary protected"]
    FutureValidator["Deferred validator slices<br/>scratch Vault, generate-root,<br/>signed results, live schedule"]
  end

  Stage0Local --> S3Sync
  S3Sync --> S3Bucket
  VaultPVC --> LonghornVault
  LonghornVault --> VaultDailyBackup
  VaultDailyBackup --> Synology
  Synology --> CurrentVaultDR

  EtcdCronJob --> EtcdPVC
  EtcdPVC --> EtcdDailyBackup
  EtcdDailyBackup --> Synology
  VaultSnapshotRole -. "foundation only; no scheduled capture" .-> VaultRaftSnapshots
  VaultRaftSnapshots -. "not current Vault DR source" .-> CurrentVaultDR
  RestoreValidator -. "inert and owner-supervised only" .-> ValidatorGuard
  ValidatorGuard -. "go-live requires later slices" .-> FutureValidator

  classDef live fill:#eaf5ea,stroke:#2e7d32,stroke-width:2px;
  classDef notlive fill:#fff8e1,stroke:#8a6d00,stroke-width:2px,stroke-dasharray: 5 5;
  class Stage0Local,S3Sync,S3Bucket,VaultPVC,LonghornVault,VaultDailyBackup,Synology,CurrentVaultDR,EtcdCronJob,EtcdPVC,EtcdDailyBackup,LiveLegend live;
  class VaultSnapshotRole,VaultRaftSnapshots,RestoreValidator,ValidatorGuard,FutureValidator,NotLiveLegend notlive;
```
