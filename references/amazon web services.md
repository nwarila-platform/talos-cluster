# IAM Audit: `github_nwarila-platform_talos-cluster`

> **Scope:** GitHub Actions OIDC federation for Terraform S3 state backend  
> **Audit Date:** 2026-04-14  
> **Verdict:** PASS with minor hardening recommendations

---

## Resource Linkage

```
┌─────────────────────────────────────────────────────────────────────┐
│  GitHub Actions Workflow                                            │
│  repo: nwarila-platform/talos-cluster  (ID: 1202118418)            │
│  branch: refs/heads/main                                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ OIDC Token (aud: sts.amazonaws.com)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  IAM OIDC Provider                                                  │
│  arn:aws:iam::793496711039:oidc-provider/                           │
│      token.actions.githubusercontent.com                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ sts:AssumeRoleWithWebIdentity
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  IAM Role                                                           │
│  arn:aws:iam::793496711039:role/github_nwarila-platform_talos-cluster│
│                                                                     │
│  Trust Policy ──► Validates sub, repository_id, aud claims          │
│                                                                     │
│  Attached Policy ─┐                                                 │
│                   ▼                                                 │
│  arn:aws:iam::793496711039:policy/                                  │
│      github_nwarila-platform_talos-cluster                          │
│                                                                     │
│  Grants scoped S3 access to:                                        │
│    s3://793496711039-terraform/nwarila-platform/talos-cluster/       │
└─────────────────────────────────────────────────────────────────────┘
```

The **role** and **policy** share the naming convention `github_nwarila-platform_talos-cluster`, establishing a 1:1 relationship. The policy is attached directly to the role as a customer-managed policy. No other policies or permission boundaries are referenced.

---

## Trust Policy (AssumeRole)

**ARN:** `arn:aws:iam::793496711039:role/github_nwarila-platform_talos-cluster`

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "GitHubActionsAssumeRole",
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::793496711039:oidc-provider/token.actions.githubusercontent.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:sub": "repo:nwarila-platform/talos-cluster:ref:refs/heads/main",
                    "token.actions.githubusercontent.com:repository_id": "1202118418",
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}
```

---

## Permission Policy

**ARN:** `arn:aws:iam::793496711039:policy/github_nwarila-platform_talos-cluster`

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ListRepoFolders",
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::793496711039-terraform",
            "Condition": {
                "StringEquals": {
                    "s3:prefix": [
                        "nwarila-platform/talos-cluster/"
                    ]
                }
            }
        },
        {
            "Sid": "ReadWriteStateFileOnly",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::793496711039-terraform/nwarila-platform/talos-cluster/terraform.tfstate"
        },
        {
            "Sid": "ManageS3LockfileOnly",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::793496711039-terraform/nwarila-platform/talos-cluster/terraform.tfstate.tflock"
        },
        {
            "Sid": "DenyUnencryptedPuts",
            "Effect": "Deny",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::793496711039-terraform/nwarila-platform/talos-cluster/*",
            "Condition": {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": "AES256"
                }
            }
        },
        {
            "Sid": "DenyPutsWithoutEncryptionHeader",
            "Effect": "Deny",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::793496711039-terraform/nwarila-platform/talos-cluster/*",
            "Condition": {
                "Null": {
                    "s3:x-amz-server-side-encryption": "true"
                }
            }
        }
    ]
}
```