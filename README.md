# AWS Secure Landing Zone

"Secure by design" AWS infrastructure with Terraform + hardened EKS, built to demonstrate a complete DevSecOps posture: IaC, cloud security posture management, Kubernetes hardening, and a CI/CD pipeline that blocks merges when a vulnerability is detected.

**Project scope**: this repo ships complete infrastructure code, validated (`terraform validate`, scanned with `tfsec`/`checkov`/`trivy`) and ready to deploy, but **not deployed** - no real AWS resource has been created. See [Status](#status--scope).

## What this demonstrates

- **Segmented VPC**: public subnets (NAT/ALB only) / private subnets (EKS), no direct SSH access from the internet, node access via SSM Session Manager.
- **Least-privilege IAM**: no `service:*` wildcards, `iam:PassRole` scoped to two exact ARNs, OIDC federation from GitHub Actions to AWS (no static keys), MFA-gated break-glass admin role.
- **Encryption everywhere**: 5 dedicated KMS keys (EKS secrets, EBS, S3, Secrets Manager, CloudWatch Logs), Kubernetes secrets encrypted in etcd, native TLS on the EKS API.
- **Hardened EKS**: private API endpoint by default, `restricted` Pod Security Standards, namespace-scoped RBAC, deny-by-default Calico NetworkPolicies, secrets synced from Secrets Manager via the External Secrets Operator (IRSA, never in plaintext).
- **DevSecOps pipeline**: `tfsec` + `checkov` block any Terraform PR, `trivy` scans container images and Kubernetes manifests, `kubeconform` validates schemas.

Full detail on security choices and the architecture diagram: **[docs/architecture.md](docs/architecture.md)**.

Real before/after hardening scan results (tfsec: 23 findings incl. 4 CRITICAL → 0 CRITICAL/HIGH; checkov: 38 failed → 0 failed): **[docs/architecture.md#scan-results-before--after-hardening](docs/architecture.md#scan-results-before--after-hardening)**, raw output in [docs/scan-results/](docs/scan-results/).

A full technical deep dive — module-by-module design rationale, threat model, deployment runbook, and interview prep notes — is available as a standalone PDF, in English and in French: [docs/deep-dive/AWS-Secure-Landing-Zone-Deep-Dive-EN.pdf](docs/deep-dive/AWS-Secure-Landing-Zone-Deep-Dive-EN.pdf) · [docs/deep-dive/AWS-Secure-Landing-Zone-Deep-Dive-FR.pdf](docs/deep-dive/AWS-Secure-Landing-Zone-Deep-Dive-FR.pdf) (source Markdown: [DEEP_DIVE.en.md](docs/deep-dive/DEEP_DIVE.en.md) / [DEEP_DIVE.fr.md](docs/deep-dive/DEEP_DIVE.fr.md)).

## What this infrastructure actually hosts

[`platform/`](platform/) is a real workload built to run on this landing zone: an **Attack Surface Monitor** (FastAPI) that continuously tracks a domain's exposed subdomains, open ports, TLS certificate expiry, and leaked credentials - gated by mandatory DNS TXT domain-ownership verification before any scan can run (unauthorized scanning is a criminal offense under, among others, French Code pénal Art. 323-1; this platform is built so it structurally cannot do that). 45 tests, 0 live network calls in this dev environment (every subprocess/HTTP/DNS call is mocked), a hardened non-root container image (built and Trivy-scanned locally), and Kubernetes manifests that reuse this repo's own `ClusterSecretStore`/Pod Security Standards/NetworkPolicy patterns. See [platform/README.md](platform/README.md) for the full picture, including what's deliberately simplified for this MVP slice and the roadmap it's designed to grow into.

[`compliance/`](compliance/) turns the Terraform/Checkov results the CI pipeline already produces into a per-framework compliance score (ISO 27001, PCI-DSS, NIS2, SOC 2) - real numbers from a real scan (currently **100% across all four frameworks, 194/194 mapped checks passing**, 7 documented exceptions excluded from the score and listed individually rather than folded in), not a self-assessment questionnaire. Regenerated on every CI run: [compliance/reports/compliance-report.md](compliance/reports/compliance-report.md). See [compliance/README.md](compliance/README.md) for methodology and, importantly, what this is *not* (not an audit, not exhaustive per framework, not legal advice).

## Repo structure

```
.
├── terraform/
│   ├── modules/
│   │   ├── vpc/      # public/private subnets, NAT, NACLs, Flow Logs
│   │   ├── iam/       # least-privilege roles, GitHub Actions OIDC, MFA break-glass
│   │   ├── kms/        # 5 dedicated keys, rotation enabled
│   │   └── eks/         # cluster + node group, private endpoint, IMDSv2, encrypted EBS
│   └── environments/
│       └── prod/          # wires the modules together, S3+DynamoDB backend
├── kubernetes/
│   ├── namespaces.yaml           # Pod Security Admission "restricted" labels
│   ├── network-policies/         # deny-by-default + targeted rules + Calico GlobalNetworkPolicy
│   ├── rbac/                      # namespace-scoped Roles/RoleBindings
│   ├── external-secrets/           # ClusterSecretStore + ExternalSecret (AWS Secrets Manager)
│   └── pod-security/                # example Deployment compliant with "restricted"
├── .github/workflows/
│   ├── terraform-security-scan.yml   # fmt, validate, tfsec, checkov (blocking), kubeconform
│   ├── terraform-plan.yml             # plan via OIDC (no static AWS key)
│   └── image-scan-trivy.yml            # build + CVE image scan, K8s config scan
├── examples/insecure-baseline/           # NOT deployable - only used to generate the "before" scan
├── platform/                               # Attack Surface Monitor - the workload this infra hosts (see platform/README.md)
│   ├── app/                                  # FastAPI: routers, services (scan types), models
│   ├── tests/                                 # 45 tests, fully offline/mocked
│   ├── k8s/                                    # Deployment, CronJob, NetworkPolicy, ExternalSecret
│   └── Dockerfile                                # non-root, nmap + subfinder, Trivy-scanned
├── compliance/                             # Checkov findings -> ISO27001/PCI-DSS/NIS2/SOC2 mapping (see compliance/README.md)
│   ├── mapping_norms.yaml                    # 61 real check_ids -> control themes -> framework clauses
│   ├── generate_report.py                     # aggregates a live checkov scan against the mapping
│   └── reports/                                 # generated compliance-report.{md,json}, committed
└── docs/
    ├── architecture.md                     # Mermaid diagram + security choices + scan results
    ├── deep-dive/                            # ultra-detailed EN/FR technical reference (PDF + Markdown)
    └── scan-results/{before,after}/          # raw tfsec/checkov output
```

## Prerequisites

- Terraform >= 1.6
- An AWS account with an S3 bucket (versioning + encryption enabled) and a DynamoDB table for remote state (create once, outside this config - see `terraform/environments/prod/backend.tf`)
- `tfsec`, `checkov`, `trivy` locally if you want to reproduce the scans (see `docs/scan-results/`)

## Getting started

```bash
cd terraform/environments/prod
cp terraform.tfvars.example terraform.tfvars   # then edit with your real values
# edit backend.tf with your real bucket/table name

terraform init
terraform plan
terraform apply
```

Once the cluster is created (private connectivity required - VPN, SSM port-forwarding, or a self-hosted GitHub Actions runner inside the VPC, see docs/architecture.md):

```bash
aws eks update-kubeconfig --name <name_prefix>-eks --region eu-west-3

kubectl apply -f kubernetes/namespaces.yaml
kubectl apply -f kubernetes/rbac/
kubectl apply -f kubernetes/network-policies/

# Install Calico (policy engine) and the External Secrets Operator via Helm
# - see the comments at the top of kubernetes/external-secrets/secret-store.yaml
kubectl apply -f kubernetes/external-secrets/
```

## Status & scope

- [x] Terraform validated (`terraform validate`) across all 4 modules + the `prod` environment
- [x] Kubernetes manifests syntactically validated
- [x] `tfsec`/`checkov` scans actually run (before/after), results committed under `docs/scan-results/`
- [x] GitHub Actions CI verified green on this repo (`Terraform Security Scan`, `Platform CI`), including the SARIF-to-Security-tab upload path - not just written and assumed to work
- [x] `platform/`'s 45 tests and `compliance/`'s 10 tests pass; both container-image scans (landing zone template + platform API) run through Trivy with findings either fixed or documented as an accepted, tracked exception
- [ ] Not deployed to a real AWS account (no billable resource created by this repo as-is)
- [ ] `terraform-plan.yml` (the OIDC-federated plan-on-PR workflow) needs `AWS_DEPLOY_ROLE_ARN` configured as a repo secret post-deployment to actually run - untestable without a deployed AWS account

## License

MIT
