# AWS Secure Landing Zone

Infrastructure AWS "secure by design" avec Terraform + EKS durci, pensée pour démontrer une posture DevSecOps complète : IaC, cloud security posture management, Kubernetes hardening, et pipeline CI/CD qui bloque la fusion en cas de faille détectée.

**Portée du projet** : ce repo livre du code d'infrastructure complet, validé (`terraform validate`, scanné `tfsec`/`checkov`/`trivy`) et prêt à déployer, mais **non déployé** - aucune ressource AWS réelle n'a été créée. Voir [Statut](#statut--porté).

## Ce que ça démontre

- **VPC segmenté** : subnets publics (NAT/ALB uniquement) / privés (EKS), aucun accès SSH direct depuis internet, accès aux nœuds via SSM Session Manager.
- **IAM en moindre privilège** : pas de wildcard `service:*`, `iam:PassRole` scopé à deux ARN précis, fédération OIDC GitHub Actions → AWS (pas de clé statique), rôle break-glass admin gated par MFA.
- **Chiffrement systématique** : 5 clés KMS dédiées (secrets EKS, EBS, S3, Secrets Manager, CloudWatch Logs), secrets Kubernetes chiffrés dans etcd, TLS natif sur l'API EKS.
- **EKS durci** : endpoint API privé par défaut, Pod Security Standards `restricted`, RBAC namespace-scopé, NetworkPolicies Calico en deny-by-default, secrets synchronisés depuis Secrets Manager via External Secrets Operator (IRSA, jamais en clair).
- **Pipeline DevSecOps** : `tfsec` + `checkov` bloquants sur toute PR Terraform, `trivy` pour les images de conteneurs et les manifests Kubernetes, `kubeconform` pour la validation de schéma.

Détail complet des choix de sécurité et schéma d'architecture : **[docs/architecture.md](docs/architecture.md)**.

Résultats réels des scans avant/après durcissement (tfsec 23 findings dont 4 CRITICAL → 0 CRITICAL/HIGH ; checkov 38 failed → 0 failed) : **[docs/architecture.md#résultats-des-scans-avantaprès-durcissement](docs/architecture.md#résultats-des-scans-avantaprès-durcissement)**, détail brut dans [docs/scan-results/](docs/scan-results/).

## Structure du repo

```
.
├── terraform/
│   ├── modules/
│   │   ├── vpc/      # subnets pub/priv, NAT, NACL, Flow Logs
│   │   ├── iam/       # rôles least-privilege, OIDC GitHub Actions, break-glass MFA
│   │   ├── kms/        # 5 clés dédiées, rotation activée
│   │   └── eks/         # cluster + node group, endpoint privé, IMDSv2, EBS chiffré
│   └── environments/
│       └── prod/          # assemble les modules, backend S3+DynamoDB
├── kubernetes/
│   ├── namespaces.yaml           # labels Pod Security Admission "restricted"
│   ├── network-policies/         # deny-by-default + règles ciblées + Calico GlobalNetworkPolicy
│   ├── rbac/                      # Roles/RoleBindings namespace-scopés
│   ├── external-secrets/           # ClusterSecretStore + ExternalSecret (AWS Secrets Manager)
│   └── pod-security/                # exemple de Deployment conforme "restricted"
├── .github/workflows/
│   ├── terraform-security-scan.yml   # fmt, validate, tfsec, checkov (bloquants), kubeconform
│   ├── terraform-plan.yml             # plan via OIDC (pas de clé AWS statique)
│   └── image-scan-trivy.yml            # build + scan CVE image, scan config K8s
├── examples/insecure-baseline/           # NON déployable - sert uniquement à générer le scan "avant"
└── docs/
    ├── architecture.md                     # schéma Mermaid + choix de sécurité + résultats scans
    └── scan-results/{before,after}/          # sorties brutes tfsec/checkov
```

## Prérequis

- Terraform >= 1.6
- Un compte AWS avec un bucket S3 (versioning + chiffrement activés) et une table DynamoDB pour le state distant (à créer une fois, hors de cette config - voir `terraform/environments/prod/backend.tf`)
- `tfsec`, `checkov`, `trivy` en local si vous voulez reproduire les scans (voir `docs/scan-results/`)

## Démarrage

```bash
cd terraform/environments/prod
cp terraform.tfvars.example terraform.tfvars   # puis éditer avec vos valeurs réelles
# éditer backend.tf avec le nom réel du bucket/table

terraform init
terraform plan
terraform apply
```

Une fois le cluster créé (connectivité privée requise - VPN, SSM port-forwarding, ou runner GitHub Actions auto-hébergé dans le VPC, voir docs/architecture.md) :

```bash
aws eks update-kubeconfig --name <name_prefix>-eks --region eu-west-3

kubectl apply -f kubernetes/namespaces.yaml
kubectl apply -f kubernetes/rbac/
kubectl apply -f kubernetes/network-policies/

# Installer Calico (policy engine) et External Secrets Operator via Helm
# - voir les commentaires en tête de kubernetes/external-secrets/secret-store.yaml
kubectl apply -f kubernetes/external-secrets/
```

## Statut & portée

- [x] Terraform validé (`terraform validate`) sur les 4 modules + l'environnement `prod`
- [x] Manifests Kubernetes validés syntaxiquement
- [x] Scans `tfsec`/`checkov` exécutés réellement (avant/après), résultats commités dans `docs/scan-results/`
- [ ] Non déployé sur un compte AWS réel (aucune ressource facturable créée par ce repo tel quel)
- [ ] CI GitHub Actions non encore exécutée en conditions réelles (nécessite les secrets/OIDC configurés sur le repo GitHub une fois poussé)

## Licence

MIT
