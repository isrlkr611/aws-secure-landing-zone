locals {
  common_tags = {
    Project     = "secure-landing-zone"
    Environment = "prod"
    ManagedBy   = "terraform"
  }
}

module "kms" {
  source = "../../modules/kms"

  name_prefix = var.name_prefix
  account_id  = var.account_id
  key_admin_role_arns = concat(
    [module.iam.break_glass_admin_role_arn],
    var.human_admin_principal_arns
  )
  tags = local.common_tags
}

module "vpc" {
  source = "../../modules/vpc"

  name_prefix           = var.name_prefix
  vpc_cidr              = var.vpc_cidr
  azs                   = var.azs
  public_subnet_cidrs   = var.public_subnet_cidrs
  private_subnet_cidrs  = var.private_subnet_cidrs
  flow_logs_kms_key_arn = module.kms.key_arns["cloudwatch_logs"]
  tags                  = local.common_tags
}

module "iam" {
  source = "../../modules/iam"

  name_prefix                = var.name_prefix
  account_id                 = var.account_id
  github_org                 = var.github_org
  github_repo                = var.github_repo
  human_admin_principal_arns = var.human_admin_principal_arns
  state_bucket_arn           = var.state_bucket_arn
  state_lock_table_arn       = var.state_lock_table_arn
  tags                       = local.common_tags
}

module "eks" {
  source = "../../modules/eks"

  name_prefix                          = var.name_prefix
  vpc_id                               = module.vpc.vpc_id
  private_subnet_ids                   = module.vpc.private_subnet_ids
  cluster_role_arn                     = module.iam.eks_cluster_role_arn
  node_role_arn                        = module.iam.eks_node_role_arn
  eks_secrets_kms_key_arn              = module.kms.key_arns["eks_secrets"]
  ebs_kms_key_arn                      = module.kms.key_arns["ebs"]
  cloudwatch_logs_kms_key_arn          = module.kms.key_arns["cloudwatch_logs"]
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs
  tags                                 = local.common_tags
}

# ---------------------------------------------------------------------------
# IRSA role for the External Secrets Operator. Lives at root level because it
# needs both the EKS module's OIDC provider and the IAM module's permission
# policy - creating it inside either module would introduce a cycle.
# Trust is scoped to the exact namespace/service-account pair the operator
# runs as, not to the whole cluster.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "external_secrets_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider_url, "https://", "")}:sub"
      values   = ["system:serviceaccount:external-secrets:external-secrets"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider_url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "external_secrets_irsa" {
  name               = "${var.name_prefix}-external-secrets-irsa"
  assume_role_policy = data.aws_iam_policy_document.external_secrets_trust.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "external_secrets_irsa" {
  role       = aws_iam_role.external_secrets_irsa.name
  policy_arn = module.iam.external_secrets_policy_arn
}
