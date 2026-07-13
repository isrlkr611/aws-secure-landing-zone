output "vpc_id" {
  value = module.vpc.vpc_id
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "github_actions_deploy_role_arn" {
  description = "Put this in the GitHub Actions workflow's `role-to-assume` input."
  value       = module.iam.github_actions_deploy_role_arn
}

output "external_secrets_irsa_role_arn" {
  description = "Annotate the external-secrets service account with eks.amazonaws.com/role-arn = this value."
  value       = aws_iam_role.external_secrets_irsa.arn
}

output "kms_key_arns" {
  value = module.kms.key_arns
}
