output "eks_cluster_role_arn" {
  value = aws_iam_role.eks_cluster.arn
}

output "eks_node_role_arn" {
  value = aws_iam_role.eks_node.arn
}

output "external_secrets_policy_arn" {
  value = aws_iam_policy.external_secrets.arn
}

output "github_actions_deploy_role_arn" {
  value = aws_iam_role.github_actions_deploy.arn
}

output "break_glass_admin_role_arn" {
  value = aws_iam_role.break_glass_admin.arn
}
