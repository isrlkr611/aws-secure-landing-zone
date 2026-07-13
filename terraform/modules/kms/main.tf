# ---------------------------------------------------------------------------
# One KMS key per data domain (EKS secrets, EBS, S3, Secrets Manager, logs)
# rather than a single shared key. This limits blast radius if one key's
# policy is ever loosened by mistake, and lets us set independent rotation
# and deletion-protection settings per use case.
# ---------------------------------------------------------------------------

locals {
  key_specs = {
    eks_secrets     = "EKS Kubernetes secrets envelope encryption"
    ebs             = "EBS volumes for EKS worker nodes"
    s3              = "S3 buckets (app data, Terraform state, logs)"
    secrets_manager = "Secrets Manager secrets consumed by workloads"
    cloudwatch_logs = "CloudWatch Logs (VPC Flow Logs, EKS control plane logs)"
  }

  base_key_policy_statements = [
    {
      Sid    = "EnableRootAccountAdmin"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.account_id}:root"
      }
      Action   = "kms:*"
      Resource = "*"
    },
    {
      Sid    = "AllowKeyAdministration"
      Effect = "Allow"
      Principal = {
        AWS = var.key_admin_role_arns
      }
      Action = [
        "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
        "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
        "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
      ]
      Resource = "*"
    },
  ]
}

resource "aws_kms_key" "this" {
  for_each = local.key_specs

  description             = each.value
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.base_key_policy_statements
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

resource "aws_kms_alias" "this" {
  for_each      = local.key_specs
  name          = "alias/${var.name_prefix}-${replace(each.key, "_", "-")}"
  target_key_id = aws_kms_key.this[each.key].key_id
}
