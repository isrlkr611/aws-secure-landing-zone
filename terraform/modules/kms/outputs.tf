output "key_arns" {
  description = "Map of key name (eks_secrets, ebs, s3, secrets_manager, cloudwatch_logs) to KMS key ARN."
  value       = { for k, v in aws_kms_key.this : k => v.arn }
}

output "key_ids" {
  value = { for k, v in aws_kms_key.this : k => v.key_id }
}
