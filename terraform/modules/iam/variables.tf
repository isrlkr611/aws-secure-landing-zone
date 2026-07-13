variable "name_prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "github_org" {
  description = "GitHub organization or user that owns the repo allowed to assume the CI/CD deploy role via OIDC."
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name (without org) allowed to assume the CI/CD deploy role via OIDC."
  type        = string
}

variable "github_allowed_branch" {
  description = "Only workflow runs on this branch/ref may assume the deploy role (prevents PR branches from deploying)."
  type        = string
  default     = "main"
}

variable "human_admin_principal_arns" {
  description = "IAM user/role ARNs of human operators allowed to assume the break-glass admin role. MFA is enforced in the trust policy regardless of who is listed here."
  type        = list(string)
  default     = []
}

variable "state_bucket_arn" {
  description = "ARN of the S3 bucket holding Terraform remote state (see backend.tf). The CI/CD deploy role is scoped to exactly this bucket, never s3:* on all buckets."
  type        = string
}

variable "state_lock_table_arn" {
  description = "ARN of the DynamoDB table used for Terraform state locking. The CI/CD deploy role is scoped to exactly this table."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
