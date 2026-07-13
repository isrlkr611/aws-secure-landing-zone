variable "aws_region" {
  type    = string
  default = "eu-west-3"
}

variable "account_id" {
  description = "AWS account ID this landing zone is deployed into."
  type        = string
}

variable "name_prefix" {
  type    = string
  default = "slz-prod"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "azs" {
  type    = list(string)
  default = ["eu-west-3a", "eu-west-3b", "eu-west-3c"]
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.16.0/20", "10.0.32.0/20", "10.0.48.0/20"]
}

variable "github_org" {
  description = "GitHub org/user hosting this repository, used to scope the OIDC deploy role trust policy."
  type        = string
}

variable "github_repo" {
  description = "Repository name, used to scope the OIDC deploy role trust policy."
  type        = string
  default     = "aws-secure-landing-zone"
}

variable "human_admin_principal_arns" {
  description = "IAM principals allowed to assume the break-glass admin role (still gated by MFA in the trust policy)."
  type        = list(string)
  default     = []
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "CIDR blocks allowed to reach the public EKS API endpoint. Only used if you override cluster_endpoint_public_access to true. Must not contain 0.0.0.0/0."
  type        = list(string)
  default     = []
}

variable "state_bucket_arn" {
  description = "ARN of the S3 bucket holding this environment's Terraform state (see backend.tf) - used to scope the CI/CD deploy role."
  type        = string
}

variable "state_lock_table_arn" {
  description = "ARN of the DynamoDB table used for state locking - used to scope the CI/CD deploy role."
  type        = string
}
