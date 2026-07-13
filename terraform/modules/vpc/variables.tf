variable "name_prefix" {
  description = "Prefix applied to all resource names/tags created by this module."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "azs" {
  description = "Availability zones to spread subnets across (minimum 2 for HA)."
  type        = list(string)

  validation {
    condition     = length(var.azs) >= 2
    error_message = "At least 2 availability zones are required for a highly available NAT/EKS setup."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ). Only load balancers / NAT gateways live here."
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (one per AZ). EKS nodes and workloads live here, no public IPs."
  type        = list(string)
}

variable "single_nat_gateway" {
  description = "If true, deploy a single NAT Gateway (cheaper, less resilient) instead of one per AZ. Default false for production-grade HA."
  type        = bool
  default     = false
}

variable "flow_logs_retention_days" {
  description = "Retention period for VPC Flow Logs in CloudWatch Logs. Needed for network forensics/audit. Defaults to 400 days (> 1 year) to satisfy common compliance baselines (e.g. CKV_AWS_338)."
  type        = number
  default     = 400
}

variable "flow_logs_kms_key_arn" {
  description = "KMS key ARN used to encrypt VPC Flow Logs at rest in CloudWatch Logs."
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources."
  type        = map(string)
  default     = {}
}
