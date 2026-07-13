variable "name_prefix" {
  type = string
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS control plane."
  type        = string
  default     = "1.30"
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  description = "Worker nodes and the EKS control plane ENIs are placed only in private subnets."
  type        = list(string)
}

variable "cluster_role_arn" {
  type = string
}

variable "node_role_arn" {
  type = string
}

variable "eks_secrets_kms_key_arn" {
  type = string
}

variable "ebs_kms_key_arn" {
  type = string
}

variable "cloudwatch_logs_kms_key_arn" {
  type = string
}

variable "log_retention_days" {
  description = "Retention for EKS control plane logs (api/audit/authenticator/controllerManager/scheduler). Defaults to 400 days (> 1 year) to satisfy common compliance baselines (e.g. CKV_AWS_338)."
  type        = number
  default     = 400
}

variable "node_instance_types" {
  type    = list(string)
  default = ["m6i.large"]
}

variable "node_desired_size" {
  type    = number
  default = 3
}

variable "node_min_size" {
  type    = number
  default = 2
}

variable "node_max_size" {
  type    = number
  default = 6
}

variable "cluster_endpoint_public_access" {
  description = "Whether the EKS API server endpoint is reachable from the public internet at all. Defaults to false: this landing zone assumes kubectl/helm-level operations (installing Calico, External Secrets Operator, applying manifests) run from inside the VPC (self-hosted GitHub Actions runner, VPN, or SSM port-forwarding), not from public internet. Terraform itself (plan/apply on the aws_eks_cluster resource) does not need this - it talks to the regular eks.<region>.amazonaws.com control-plane API, not the cluster's own API server. Only flip to true, with cluster_endpoint_public_access_cidrs locked to known IPs, if you have no private connectivity option."
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "CIDR blocks allowed to reach the public EKS API endpoint, only used when cluster_endpoint_public_access = true (e.g. office/VPN egress IPs). Must never contain 0.0.0.0/0."
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.cluster_endpoint_public_access_cidrs, "0.0.0.0/0")
    error_message = "cluster_endpoint_public_access_cidrs must not include 0.0.0.0/0 - restrict to known operator/CI ranges or leave cluster_endpoint_public_access = false and use VPN/SSM/private connectivity instead."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
