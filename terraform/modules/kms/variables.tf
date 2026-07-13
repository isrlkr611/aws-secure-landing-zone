variable "name_prefix" {
  type = string
}

variable "account_id" {
  description = "AWS account ID, used to scope the key policy to this account instead of a wildcard principal."
  type        = string
}

variable "key_admin_role_arns" {
  description = "IAM role ARNs allowed to administer (not just use) the KMS keys. Kept short and explicit - no wildcards."
  type        = list(string)
}

variable "tags" {
  type    = map(string)
  default = {}
}
