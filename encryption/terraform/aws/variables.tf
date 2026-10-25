variable "environment" {
  description = "Deployment environment, used in the key alias and log group name (e.g. prod, staging)."
  type        = string
}

variable "application_role_arns" {
  description = "IAM role ARNs of the applications allowed to encrypt and decrypt personal data."
  type        = list(string)
}

variable "kms_admin_role_arn" {
  description = "The only IAM role allowed to schedule deletion of, or disable, the key."
  type        = string
}
