variable "project_id" {
  description = "GCP project that holds the key ring."
  type        = string
}

variable "environment" {
  description = "Deployment environment, used in the key ring name (e.g. prod)."
  type        = string
}

variable "app_service_account_email" {
  description = "The only service account allowed to encrypt and decrypt with the key."
  type        = string
}
