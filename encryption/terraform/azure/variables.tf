variable "environment" {
  description = "Deployment environment, used in the Key Vault name (e.g. prod). Key Vault names are 3-24 characters."
  type        = string
}

variable "resource_group_name" {
  description = "Existing resource group for the Key Vault."
  type        = string
}

variable "allowed_ip_ranges" {
  description = "Public IP ranges (CIDR) allowed through the Key Vault firewall."
  type        = list(string)
  default     = []
}

variable "allowed_subnet_ids" {
  description = "Subnet IDs allowed through the Key Vault firewall."
  type        = list(string)
  default     = []
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace that receives Key Vault audit events."
  type        = string
}
