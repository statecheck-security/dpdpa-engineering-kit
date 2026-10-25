# azure_keyvault_dpdpa.tf
# Azure Key Vault for DPDPA personal data encryption

resource "azurerm_key_vault" "dpdpa" {
  name                = "dpdpa-${var.environment}-kv"
  location            = "centralindia" # Pune region
  resource_group_name = var.resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium" # HSM-backed keys

  # Purge protection: prevent accidental key deletion
  purge_protection_enabled   = true
  soft_delete_retention_days = 90

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
  }
}

resource "azurerm_key_vault_key" "dpdpa_personal_data" {
  name         = "dpdpa-personal-data-key"
  key_vault_id = azurerm_key_vault.dpdpa.id
  key_type     = "RSA-HSM" # HSM-protected
  key_size     = 4096

  key_opts = ["encrypt", "decrypt", "wrapKey", "unwrapKey"]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P365D" # Annual rotation
    notify_before_expiry = "P30D"
  }

  tags = {
    compliance = "dpdpa-rule-6-1-a"
    data_class = "personal_data"
  }
}

# Diagnostic settings for audit logging — Rule 6(1)(c)
resource "azurerm_monitor_diagnostic_setting" "kv_audit" {
  name                       = "dpdpa-kv-audit"
  target_resource_id         = azurerm_key_vault.dpdpa.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "AuditEvent"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}
