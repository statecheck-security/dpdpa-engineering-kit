# Plans the module against a mocked AzureRM provider (no credentials needed) and checks its safeguards.
mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id = "00000000-0000-0000-0000-000000000000"
    }
  }
}

variables {
  environment                = "test"
  resource_group_name        = "rg-dpdpa-test"
  log_analytics_workspace_id = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law"
}

run "vault_is_in_india_and_locked_down" {
  command = plan

  assert {
    condition     = azurerm_key_vault.dpdpa.location == "centralindia"
    error_message = "Key Vault must stay in an Indian region."
  }

  assert {
    condition     = azurerm_key_vault.dpdpa.purge_protection_enabled
    error_message = "Purge protection must be on."
  }

  assert {
    condition     = azurerm_key_vault.dpdpa.sku_name == "premium"
    error_message = "Premium SKU is needed for HSM-backed keys."
  }

  assert {
    condition     = azurerm_key_vault.dpdpa.network_acls[0].default_action == "Deny"
    error_message = "The vault firewall must deny by default."
  }
}

run "key_is_hsm_backed_and_rotates" {
  command = plan

  assert {
    condition     = azurerm_key_vault_key.dpdpa_personal_data.key_type == "RSA-HSM"
    error_message = "Use an HSM-protected key."
  }

  assert {
    condition     = azurerm_key_vault_key.dpdpa_personal_data.rotation_policy[0].expire_after == "P365D"
    error_message = "Keys must rotate at least annually."
  }

  assert {
    condition     = one(azurerm_monitor_diagnostic_setting.kv_audit.enabled_log).category == "AuditEvent"
    error_message = "Key Vault audit events must be sent to Log Analytics."
  }
}
