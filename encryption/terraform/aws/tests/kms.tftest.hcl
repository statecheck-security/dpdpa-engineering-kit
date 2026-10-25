# Plans the module against a mocked AWS provider (no credentials needed) and checks its safeguards.
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
}

variables {
  environment           = "test"
  application_role_arns = ["arn:aws:iam::123456789012:role/orders-api"]
  kms_admin_role_arn    = "arn:aws:iam::123456789012:role/kms-admin"
}

run "key_has_rotation_and_audit_retention" {
  command = plan

  assert {
    condition     = aws_kms_key.dpdpa_personal_data.enable_key_rotation
    error_message = "Automatic key rotation must be on."
  }

  assert {
    condition     = aws_kms_key.dpdpa_personal_data.deletion_window_in_days == 30
    error_message = "Keep the 30-day deletion window."
  }

  assert {
    condition     = aws_cloudwatch_log_group.kms_audit.retention_in_days >= 365
    error_message = "KMS audit logs must be kept for at least one year (Rule 6(1)(e))."
  }

  assert {
    condition     = aws_kms_alias.dpdpa_personal_data.name == "alias/dpdpa-personal-data-test"
    error_message = "Alias must include the environment."
  }
}

run "key_policy_statements" {
  command = plan

  assert {
    condition = anytrue([
      for s in jsondecode(aws_kms_key.dpdpa_personal_data.policy).Statement :
      s.Sid == "ApplicationEncryptDecrypt" && s.Condition.StringEquals["kms:EncryptionContext:purpose"] == "dpdpa_field_encryption"
    ])
    error_message = "Application crypto calls must require the dpdpa_field_encryption context."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_kms_key.dpdpa_personal_data.policy).Statement :
      s.Sid == "ApplicationDescribeKey" && s.Action == "kms:DescribeKey" && !can(s.Condition)
    ])
    error_message = "DescribeKey needs its own statement without an encryption-context condition."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_kms_key.dpdpa_personal_data.policy).Statement :
      s.Effect == "Deny" && contains(s.Action, "kms:ScheduleKeyDeletion")
    ])
    error_message = "Only the admin role may schedule key deletion."
  }
}
