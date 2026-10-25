# aws_kms_dpdpa.tf
# KMS key for DPDPA personal data encryption
# Maps to: Rule 6(1)(a) — key management for encryption

resource "aws_kms_key" "dpdpa_personal_data" {
  description              = "DPDPA personal data encryption - Rule 6(1)(a)"
  deletion_window_in_days  = 30
  enable_key_rotation      = true # Automatic annual rotation
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT" # AES-256-GCM

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "ApplicationEncryptDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = var.application_role_arns # Only app roles
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:ReEncryptFrom",
          "kms:ReEncryptTo",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:purpose" = "dpdpa_field_encryption"
          }
        }
      },
      {
        # DescribeKey carries no encryption context, so it cannot sit under the
        # condition above: the condition would never match and the call would fail.
        Sid    = "ApplicationDescribeKey"
        Effect = "Allow"
        Principal = {
          AWS = var.application_role_arns
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      },
      {
        Sid       = "DenyDeleteToNonAdmins"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DisableKey",
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = var.kms_admin_role_arn
          }
        }
      }
    ]
  })

  tags = {
    compliance  = "dpdpa-rule-6-1-a"
    data_class  = "personal_data"
    environment = var.environment
  }
}

resource "aws_kms_alias" "dpdpa_personal_data" {
  name          = "alias/dpdpa-personal-data-${var.environment}"
  target_key_id = aws_kms_key.dpdpa_personal_data.key_id
}

# CloudTrail logging for KMS key usage — Rule 6(1)(c)
# Ensure CloudTrail is enabled with management events
# Key usage events are logged automatically
# Retention: minimum 1 year per Rule 6(1)(e)

resource "aws_cloudwatch_log_group" "kms_audit" {
  name              = "/dpdpa/kms-audit/${var.environment}"
  retention_in_days = 365 # Rule 6(1)(e): 1 year minimum
}
