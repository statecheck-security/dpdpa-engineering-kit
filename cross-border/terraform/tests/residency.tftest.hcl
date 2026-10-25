# Plans the module against a mocked AWS provider (no credentials needed) and checks the residency controls.
mock_provider "aws" {
  alias           = "ap_south_1"
  override_during = plan

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::myorg-india-personal-data"
    }
  }
}

variables {
  residency_admin_role_arn = "arn:aws:iam::123456789012:role/data-residency-admin"
}

run "replication_is_limited_to_the_residency_admin" {
  command = plan

  assert {
    condition = anytrue([
      for s in jsondecode(aws_s3_bucket_policy.india_residency.policy).Statement :
      s.Action == "s3:PutReplicationConfiguration" && s.Effect == "Deny" &&
      try(s.Condition.ArnNotEquals["aws:PrincipalArn"], "") == "arn:aws:iam::123456789012:role/data-residency-admin"
    ])
    error_message = "Only the residency admin role may configure replication."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_s3_bucket_policy.india_residency.policy).Statement :
      s.Effect == "Deny" && try(s.Condition.Bool["aws:SecureTransport"], "") == "false"
    ])
    error_message = "Plain-HTTP access to the bucket must be denied."
  }
}

run "kms_key_cannot_leave_the_region" {
  command = plan

  assert {
    condition     = aws_kms_key.india_pii_key.multi_region == false
    error_message = "A multi-Region key can be replicated outside India."
  }

  assert {
    condition     = jsondecode(aws_kms_key.india_pii_key.policy).Statement[0].Condition.StringEquals["aws:RequestedRegion"] == "ap-south-1"
    error_message = "Key use must be limited to ap-south-1."
  }
}
