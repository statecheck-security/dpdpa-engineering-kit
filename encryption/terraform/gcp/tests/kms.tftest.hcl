# Plans the module against a mocked Google provider (no credentials needed) and checks its safeguards.
mock_provider "google" {}

variables {
  project_id                = "dpdpa-test"
  environment               = "test"
  app_service_account_email = "orders-api@dpdpa-test.iam.gserviceaccount.com"
}

run "key_is_in_india_hsm_backed_and_rotates" {
  command = plan

  assert {
    condition     = google_kms_key_ring.dpdpa.location == "asia-south1"
    error_message = "The key ring must stay in an Indian region."
  }

  assert {
    condition     = google_kms_crypto_key.dpdpa_personal_data.version_template[0].protection_level == "HSM"
    error_message = "Use HSM protection."
  }

  assert {
    condition     = google_kms_crypto_key.dpdpa_personal_data.rotation_period == "31536000s"
    error_message = "Rotate the key at least every 365 days."
  }
}

run "only_the_app_can_use_the_key_and_access_is_logged" {
  command = plan

  assert {
    condition     = google_kms_crypto_key_iam_member.app_encrypter.member == "serviceAccount:orders-api@dpdpa-test.iam.gserviceaccount.com"
    error_message = "Grant encrypt/decrypt to the application service account only."
  }

  assert {
    condition     = toset([for c in google_project_iam_audit_config.kms_audit.audit_log_config : c.log_type]) == toset(["DATA_READ", "DATA_WRITE"])
    error_message = "Data Access logs must be on for Cloud KMS."
  }
}
