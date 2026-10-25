# gcp_kms_dpdpa.tf
# GCP Cloud KMS for DPDPA personal data encryption

resource "google_kms_key_ring" "dpdpa" {
  name     = "dpdpa-personal-data-${var.environment}"
  location = "asia-south1" # Mumbai region
}

resource "google_kms_crypto_key" "dpdpa_personal_data" {
  name     = "personal-data-encryption-key"
  key_ring = google_kms_key_ring.dpdpa.id

  purpose = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION" # AES-256-GCM
    protection_level = "HSM"                         # Cloud HSM backing
  }

  # Automatic key rotation — annual
  rotation_period = "31536000s" # 365 days

  # Prevent accidental destruction
  lifecycle {
    prevent_destroy = true
  }

  labels = {
    compliance = "dpdpa-rule-6-1-a"
    data_class = "personal-data"
  }
}

# IAM binding: only the application service account can encrypt/decrypt
resource "google_kms_crypto_key_iam_member" "app_encrypter" {
  crypto_key_id = google_kms_crypto_key.dpdpa_personal_data.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${var.app_service_account_email}"
}

# Audit logging is enabled by default in GCP Cloud Audit Logs
# Ensure Data Access logs are enabled for Cloud KMS
resource "google_project_iam_audit_config" "kms_audit" {
  project = var.project_id
  service = "cloudkms.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
