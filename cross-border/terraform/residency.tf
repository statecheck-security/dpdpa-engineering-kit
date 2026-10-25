# Enforce that Indian personal data stays in ap-south-1
resource "aws_s3_bucket" "india_pii" {
  provider = aws.ap_south_1
  bucket   = "myorg-india-personal-data"
  # S3 buckets are region-pinned at creation
}

resource "aws_s3_bucket_policy" "india_residency" {
  provider = aws.ap_south_1
  bucket   = aws_s3_bucket.india_pii.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # S3 has no condition key for the replication destination, so the
        # bucket policy limits who may set replication at all. Pair it with the
        # SCP in ../aws/scp-india-residency.json, which stops destination
        # buckets being created outside India.
        Sid       = "OnlyResidencyAdminSetsReplication"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutReplicationConfiguration"
        Resource  = aws_s3_bucket.india_pii.arn
        Condition = {
          ArnNotEquals = {
            "aws:PrincipalArn" = var.residency_admin_role_arn
          }
        }
      },
      {
        Sid       = "EnforceEncryptionInTransit"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.india_pii.arn,
          "${aws_s3_bucket.india_pii.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# KMS key pinned to ap-south-1 -- data encrypted with this key
# cannot be decrypted outside the region (true for single-Region keys only,
# hence multi_region = false: a multi-Region key can be replicated elsewhere)
resource "aws_kms_key" "india_pii_key" {
  provider     = aws.ap_south_1
  description  = "DPDPA-compliant encryption key for Indian PII"
  multi_region = false

  # Key policy restricts usage to India region principals
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RestrictToIndiaRegion"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "ap-south-1"
          }
        }
      }
    ]
  })
}
