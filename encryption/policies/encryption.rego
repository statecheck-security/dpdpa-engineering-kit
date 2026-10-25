# policies/dpdpa/encryption.rego
# Rule 6(1)(a) lists encryption among the reasonable security safeguards for
# personal data. Used as a CI/CD gate on `terraform show -json` plan output.
#
# Merges the two versions in the encryption and privacy-by-design articles.
# Rego v1 syntax (OPA 1.0+).

package dpdpa.encryption

# S3 default encryption must use KMS (SSE-S3 is on by default for every new
# bucket since January 2023, so "no encryption" no longer happens; the useful
# check is which keys are used).
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
	rule := resource.change.after.rule[_]
	algo := rule.apply_server_side_encryption_by_default[_].sse_algorithm
	not algo in {"aws:kms", "aws:kms:dsse"}
	msg := sprintf(
		"S3 default encryption must use aws:kms, found %s. Rule 6(1)(a) lists encryption as a safeguard; KMS keys give the access control and audit trail behind it. [%s]",
		[algo, resource.address],
	)
}

# RDS instances must have storage encryption on
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_db_instance"
	not is_true(resource.change.after, "storage_encrypted")
	msg := sprintf(
		"RDS instance '%s' has storage_encrypted off. Rule 6(1)(a) lists encryption as a safeguard. [%s]",
		[resource.change.after.identifier, resource.address],
	)
}

# RDS instances should use a customer-managed KMS key
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_db_instance"
	resource.change.after.storage_encrypted == true
	not has_value(resource.change.after, "kms_key_id")
	not known_after_apply(resource, "kms_key_id")
	msg := sprintf(
		"RDS instance '%s' uses the AWS-managed key. Policy: use a customer-managed KMS key so you control rotation, access and deletion (DPDPA does not name a key type). [%s]",
		[resource.change.after.identifier, resource.address],
	)
}

# EBS volumes must be encrypted
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_ebs_volume"
	not is_true(resource.change.after, "encrypted")
	msg := sprintf(
		"EBS volume %s is unencrypted. Rule 6(1)(a). [%s]",
		[object.get(object.get(resource.change.after, "tags", {}), "Name", "(untagged)"), resource.address],
	)
}

# ElastiCache must encrypt at rest and in transit
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_elasticache_replication_group"
	not is_true(resource.change.after, "at_rest_encryption_enabled")
	msg := sprintf(
		"ElastiCache '%s' lacks at-rest encryption. Rule 6(1)(a). [%s]",
		[resource.change.after.replication_group_id, resource.address],
	)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_elasticache_replication_group"
	not is_true(resource.change.after, "transit_encryption_enabled")
	msg := sprintf(
		"ElastiCache '%s' lacks in-transit encryption. Rule 6(1)(a). [%s]",
		[resource.change.after.replication_group_id, resource.address],
	)
}

# Plan JSON writes unset attributes as null, which Rego's `not` does not treat as false
has_value(obj, attr) if {
	not object.get(obj, attr, null) in {null, ""}
}

# A value Terraform will only know after apply (e.g. a key ARN created in the same plan)
known_after_apply(resource, attr) if {
	resource.change.after_unknown[attr] == true
}

is_true(obj, attr) if {
	object.get(obj, attr, false) == true
}
