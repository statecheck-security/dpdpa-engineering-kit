package dpdpa.encryption_test

import data.dpdpa.encryption

change(type, address, after) := {"type": type, "address": address, "change": {"after": after, "after_unknown": {}}}

plan(changes) := {"resource_changes": changes}

sse(algo) := change("aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_server_side_encryption_configuration.pii", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": algo}]}]})

test_s3_with_kms_passes if {
	count(encryption.deny) == 0 with input as plan([sse("aws:kms")])
}

test_s3_with_dsse_kms_passes if {
	count(encryption.deny) == 0 with input as plan([sse("aws:kms:dsse")])
}

test_s3_with_sse_s3_is_denied if {
	msgs := encryption.deny with input as plan([sse("AES256")])
	count(msgs) == 1
	some m in msgs
	contains(m, "found AES256")
}

test_rds_unencrypted_is_denied if {
	msgs := encryption.deny with input as plan([change("aws_db_instance", "aws_db_instance.orders", {"identifier": "orders", "storage_encrypted": false})])
	some m in msgs
	contains(m, "storage_encrypted off")
}

test_rds_missing_storage_encrypted_is_denied if {
	msgs := encryption.deny with input as plan([change("aws_db_instance", "aws_db_instance.orders", {"identifier": "orders"})])
	count(msgs) == 1
}

test_rds_with_default_key_is_denied if {
	msgs := encryption.deny with input as plan([change("aws_db_instance", "aws_db_instance.orders", {"identifier": "orders", "storage_encrypted": true, "kms_key_id": null})])
	some m in msgs
	contains(m, "AWS-managed key")
}

test_rds_with_cmk_passes if {
	count(encryption.deny) == 0 with input as plan([change("aws_db_instance", "aws_db_instance.orders", {"identifier": "orders", "storage_encrypted": true, "kms_key_id": "arn:aws:kms:ap-south-1:123456789012:key/abc"})])
}

test_rds_with_cmk_created_in_same_plan_passes if {
	rds := {"type": "aws_db_instance", "address": "aws_db_instance.orders", "change": {"after": {"identifier": "orders", "storage_encrypted": true}, "after_unknown": {"kms_key_id": true}}}
	count(encryption.deny) == 0 with input as plan([rds])
}

test_ebs_unencrypted_is_denied_even_without_tags if {
	msgs := encryption.deny with input as plan([change("aws_ebs_volume", "aws_ebs_volume.data", {"encrypted": false})])
	some m in msgs
	contains(m, "(untagged)")
}

test_elasticache_needs_both_encryptions if {
	msgs := encryption.deny with input as plan([change("aws_elasticache_replication_group", "aws_elasticache_replication_group.sessions", {"replication_group_id": "sessions", "at_rest_encryption_enabled": true, "transit_encryption_enabled": false})])
	count(msgs) == 1
	some m in msgs
	contains(m, "in-transit")
}

test_unrelated_resources_are_ignored if {
	count(encryption.deny) == 0 with input as plan([change("aws_iam_role", "aws_iam_role.app", {"name": "app"})])
}

test_null_booleans_are_treated_as_off if {
	msgs := encryption.deny with input as plan([
		change("aws_db_instance", "aws_db_instance.a", {"identifier": "a", "storage_encrypted": null}),
		change("aws_ebs_volume", "aws_ebs_volume.b", {"encrypted": null}),
		change("aws_elasticache_replication_group", "aws_elasticache_replication_group.c", {"replication_group_id": "c", "at_rest_encryption_enabled": null, "transit_encryption_enabled": null}),
	])
	count(msgs) == 4
}
