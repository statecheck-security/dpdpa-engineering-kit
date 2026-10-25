package dpdpa.retention_test

import data.dpdpa.retention

log_group(days) := {"resource_changes": [{
	"type": "aws_cloudwatch_log_group",
	"address": "aws_cloudwatch_log_group.audit",
	"change": {"after": {"name": "/dpdpa/audit", "retention_in_days": days}},
}]}

test_one_year_passes if {
	count(retention.deny) == 0 with input as log_group(365)
}

test_longer_passes if {
	count(retention.deny) == 0 with input as log_group(731)
}

test_never_expire_passes if {
	count(retention.deny) == 0 with input as log_group(0)
}

test_unset_passes if {
	count(retention.deny) == 0 with input as log_group(null)
}

test_ninety_days_is_denied if {
	msgs := retention.deny with input as log_group(90)
	count(msgs) == 1
	some m in msgs
	contains(m, "90 days")
}
