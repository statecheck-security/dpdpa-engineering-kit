package dpdpa.zero_trust_test

import data.dpdpa.iam
import data.dpdpa.network

permissions := {"orders-api": {"customers.address": ["read"]}}

# --- least_privilege.rego ---

test_granted_action_is_allowed if {
	iam.allow with input as {"principal": "orders-api", "resource": "customers.address", "action": "read"}
		with data.permissions as permissions
}

test_ungranted_action_is_denied_with_message if {
	inp := {"principal": "orders-api", "resource": "customers.address", "action": "write", "resource_scope": "personal_data"}
	not iam.allow with input as inp with data.permissions as permissions
	msgs := iam.deny with input as inp with data.permissions as permissions
	count(msgs) == 1
}

test_unknown_principal_is_denied if {
	not iam.allow with input as {"principal": "marketing-api", "resource": "customers.address", "action": "read"}
		with data.permissions as permissions
}

test_non_personal_scope_has_no_deny_message if {
	inp := {"principal": "orders-api", "resource": "catalogue", "action": "write", "resource_scope": "public"}
	count(iam.deny) == 0 with input as inp with data.permissions as permissions
}

# --- network.rego ---

test_flow_between_ordinary_segments_is_allowed if {
	network.allow_flow with input as {"src_segment": "web", "dst_segment": "app"}
}

test_approved_healthy_service_reaches_personal_data_zone if {
	network.allow_flow with input as {
		"src_segment": "app", "dst_segment": "personal_data_zone",
		"src_service": "orders-api", "device_posture": {"compliant": true},
	}
		with data.approved_services as ["orders-api"]
}

test_unhealthy_device_is_blocked if {
	not network.allow_flow with input as {
		"src_segment": "app", "dst_segment": "personal_data_zone",
		"src_service": "orders-api", "device_posture": {"compliant": false},
	}
		with data.approved_services as ["orders-api"]
}

test_unapproved_service_is_blocked if {
	not network.allow_flow with input as {
		"src_segment": "app", "dst_segment": "personal_data_zone",
		"src_service": "analytics", "device_posture": {"compliant": true},
	}
		with data.approved_services as ["orders-api"]
}

test_egress_from_personal_data_zone_is_blocked_by_default if {
	not network.allow_flow with input as {"src_segment": "personal_data_zone", "dst_segment": "web"}
}
