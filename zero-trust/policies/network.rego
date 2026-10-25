# policies/dpdpa_network_policy.rego
package dpdpa.network

import future.keywords.if

# Default: deny all cross-segment flows to personal_data_zone
default allow_flow := false

allow_flow if {
	input.src_segment != "personal_data_zone"
	input.dst_segment != "personal_data_zone"
}

allow_flow if {
	input.dst_segment == "personal_data_zone"

	# Require: source is an approved service AND device posture is healthy
	input.src_service in data.approved_services
	input.device_posture.compliant == true
}
