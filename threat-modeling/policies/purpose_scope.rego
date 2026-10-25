# policy/dpdpa_purpose_scope.rego
package dpdpa.access

# STRIDE: Elevation of Privilege
# LINDDUN: Linkability, Non-compliance
# DPDPA: Section 6(1), Section 8(1)-(2), Rule 6(1)(b)

default allow := false

allow if {
	# The caller has an active consent event for this exact purpose
	some consent in input.consent_events
	consent.data_principal_id == input.resource.data_principal_id
	consent.purpose == input.request.purpose
	consent.status == "active"
	time.now_ns() < consent.expires_at_ns

	# The caller's service identity is contractually bound
	input.caller.service_id in data.dpa_authorised_services[input.request.purpose]

	# The requested fields are within the purpose's minimum-necessary set
	requested := {f | f := input.request.fields[_]}
	allowed := {f | f := data.purpose_field_scope[input.request.purpose][_]}
	count(requested - allowed) == 0
}

violation contains msg if {
	not allow
	msg := sprintf(
		"dpdpa: access denied. caller=%s purpose=%s principal=%s. Refer DPDPA S.6(1) purpose limitation and S.8(1) accountability.",
		[input.caller.service_id, input.request.purpose, input.resource.data_principal_id],
	)
}
