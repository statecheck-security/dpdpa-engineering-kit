package dpdpa.access_test

import data.dpdpa.access

future_ns := time.now_ns() + (3600 * 1000000000)

past_ns := time.now_ns() - 1

policy_data := {
	"dpa_authorised_services": {"order_fulfilment": ["orders-api"]},
	"purpose_field_scope": {"order_fulfilment": ["name", "address", "phone"]},
}

request(overrides) := object.union(
	{
		"caller": {"service_id": "orders-api"},
		"request": {"purpose": "order_fulfilment", "fields": ["name", "address"]},
		"resource": {"data_principal_id": "dp-1"},
		"consent_events": [{"data_principal_id": "dp-1", "purpose": "order_fulfilment", "status": "active", "expires_at_ns": future_ns}],
	},
	overrides,
)

test_active_consent_bound_service_and_scoped_fields_is_allowed if {
	access.allow with input as request({}) with data.dpa_authorised_services as policy_data.dpa_authorised_services
		with data.purpose_field_scope as policy_data.purpose_field_scope
}

test_field_outside_purpose_scope_is_denied if {
	inp := request({"request": {"purpose": "order_fulfilment", "fields": ["name", "aadhaar"]}})
	not access.allow with input as inp with data.dpa_authorised_services as policy_data.dpa_authorised_services
		with data.purpose_field_scope as policy_data.purpose_field_scope
}

test_service_without_processor_contract_is_denied if {
	inp := request({"caller": {"service_id": "marketing-api"}})
	not access.allow with input as inp with data.dpa_authorised_services as policy_data.dpa_authorised_services
		with data.purpose_field_scope as policy_data.purpose_field_scope
}

test_withdrawn_consent_is_denied if {
	inp := request({"consent_events": [{"data_principal_id": "dp-1", "purpose": "order_fulfilment", "status": "withdrawn", "expires_at_ns": future_ns}]})
	not access.allow with input as inp with data.dpa_authorised_services as policy_data.dpa_authorised_services
		with data.purpose_field_scope as policy_data.purpose_field_scope
}

test_expired_consent_is_denied if {
	inp := request({"consent_events": [{"data_principal_id": "dp-1", "purpose": "order_fulfilment", "status": "active", "expires_at_ns": past_ns}]})
	not access.allow with input as inp with data.dpa_authorised_services as policy_data.dpa_authorised_services
		with data.purpose_field_scope as policy_data.purpose_field_scope
}

test_consent_for_another_principal_is_denied if {
	inp := request({"resource": {"data_principal_id": "dp-2"}})
	not access.allow with input as inp with data.dpa_authorised_services as policy_data.dpa_authorised_services
		with data.purpose_field_scope as policy_data.purpose_field_scope
}

test_denial_produces_a_violation_message if {
	inp := request({"caller": {"service_id": "marketing-api"}})
	msgs := access.violation with input as inp with data.dpa_authorised_services as policy_data.dpa_authorised_services
		with data.purpose_field_scope as policy_data.purpose_field_scope
	count(msgs) == 1
	some m in msgs
	contains(m, "caller=marketing-api")
}
