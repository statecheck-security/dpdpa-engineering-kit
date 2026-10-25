# policies/dpdpa_least_privilege.rego
package dpdpa.iam

import future.keywords.contains
import future.keywords.if

# Rule 6(1)(b): control access to computer resources holding personal data,
# implemented on the principle of least privilege.
default allow := false

allow if {
	input.action in data.permissions[input.principal][input.resource]
}

# Deny access to personal_data scope unless explicitly granted
deny contains msg if {
	input.resource_scope == "personal_data"
	not allow
	msg := sprintf(
		"Access denied: %v lacks %v permission on %v (DPDPA Rule 6(1)(b))",
		[input.principal, input.action, input.resource],
	)
}
