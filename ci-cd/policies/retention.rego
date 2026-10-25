# policies/dpdpa/retention.rego
# Rules 6(1)(e) and 8(3) keep logs of personal data processing for at least one year.
# Gate 2 of the privacy-by-design pipeline runs this on `terraform show -json` plan output.

package dpdpa.retention

min_days := 365

# CloudWatch log groups must keep logs for a year. retention_in_days = 0 (or unset) means "never expire".
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_cloudwatch_log_group"
	days := object.get(resource.change.after, "retention_in_days", 0)
	days != null
	days > 0
	days < min_days
	msg := sprintf(
		"Log group %s keeps logs for %d days; Rules 6(1)(e) and 8(3) need at least %d. [%s]",
		[object.get(resource.change.after, "name", "(unnamed)"), days, min_days, resource.address],
	)
}
