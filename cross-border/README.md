# Cross-border transfers

Section 16 lets personal data go anywhere except countries the Central Government restricts by
notification. None are restricted yet, but sector rules (RBI payment-data localisation, for
one) already apply, and GDPR still governs EU data. This folder keeps Indian data in India by
default and decides transfers against both regimes.

From [DPDPA cross-border data transfer](https://statechecksecurity.com/blog/dpdpa-cross-border-data-transfer).

| Path | What it is |
|---|---|
| `aws/scp-india-residency.json` | Service Control Policy: regional actions only in `ap-south-1` / `ap-south-2`; S3 replication set only by a residency-admin role |
| `terraform/residency.tf` | India bucket with HTTPS-only access and admin-only replication, and a single-Region KMS key usable only in `ap-south-1` |
| `azure/deny-non-india-locations.json` | Azure Policy: resources tagged `data-residency=india` must be in an Indian region |
| `azure/require-cmk-storage.json` | Azure Policy: those storage accounts must use a Key Vault key |
| `transfer_governance.py`, `transfer-policy.json` | Returns the most restrictive of the DPDPA and GDPR decisions for a transfer |
| `architecture.mmd` | Region-pinned data, global compute |

## Before you use it

- **SCP exemptions.** `NotAction` exempts global services (IAM, STS, CloudFront, Route 53,
  Organizations, Support). Add any other global service you use, or its calls will be denied.
  Test the SCP in a sandbox OU before attaching it to production.
- **Replication role.** Replace `data-residency-admin` (SCP) and `var.residency_admin_role_arn`
  (bucket policy) with your role.
- **Section 16 list.** Keep `dpdpa_restricted_destinations` in `transfer-policy.json` up to date
  as MeitY notifies countries. It is empty as of October 2026.
- **GDPR adequacy.** The list leaves out the US on purpose: the EU–US Data Privacy Framework
  covers only certified organisations, which a country list can't express. Handle those
  transfers as SCC cases or add a per-processor check.

## Tests

`tests/test_transfer_governance.py`, `tests/test_azure_policies.py` (evaluates the policy
conditions on sample resources), `tests/test_aws_condition_keys.py` (every IAM condition key
in the kit exists, per AWS's Service Reference) and `terraform test` in `terraform/`.
