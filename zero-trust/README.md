# Zero Trust controls

Rule 6(1)(b) asks for access control on systems holding personal data; Rule 6(1)(c) for
logs and monitoring to detect unauthorised access. These are the identity, network and
visibility pieces.

From [Zero Trust and DPDPA compliance](https://statechecksecurity.com/blog/zero-trust-dpdpa-compliance).

| Path | What it is |
|---|---|
| `policies/least_privilege.rego` | Allows an action only if granted to that principal on that resource; explains every denied personal-data access |
| `policies/network.rego` | Default-deny into the personal-data zone, except approved services on compliant devices |
| `zt_audit_logger.py` | Access events sealed with an HMAC chained to the previous event, and `verify_log()` to find edits or gaps |

## Before you use it

- **Seal key.** Keep `seal_key` in a KMS or vault, out of reach of anyone who can write to the
  log store. Persist the last seal so the chain survives restarts.
- **Policy data.** `data.permissions` and `data.approved_services` come from your IAM and
  service catalogue. Generate them; don't hand-edit them.

## Tests

`tests/test_zt_audit_logger.py` and `opa test policies/`.
