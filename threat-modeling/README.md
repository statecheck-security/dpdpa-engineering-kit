# Threat-model mitigations

Code for three findings a LINDDUN + STRIDE review of a consent-handling system typically
produces.

From [DPDPA threat modelling with LINDDUN and STRIDE](https://statechecksecurity.com/blog/dpdpa-threat-modeling-linddun-stride).

| Path | Threat | What it does |
|---|---|---|
| `signup.py` | Detectability (LINDDUN) | Signup always answers 202 with a random correlation ID and queues the work, so the response can't reveal whether an email or phone is registered. Only HMACs of the normalised email and phone reach the queue. |
| `policies/purpose_scope.rego` | Elevation of privilege (STRIDE), linkability (LINDDUN) | Allows a read only with active, unexpired consent for that purpose, from a service under a processor contract, for fields within the purpose's scope |
| `crypto_shred.py` | Non-repudiation vs erasure | Erases by scheduling deletion of the Data Principal's KMS key, and keeps the consent ledger entry with identifiers stripped |
| `dfd.mmd` | — | DPDPA-annotated data flow diagram |

## Before you use it

- **`signup.py`**: wire `enqueue_signup_task` to your queue and `load_secret` to your secret
  store. The worker must send the same message whether or not the account exists.
- **`crypto_shred.py`** uses one KMS key per Data Principal. KMS charges per key per month,
  so at scale, wrap per-principal data keys with one KMS key and delete the wrapped key
  instead. A scheduled key deletion can be cancelled for 7 days; record the erasure as final
  after KMS emits `DeleteKey`.
- **The Rego policy** needs `data.dpa_authorised_services` and `data.purpose_field_scope`;
  generate both from your processor contracts and purpose register.

## Tests

`tests/test_threat_modeling.py` (signup through `TestClient`; crypto-shred through botocore's
`Stubber`) and `opa test policies/`.
