# src/zt_audit_logger.py
#
# Changed from the article: the "integrity seal" was a plain SHA-256 of the
# event, which anyone who can edit a log line can recompute. It is now an
# HMAC with a key the log writer holds, chained to the previous event's seal,
# so edits and deleted lines are both detectable.
import hashlib
import hmac
import json
from datetime import datetime, timezone

GENESIS = "0" * 64


def log_personal_data_access(
    principal: str,
    resource: str,
    action: str,
    outcome: str,       # "allow" | "deny"
    device_id: str,
    session_id: str,
    *,
    seal_key: bytes,    # from KMS / Vault; never stored with the logs
    prev_seal: str = GENESIS,
) -> dict:
    """
    Emit a structured audit event for Rule 6(1)(c) compliance.
    Captures: who accessed what, from which device, in which session,
    and whether access was granted or denied.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "principal": principal,
        "resource": resource,
        "action": action,
        "outcome": outcome,
        "device_id": device_id,
        "session_id": session_id,
        "legal_basis": "Rule 6(1)(c) — DPDP Rules 2025",
        "prev_seal": prev_seal,
    }
    event["integrity_hmac"] = _seal(event, seal_key)
    return event


def _seal(event: dict, key: bytes) -> str:
    body = {k: v for k, v in event.items() if k != "integrity_hmac"}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False)
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_log(events: list[dict], seal_key: bytes) -> int | None:
    """Return the index of the first event that was edited, inserted or follows a deletion; None if intact."""
    prev = GENESIS
    for i, event in enumerate(events):
        if event.get("prev_seal") != prev:
            return i
        if not hmac.compare_digest(event.get("integrity_hmac", ""), _seal(event, seal_key)):
            return i
        prev = event["integrity_hmac"]
    return None
