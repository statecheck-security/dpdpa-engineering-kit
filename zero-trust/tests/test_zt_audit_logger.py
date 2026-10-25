import hashlib
import json

from zt_audit_logger import GENESIS, log_personal_data_access, verify_log

KEY = b"test-seal-key"


def _log(n=3):
    events, prev = [], GENESIS
    for i in range(n):
        e = log_personal_data_access(
            f"svc-{i}", "customers.email", "READ", "allow", "laptop-7", "sess-1", seal_key=KEY, prev_seal=prev
        )
        events.append(e)
        prev = e["integrity_hmac"]
    return events


def test_event_records_who_what_where_and_outcome():
    (e,) = _log(1)
    assert {"principal", "resource", "action", "outcome", "device_id", "session_id", "timestamp"} <= e.keys()
    assert e["prev_seal"] == GENESIS


def test_intact_log_verifies():
    assert verify_log(_log(), KEY) is None


def test_edited_event_is_detected():
    events = _log()
    events[1]["outcome"] = "deny"
    assert verify_log(events, KEY) == 1


def test_deleted_event_is_detected():
    events = _log()
    del events[1]
    assert verify_log(events, KEY) == 1


def test_attacker_without_key_cannot_reseal():
    """The article's plain SHA-256 seal could be recomputed by anyone; an HMAC cannot."""
    events = _log()
    forged = dict(events[1], outcome="deny")
    body = {k: v for k, v in forged.items() if k != "integrity_hmac"}
    forged["integrity_hmac"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    events[1] = forged
    assert verify_log(events, KEY) == 1


def test_wrong_key_fails_verification():
    assert verify_log(_log(), b"other-key") == 0
