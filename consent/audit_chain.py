# Computes the hash chain entry for a single consent lifecycle event.
# Each event in the DPDPA consent management API audit log is bound to the
# previous one, so any tampering with historical rows breaks the chain and
# is detectable by the auditor walking it forwards.
import json
from hashlib import sha256

GENESIS_HASH = b"\x00" * 32  # prev_event_hash for the first event of a consent


def compute_event_hash(
    prev_event_hash: bytes,
    consent_id: str,
    event_type: str,
    event_payload: dict,
    occurred_at_iso: str,
) -> bytes:
    # Canonicalise with sorted keys so that replay-hashing is deterministic.
    payload_bytes = json.dumps(event_payload, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
    header = b"|".join([
        prev_event_hash,
        consent_id.encode("utf-8"),
        event_type.encode("utf-8"),
        occurred_at_iso.encode("utf-8"),
    ])
    return sha256(header + b"|" + payload_bytes).digest()


def verify_chain(events: list[dict]) -> int | None:
    """Walk events in order and return the index of the first broken link, or None.

    Each event is a dict with the consent_audit_event columns: consent_id,
    event_type, event_payload, occurred_at (ISO string), prev_event_hash and
    this_event_hash.
    """
    expected_prev = GENESIS_HASH
    for i, event in enumerate(events):
        if event["prev_event_hash"] != expected_prev:
            return i
        recomputed = compute_event_hash(
            event["prev_event_hash"],
            event["consent_id"],
            event["event_type"],
            event["event_payload"],
            event["occurred_at"],
        )
        if recomputed != event["this_event_hash"]:
            return i
        expected_prev = event["this_event_hash"]
    return None
