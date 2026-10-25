# Python 3.12+, cryptography library. Signs a consent receipt for a single
# DPDPA consent management API grant event. The receipt proves:
#   (1) a notice was given (notice_version_id + content_hash_shown)
#   (2) consent was given (principal pseudonym + timestamp)
#   (3) the binding between them is cryptographically verifiable
from datetime import datetime, timezone
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

RECEIPT_VERSION = "DPDPA-CR-v1"


def _canonical(
    principal_pseudonym: str,
    purpose_id: str,
    notice_version_id: str,
    content_hash_hex: str,
    language_shown: str,
    granted_at: str,
) -> bytes:
    return "|".join([
        RECEIPT_VERSION,
        principal_pseudonym,
        purpose_id,
        notice_version_id,
        content_hash_hex,
        language_shown,
        granted_at,
    ]).encode("utf-8")


def build_consent_receipt(
    principal_pseudonym: str,    # HMAC of principal_id, not the id itself
    purpose_id: str,
    notice_version_id: str,
    content_hash_shown: bytes,    # hash the principal's client actually rendered
    language_shown: str,
    signing_key: Ed25519PrivateKey,
    granted_at: datetime | None = None,
) -> dict:
    granted_at_iso = (granted_at or datetime.now(timezone.utc)).isoformat()
    canonical = _canonical(
        principal_pseudonym,
        purpose_id,
        notice_version_id,
        content_hash_shown.hex(),
        language_shown,
        granted_at_iso,
    )

    receipt_hash = sha256(canonical).digest()
    signature = signing_key.sign(receipt_hash)

    return {
        "version": RECEIPT_VERSION,
        "principal_pseudonym": principal_pseudonym,
        "purpose_id": purpose_id,
        "notice_version_id": notice_version_id,
        "content_hash": content_hash_shown.hex(),
        "language_shown": language_shown,
        "granted_at": granted_at_iso,
        "receipt_hash": receipt_hash.hex(),
        "signature": signature.hex(),
    }


def verify_consent_receipt(receipt: dict, public_key: Ed25519PublicKey) -> bool:
    """Recompute the receipt hash from its fields and check the signature.

    Returns False if any field was changed after signing, or if the signature
    was made with a different key.
    """
    if receipt.get("version") != RECEIPT_VERSION:
        return False
    canonical = _canonical(
        receipt["principal_pseudonym"],
        receipt["purpose_id"],
        receipt["notice_version_id"],
        receipt["content_hash"],
        receipt["language_shown"],
        receipt["granted_at"],
    )
    receipt_hash = sha256(canonical).digest()
    if receipt_hash.hex() != receipt["receipt_hash"]:
        return False
    try:
        public_key.verify(bytes.fromhex(receipt["signature"]), receipt_hash)
    except InvalidSignature:
        return False
    return True
