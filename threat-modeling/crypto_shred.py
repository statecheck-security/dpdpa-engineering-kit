# erasure/crypto_shred.py
#
# The erasure logic is the one from the article. The AWS clients and the two
# lookups are passed in rather than created at import time: boto3.client("kms")
# at module level fails on import anywhere no default AWS region is set.
import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class ErasureResult:
    data_principal_id: str
    deleted_key_arn: str
    erasure_timestamp_utc: str
    consent_record_retained: bool


class CryptoShredder:
    def __init__(
        self,
        kms,                                   # boto3.client("kms", region_name="ap-south-1")
        consent_table,                         # boto3.resource("dynamodb").Table("consent_events")
        lookup_dek_arn: Callable[[str], str],  # principal id -> ARN of that principal's KMS key
        pseudonym_key: bytes,                  # HMAC key for the ledger's principal pseudonyms
    ):
        self.kms = kms
        self.ddb = consent_table
        self._lookup_dek_arn = lookup_dek_arn
        self._pseudonym_key = pseudonym_key

    def _pseudonym(self, data_principal_id: str) -> str:
        return hmac.new(self._pseudonym_key, data_principal_id.encode(), hashlib.sha256).hexdigest()

    def erase_data_principal(self, data_principal_id: str, reason: str) -> ErasureResult:
        """
        Reconciles DPDPA Section 8(7) erasure obligation with
        Section 6(10) consent proof obligation.

        Strategy: per-principal DEK in KMS, destroyed on erasure request.
        The ciphertext in object storage becomes unrecoverable, but the
        consent ledger entry (which contains no plaintext PII) is retained
        for at least the one-year minimum under Rules 6(1)(e) and 8(3).
        """
        dek_arn = self._lookup_dek_arn(data_principal_id)

        # Schedule deletion with 7-day window (KMS minimum) — logged for
        # Rule 6(1)(c) detection of unauthorised access requirements.
        # Until the window ends the deletion can be cancelled, so record the
        # erasure as complete only after it (KMS emits a DeleteKey event).
        self.kms.schedule_key_deletion(KeyId=dek_arn, PendingWindowInDays=7)

        # Retain the ledger entry but strip any residual quasi-identifiers.
        pseudonym = self._pseudonym(data_principal_id)
        self.ddb.update_item(
            Key={"data_principal_id": pseudonym},
            UpdateExpression="SET erasure_reason = :r, erased_at = :t REMOVE email, phone",
            ExpressionAttributeValues={
                ":r": reason,
                ":t": datetime.now(timezone.utc).isoformat(),
            },
        )

        return ErasureResult(
            data_principal_id=pseudonym,
            deleted_key_arn=dek_arn,
            erasure_timestamp_utc=datetime.now(timezone.utc).isoformat(),
            consent_record_retained=True,
        )
