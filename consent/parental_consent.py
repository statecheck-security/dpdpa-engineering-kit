"""
parental_consent.py

Implements Verifiable Parental Consent (VPC) and Child Data Protection safeguards
mandated by DPDPA Section 9 and the DPDP Rules, 2025.

Statutory Obligations:
  - Section 9(1): Verifiable consent of the parent or lawful guardian before processing
    any personal data of a child (individual < 18 years, Section 2(f)).
  - Section 9(2): Prohibition of processing causing detrimental effect on well-being of child.
  - Section 9(3): Absolute statutory prohibition on:
      (a) Tracking
      (b) Behavioural monitoring
      (c) Targeted advertising directed at children
"""
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from enum import Enum
from hashlib import sha256


class GuardianRelationship(Enum):
    PARENT = "parent"
    LAWFUL_GUARDIAN = "lawful_guardian"


class VerificationMethod(Enum):
    DIGILOCKER_PARENT_BINDING = "digilocker_parent_binding"
    GOVT_ID_OTP = "govt_id_otp"
    MICRO_PAYMENT_REVERSAL = "micro_payment_reversal"
    TOKENIZED_GUARDIAN_CREDENTIAL = "tokenized_guardian_credential"


class ProhibitedProcessingType(Enum):
    TRACKING = "tracking"
    BEHAVIOURAL_MONITORING = "behavioural_monitoring"
    TARGETED_ADVERTISING = "targeted_advertising"


class ChildProcessingViolation(Exception):
    """Raised when an operation violates Section 9 child protection safeguards."""
    pass


def calculate_age(dob: date, at_date: date | None = None) -> int:
    at = at_date or datetime.now(timezone.utc).date()
    return at.year - dob.year - ((at.month, at.day) < (dob.month, dob.day))


def is_child(dob: date, at_date: date | None = None) -> bool:
    """DPDPA Section 2(f): 'child' means an individual who has not completed the age of eighteen years."""
    return calculate_age(dob, at_date) < 18


@dataclass
class ParentalConsentRecord:
    consent_id: str
    child_principal_id: str
    guardian_principal_id: str
    relationship: GuardianRelationship
    verification_method: VerificationMethod
    verification_proof_hash: str
    approved_purposes: list[str]
    tracking_prohibited: bool = True
    behavioural_monitoring_prohibited: bool = True
    targeted_advertising_prohibited: bool = True
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        if self.expires_at and current >= self.expires_at:
            return False
        return True


class ChildDataGuard:
    """Enforces Section 9 child data protection rules across processing activities."""

    def __init__(self):
        self.consents: dict[str, ParentalConsentRecord] = {}  # child_id -> active consent

    def register_parental_consent(
        self,
        child_principal_id: str,
        guardian_principal_id: str,
        relationship: GuardianRelationship,
        verification_method: VerificationMethod,
        verification_proof: bytes,
        approved_purposes: list[str],
        expires_at: datetime | None = None,
    ) -> ParentalConsentRecord:
        proof_hash = sha256(verification_proof).hexdigest()
        record = ParentalConsentRecord(
            consent_id=str(uuid.uuid4()),
            child_principal_id=child_principal_id,
            guardian_principal_id=guardian_principal_id,
            relationship=relationship,
            verification_method=verification_method,
            verification_proof_hash=proof_hash,
            approved_purposes=approved_purposes,
            tracking_prohibited=True,
            behavioural_monitoring_prohibited=True,
            targeted_advertising_prohibited=True,
            verified_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )
        self.consents[child_principal_id] = record
        return record

    def validate_processing(
        self,
        child_dob: date,
        child_principal_id: str,
        purpose_key: str,
        activity_type: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        """
        Validates whether data processing for this individual is legally permitted.
        Enforces Section 9(1) verifiable consent and Section 9(3) processing prohibitions.
        """
        current_time = now or datetime.now(timezone.utc)
        current_date = current_time.date()

        # If individual is 18 or older, Section 9 child constraints no longer apply
        if not is_child(child_dob, current_date):
            return True

        # Check Section 9(3) statutory prohibitions
        if activity_type:
            normalized_activity = activity_type.lower().strip()
            prohibited_types = {p.value for p in ProhibitedProcessingType}
            if normalized_activity in prohibited_types:
                raise ChildProcessingViolation(
                    f"DPDPA Section 9(3) violation: processing of type '{activity_type}' "
                    f"is strictly prohibited for children."
                )

        # Check Section 9(1) verifiable parental consent
        consent = self.consents.get(child_principal_id)
        if consent is None or not consent.is_active(current_time):
            raise ChildProcessingViolation(
                f"DPDPA Section 9(1) violation: No active verifiable parental consent "
                f"registered for child '{child_principal_id}'."
            )

        if purpose_key not in consent.approved_purposes:
            raise ChildProcessingViolation(
                f"DPDPA Section 9(1) violation: Purpose '{purpose_key}' is not approved "
                f"in verifiable parental consent for child '{child_principal_id}'."
            )

        return True
