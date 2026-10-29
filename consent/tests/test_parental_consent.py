from datetime import date, datetime, timedelta, timezone

import pytest
from parental_consent import (
    ChildDataGuard,
    ChildProcessingViolation,
    GuardianRelationship,
    VerificationMethod,
    calculate_age,
    is_child,
)


def test_age_calculation_and_child_detection():
    now_date = date(2026, 10, 29)
    assert calculate_age(date(2012, 5, 10), now_date) == 14
    assert is_child(date(2012, 5, 10), now_date) is True

    # Exactly 18th birthday
    assert calculate_age(date(2008, 10, 29), now_date) == 18
    assert is_child(date(2008, 10, 29), now_date) is False

    # Day before 18th birthday
    assert calculate_age(date(2008, 10, 30), now_date) == 17
    assert is_child(date(2008, 10, 30), now_date) is True


def test_section_9_3_prohibitions_enforced():
    guard = ChildDataGuard()
    child_dob = date(2014, 1, 1)

    # Register consent for general app service
    guard.register_parental_consent(
        child_principal_id="child-101",
        guardian_principal_id="parent-505",
        relationship=GuardianRelationship.PARENT,
        verification_method=VerificationMethod.DIGILOCKER_PARENT_BINDING,
        verification_proof=b"digilocker-aadhaar-xml-signature",
        approved_purposes=["educational_learning"],
    )

    # Prohibited activities must raise ChildProcessingViolation regardless of consent
    for prohibited in ["tracking", "behavioural_monitoring", "targeted_advertising"]:
        with pytest.raises(ChildProcessingViolation, match="strictly prohibited for children"):
            guard.validate_processing(
                child_dob=child_dob,
                child_principal_id="child-101",
                purpose_key="educational_learning",
                activity_type=prohibited,
            )


def test_verifiable_parental_consent_lifecycle():
    guard = ChildDataGuard()
    child_dob = date(2015, 6, 15)

    # Without consent: processing must fail
    with pytest.raises(ChildProcessingViolation, match="No active verifiable parental consent"):
        guard.validate_processing(
            child_dob=child_dob,
            child_principal_id="child-202",
            purpose_key="school_curriculum",
        )

    # Register consent
    record = guard.register_parental_consent(
        child_principal_id="child-202",
        guardian_principal_id="parent-707",
        relationship=GuardianRelationship.LAWFUL_GUARDIAN,
        verification_method=VerificationMethod.GOVT_ID_OTP,
        verification_proof=b"otp-verified-parent-pan",
        approved_purposes=["school_curriculum"],
    )
    assert record.child_principal_id == "child-202"
    assert record.relationship == GuardianRelationship.LAWFUL_GUARDIAN

    # Approved purpose succeeds
    assert guard.validate_processing(
        child_dob=child_dob,
        child_principal_id="child-202",
        purpose_key="school_curriculum",
    ) is True

    # Unapproved purpose fails
    with pytest.raises(ChildProcessingViolation, match="is not approved in verifiable parental consent"):
        guard.validate_processing(
            child_dob=child_dob,
            child_principal_id="child-202",
            purpose_key="commercial_gaming",
        )


def test_expired_parental_consent_fails():
    guard = ChildDataGuard()
    child_dob = date(2015, 1, 1)
    now = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)

    guard.register_parental_consent(
        child_principal_id="child-303",
        guardian_principal_id="parent-808",
        relationship=GuardianRelationship.PARENT,
        verification_method=VerificationMethod.MICRO_PAYMENT_REVERSAL,
        verification_proof=b"upi-token-reversal-ref",
        approved_purposes=["learning"],
        expires_at=now - timedelta(days=1),  # Expired yesterday
    )

    with pytest.raises(ChildProcessingViolation, match="No active verifiable parental consent"):
        guard.validate_processing(
            child_dob=child_dob,
            child_principal_id="child-303",
            purpose_key="learning",
            now=now,
        )


def test_adult_does_not_require_parental_consent():
    guard = ChildDataGuard()
    adult_dob = date(2000, 1, 1)
    # Adults do not need parental consent under Section 9
    assert guard.validate_processing(
        child_dob=adult_dob,
        child_principal_id="adult-999",
        purpose_key="any_purpose",
        activity_type="targeted_advertising",
    ) is True
