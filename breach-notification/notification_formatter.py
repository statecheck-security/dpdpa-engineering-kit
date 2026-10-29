"""
notification_formatter.py

Implements statutory personal data breach intimation formatting required by
DPDPA Section 8(6) and DPDP Rules, 2025 Rule 7.

When a breach is confirmed under Section 2(u), the Data Fiduciary must intimate:
  (1) The Data Protection Board of India (DPBI) per Rule 7(1)
  (2) Each affected Data Principal per Rule 7(2)
"""
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class DataCategory(Enum):
    IDENTITY = "identity"              # name, DOB, government IDs
    CONTACT = "contact"                # email, phone, address
    FINANCIAL = "financial"            # bank accounts, card numbers, transaction history
    HEALTH = "health"                  # medical records, biometrics
    CREDENTIALS = "credentials"        # passwords, tokens, API keys
    BEHAVIORAL = "behavioral"          # browsing, location history


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DPOContact:
    name: str
    email: str
    phone: str
    postal_address: str


@dataclass
class BoardIntimation:
    """Intimation to the Data Protection Board of India under Rule 7(1)."""
    intimation_id: str
    incident_id: str
    breach_type: str
    detected_at: str
    occurred_at: str | None
    data_categories: list[str]
    estimated_affected_principals: int
    consequences_and_risks: str
    risk_level: str
    mitigation_measures_taken: list[str]
    mitigation_measures_planned: list[str]
    safety_steps_advised_to_principals: list[str]
    dpo_contact: dict
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "intimation_id": self.intimation_id,
            "incident_id": self.incident_id,
            "breach_type": self.breach_type,
            "detected_at": self.detected_at,
            "occurred_at": self.occurred_at,
            "data_categories": self.data_categories,
            "estimated_affected_principals": self.estimated_affected_principals,
            "consequences_and_risks": self.consequences_and_risks,
            "risk_level": self.risk_level,
            "mitigation_measures_taken": self.mitigation_measures_taken,
            "mitigation_measures_planned": self.mitigation_measures_planned,
            "safety_steps_advised_to_principals": self.safety_steps_advised_to_principals,
            "dpo_contact": self.dpo_contact,
            "generated_at": self.generated_at,
        }


@dataclass
class PrincipalIntimation:
    """Intimation to an affected Data Principal under Rule 7(2)."""
    notice_id: str
    principal_id: str
    description: str
    compromised_categories: list[str]
    mitigation_measures: list[str]
    recommended_safety_steps: list[str]
    dpo_contact: dict
    language_code: str
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "notice_id": self.notice_id,
            "principal_id": self.principal_id,
            "description": self.description,
            "compromised_categories": self.compromised_categories,
            "mitigation_measures": self.mitigation_measures,
            "recommended_safety_steps": self.recommended_safety_steps,
            "dpo_contact": self.dpo_contact,
            "language_code": self.language_code,
            "timestamp": self.timestamp,
        }


class BreachIntimationBuilder:
    """Constructs and validates breach intimations satisfying DPDPA Section 8(6) & Rule 7."""

    def __init__(self, dpo_contact: DPOContact):
        self.dpo = dpo_contact

    def build_board_intimation(
        self,
        incident_id: str,
        breach_type: str,
        data_categories: list[DataCategory | str],
        estimated_affected: int,
        consequences: str,
        risk_level: RiskLevel | str,
        mitigation_taken: list[str],
        mitigation_planned: list[str] | None = None,
        safety_steps_advised: list[str] | None = None,
        detected_at: datetime | None = None,
        occurred_at: datetime | None = None,
    ) -> BoardIntimation:
        if estimated_affected < 0:
            raise ValueError("estimated_affected_principals cannot be negative")
        if not data_categories:
            raise ValueError("At least one data category must be specified under Rule 7(1)")
        if not mitigation_taken:
            raise ValueError("Mitigation measures taken must be documented under Rule 7(1)")

        now = datetime.now(timezone.utc)
        cat_strings = [c.value if isinstance(c, DataCategory) else str(c) for c in data_categories]
        risk_str = risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level)

        return BoardIntimation(
            intimation_id=str(uuid.uuid4()),
            incident_id=incident_id,
            breach_type=breach_type,
            detected_at=(detected_at or now).isoformat(),
            occurred_at=occurred_at.isoformat() if occurred_at else None,
            data_categories=cat_strings,
            estimated_affected_principals=estimated_affected,
            consequences_and_risks=consequences,
            risk_level=risk_str,
            mitigation_measures_taken=mitigation_taken,
            mitigation_measures_planned=mitigation_planned or [],
            safety_steps_advised_to_principals=safety_steps_advised or [],
            dpo_contact={
                "name": self.dpo.name,
                "email": self.dpo.email,
                "phone": self.dpo.phone,
                "address": self.dpo.postal_address,
            },
            generated_at=now.isoformat(),
        )

    def build_principal_intimation(
        self,
        principal_id: str,
        description: str,
        compromised_categories: list[DataCategory | str],
        mitigation_measures: list[str],
        recommended_safety_steps: list[str],
        language_code: str = "en",
    ) -> PrincipalIntimation:
        if not compromised_categories:
            raise ValueError("Compromised categories must be declared under Rule 7(2)")
        if not recommended_safety_steps:
            raise ValueError("Recommended safety steps for principal must be provided under Rule 7(2)")

        cat_strings = [c.value if isinstance(c, DataCategory) else str(c) for c in compromised_categories]

        return PrincipalIntimation(
            notice_id=str(uuid.uuid4()),
            principal_id=principal_id,
            description=description,
            compromised_categories=cat_strings,
            mitigation_measures=mitigation_measures,
            recommended_safety_steps=recommended_safety_steps,
            dpo_contact={
                "name": self.dpo.name,
                "email": self.dpo.email,
                "phone": self.dpo.phone,
            },
            language_code=language_code,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
