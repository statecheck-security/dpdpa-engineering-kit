# Purpose-bound erasure evaluation.
# Closes the gap between SOC 2 P4.2/P4.3 (and ISO 27001 A.8.10) disposal
# controls and DPDPA Section 8(7).
#
# Merges DPDPAErasureService (SOC 2 article) and DPDPADeletionService
# (ISO 27001 article). Changed: the inactivity period is no longer defaulted
# to three years for every purpose. The Third Schedule prescribes that period
# (Rule 8(1)) only for the listed large e-commerce, online-gaming and
# social-media platforms; other Data Fiduciaries set no inactivity trigger.
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


class ErasureTrigger(Enum):
    CONSENT_WITHDRAWAL = "consent_withdrawal"    # Section 6(4)
    PURPOSE_COMPLETION = "purpose_completion"     # Section 8(7)(a)
    INACTIVITY_EXPIRY = "inactivity_expiry"       # Section 8(8), Rule 8(1)
    PRINCIPAL_REQUEST = "principal_request"       # Section 12(3)


@dataclass
class DataRecord:
    principal_id: str
    purpose_key: str
    consent_status: str                       # "GRANTED" | "REVOKED"
    purpose_completed: bool = False
    pending_erasure_request: bool = False
    last_approach_date: datetime | None = None
    last_rights_exercise_date: datetime | None = None


@dataclass
class ErasureEvaluation:
    trigger: ErasureTrigger | None
    requires_legal_hold_check: bool
    cascade_to_processors: bool               # Section 8(7)(b)
    requires_48h_notice: bool = False         # Rule 8(2), before inactivity erasure


class DPDPAErasureService:
    """Evaluates erasure obligations under DPDPA.

    retention_config maps purpose_key -> timedelta for purposes that carry a
    prescribed inactivity period (Third Schedule). Purposes not listed have no
    inactivity trigger. Any erasure must still respect the Rule 8(3) one-year
    minimum for the related logs; that is the legal-hold check's job.
    """

    def __init__(self, retention_config: dict[str, timedelta], processor_registry: list[str]):
        self.retention_config = retention_config
        self.processor_registry = processor_registry

    def evaluate(self, record: DataRecord, now: datetime | None = None) -> ErasureEvaluation:
        now = now or datetime.now(timezone.utc)

        # Trigger 1: Consent withdrawn (Section 6(4) + 8(7)(a))
        if record.consent_status == "REVOKED":
            return self._erase(ErasureTrigger.CONSENT_WITHDRAWAL)

        # Trigger 2: Data Principal request (Section 12(3))
        if record.pending_erasure_request:
            return self._erase(ErasureTrigger.PRINCIPAL_REQUEST)

        # Trigger 3: Purpose no longer served (Section 8(7)(a))
        if record.purpose_completed:
            return self._erase(ErasureTrigger.PURPOSE_COMPLETION)

        # Trigger 4: Inactivity-based expiry (Section 8(8)), only where prescribed
        prescribed_period = self.retention_config.get(record.purpose_key)
        if prescribed_period is not None:
            floor = datetime.min.replace(tzinfo=timezone.utc)
            last_activity = max(
                record.last_approach_date or floor,
                record.last_rights_exercise_date or floor,
            )
            if (now - last_activity) > prescribed_period:
                evaluation = self._erase(ErasureTrigger.INACTIVITY_EXPIRY)
                evaluation.requires_48h_notice = True
                return evaluation

        return ErasureEvaluation(trigger=None, requires_legal_hold_check=False, cascade_to_processors=False)

    def _erase(self, trigger: ErasureTrigger) -> ErasureEvaluation:
        return ErasureEvaluation(
            trigger=trigger,
            requires_legal_hold_check=True,   # S.8(7) exception for retention required by law
            cascade_to_processors=bool(self.processor_registry),
        )
