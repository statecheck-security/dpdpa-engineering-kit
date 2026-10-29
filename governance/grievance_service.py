"""
grievance_service.py

Implements statutory Grievance Redressal Mechanism required by DPDPA Section 13
and DPDP Rules, 2025 Rule 14.

Statutory Obligations:
  - Section 13(1): Right of grievance redressal for Data Principals against acts/omissions
    of Data Fiduciary or Consent Manager.
  - Section 13(2): Mandatory response within prescribed SLA (ceiling: 90 days; default: 30 days).
  - Section 13(3): Data Principal may register grievance before approaching the Data Protection
    Board of India (DPBI). Every resolution notice must advise of this statutory appeal right.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum


class GrievanceCategory(Enum):
    CONSENT_VIOLATION = "consent_violation"
    RIGHTS_UNFULFILLED = "rights_unfulfilled"
    SECURITY_BREACH = "security_breach"
    CHILD_DATA_PROTECTION = "child_data_protection"
    CROSS_BORDER_TRANSFER = "cross_border_transfer"
    GENERAL_PROCESSING = "general_processing"


class GrievanceStatus(Enum):
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    IN_INVESTIGATION = "in_investigation"
    ESCALATED_TO_DPO = "escalated_to_dpo"
    RESOLVED = "resolved"
    REJECTED = "rejected"


DPBI_APPEAL_ADVISORY = (
    "In accordance with Section 13(3) and Section 27(1) of the Digital Personal Data "
    "Protection Act, 2023, if you are not satisfied with this resolution or have not "
    "received a response within the prescribed period, you have the right to register a "
    "complaint with the Data Protection Board of India (DPBI)."
)


@dataclass
class GrievanceTicket:
    ticket_id: str
    principal_id: str
    category: GrievanceCategory
    description: str
    status: GrievanceStatus
    created_at: datetime
    acknowledged_at: datetime
    sla_due_at: datetime
    resolution_summary: str | None = None
    resolved_at: datetime | None = None
    escalated_to_dpo_at: datetime | None = None
    dpbi_appeal_notice: str = DPBI_APPEAL_ADVISORY


class AuditSink:
    def write(self, event: dict) -> None:
        pass


@dataclass
class DPDPAGrievanceService:
    audit: AuditSink
    sla_days: int = 30  # Default 30 days per internal SLA; ceiling is 90 days (Rule 14(3))
    tickets: dict[str, GrievanceTicket] = field(default_factory=dict)

    def register_grievance(
        self,
        principal_id: str,
        category: GrievanceCategory | str,
        description: str,
        created_at: datetime | None = None,
    ) -> GrievanceTicket:
        if not description.strip():
            raise ValueError("Grievance description cannot be empty")

        now = created_at or datetime.now(timezone.utc)
        cat_enum = category if isinstance(category, GrievanceCategory) else GrievanceCategory(category)
        ticket_id = f"GRV-{now.year}-{uuid.uuid4().hex[:8].upper()}"

        ticket = GrievanceTicket(
            ticket_id=ticket_id,
            principal_id=principal_id,
            category=cat_enum,
            description=description,
            status=GrievanceStatus.ACKNOWLEDGED,
            created_at=now,
            acknowledged_at=now,  # Acknowledged immediately upon submission (Rule 14(1))
            sla_due_at=now + timedelta(days=self.sla_days),
        )
        self.tickets[ticket_id] = ticket

        self.audit.write({
            "event": "grievance_registered",
            "ticket_id": ticket_id,
            "principal_id": principal_id,
            "category": cat_enum.value,
            "sla_due_at": ticket.sla_due_at.isoformat(),
            "at": now.isoformat(),
        })

        return ticket

    def escalate_to_dpo(self, ticket_id: str, reason: str) -> GrievanceTicket:
        ticket = self._get_ticket(ticket_id)
        now = datetime.now(timezone.utc)
        ticket.status = GrievanceStatus.ESCALATED_TO_DPO
        ticket.escalated_to_dpo_at = now

        self.audit.write({
            "event": "grievance_escalated_to_dpo",
            "ticket_id": ticket_id,
            "principal_id": ticket.principal_id,
            "reason": reason,
            "at": now.isoformat(),
        })
        return ticket

    def resolve_grievance(self, ticket_id: str, resolution_summary: str) -> GrievanceTicket:
        if not resolution_summary.strip():
            raise ValueError("Resolution summary cannot be empty")

        ticket = self._get_ticket(ticket_id)
        now = datetime.now(timezone.utc)
        ticket.status = GrievanceStatus.RESOLVED
        ticket.resolution_summary = resolution_summary
        ticket.resolved_at = now

        self.audit.write({
            "event": "grievance_resolved",
            "ticket_id": ticket_id,
            "principal_id": ticket.principal_id,
            "sla_breached": now > ticket.sla_due_at,
            "at": now.isoformat(),
        })
        return ticket

    def check_sla_status(self, ticket_id: str, now: datetime | None = None) -> dict:
        ticket = self._get_ticket(ticket_id)
        current = now or datetime.now(timezone.utc)
        breached = current > ticket.sla_due_at and ticket.status != GrievanceStatus.RESOLVED
        remaining_seconds = max(0.0, (ticket.sla_due_at - current).total_seconds())

        return {
            "ticket_id": ticket_id,
            "status": ticket.status.value,
            "sla_due_at": ticket.sla_due_at.isoformat(),
            "sla_breached": breached,
            "remaining_days": int(remaining_seconds // 86400),
        }

    def _get_ticket(self, ticket_id: str) -> GrievanceTicket:
        if ticket_id not in self.tickets:
            raise KeyError(f"Grievance ticket '{ticket_id}' not found")
        return self.tickets[ticket_id]
