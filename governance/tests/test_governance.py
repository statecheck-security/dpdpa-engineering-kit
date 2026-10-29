import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from governance_config import DPDPA_GOVERNANCE_CONFIG
from grievance_service import DPDPAGrievanceService, GrievanceCategory, GrievanceStatus

HERE = Path(__file__).resolve().parent.parent
KIT = HERE.parent


def load_yaml(name):
    return yaml.safe_load((HERE / name).read_text(encoding="utf-8"))


def load_json(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def test_grievance_target_is_within_the_rule_14_ceiling():
    # Rule 14(3): respond within a reasonable period not exceeding ninety days.
    assert DPDPA_GOVERNANCE_CONFIG["grievance_config"]["response_sla_days"] <= 90


def test_sdf_cadences_are_annual():
    # Rule 13(1): an SDF carries out a DPIA and an audit once every twelve months.
    assert DPDPA_GOVERNANCE_CONFIG["dpia_schedule"]["frequency_months"] <= 12
    assert DPDPA_GOVERNANCE_CONFIG["audit_config"]["audit_frequency_months"] <= 12


def test_personal_data_tier_carries_the_dpdpa_controls():
    tiers = {t["level"]: t for t in load_yaml("data-classification.yaml")["data_classification"]["tiers"]}
    personal = set(tiers["personal_data_dpdpa"]["controls"])
    assert {"encryption_at_rest", "encryption_in_transit", "erasure_capability", "audit_logging"} <= personal
    # Each tier keeps every control of the tier below it.
    order = ["public", "internal", "confidential", "personal_data_dpdpa"]
    for lower, higher in zip(order, order[1:], strict=False):
        assert set(tiers[lower]["controls"]) <= set(tiers[higher]["controls"]), (lower, higher)


def test_inventory_entries_name_purpose_processor_and_retention():
    for system in load_yaml("data-inventory.yaml")["data_processing_inventory"]:
        assert all(e["purpose_keys"] for e in system["data_elements"])
        assert all(p["contract_reference"] for p in system["data_processors"])
        assert system["retention_policy"]["default_days"] >= 365  # Rule 8(3) floor for the related logs


def test_residency_policy_points_at_files_that_exist():
    policy = load_yaml("data-residency-policy.yaml")["data_residency_policy"]
    paths = [p for layer in policy["enforcement_layers"] for p in layer.get("implementation", [])]
    assert paths
    for rel in paths:
        assert (KIT / rel).exists(), rel


def test_audit_log_entry_carries_no_raw_identifier():
    entry = load_json("audit-log-entry.json")
    assert entry["principal_id_hash"].startswith("sha256:")
    assert "principal_id" not in entry
    assert {"timestamp", "actor", "action", "resource", "purpose", "outcome"} <= entry.keys()


def test_data_audit_item_has_lawful_ground_and_retention_basis():
    item = load_json("data-audit-item.json")
    assert item["lawful_ground"] and item["retention_basis"]
    assert isinstance(item["cross_border"], bool)


class RecordingAudit:
    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


def test_grievance_registration_assigns_sla_and_acknowledgement():
    audit = RecordingAudit()
    service = DPDPAGrievanceService(audit=audit, sla_days=30)
    now = datetime(2026, 10, 29, 10, 0, tzinfo=timezone.utc)

    ticket = service.register_grievance(
        principal_id="dp-777",
        category=GrievanceCategory.RIGHTS_UNFULFILLED,
        description="Erasure request not fulfilled after 30 days.",
        created_at=now,
    )

    assert ticket.ticket_id.startswith("GRV-2026-")
    assert ticket.status == GrievanceStatus.ACKNOWLEDGED
    assert ticket.sla_due_at == now + timedelta(days=30)
    assert len(audit.events) == 1
    assert audit.events[0]["event"] == "grievance_registered"


def test_grievance_escalation_and_resolution_flow():
    audit = RecordingAudit()
    service = DPDPAGrievanceService(audit=audit)

    ticket = service.register_grievance(
        principal_id="dp-888",
        category="security_breach",
        description="Unrecognized login activity on account.",
    )

    # Escalate to DPO
    escalated = service.escalate_to_dpo(ticket.ticket_id, reason="Potential credential compromise")
    assert escalated.status == GrievanceStatus.ESCALATED_TO_DPO
    assert escalated.escalated_to_dpo_at is not None

    # Resolve grievance
    resolved = service.resolve_grievance(
        ticket.ticket_id,
        resolution_summary="Sessions invalidated, credentials reset, no unauthorized data access occurred.",
    )
    assert resolved.status == GrievanceStatus.RESOLVED
    assert resolved.resolution_summary is not None
    # Section 13(3) advisory must be present
    assert "Data Protection Board of India" in resolved.dpbi_appeal_notice


def test_grievance_sla_breach_detection():
    audit = RecordingAudit()
    service = DPDPAGrievanceService(audit=audit, sla_days=30)
    created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ticket = service.register_grievance(
        principal_id="dp-999",
        category=GrievanceCategory.CONSENT_VIOLATION,
        description="Marketing emails received after consent withdrawal.",
        created_at=created_at,
    )

    # Check status after 45 days (past 30-day SLA)
    status_check = service.check_sla_status(
        ticket.ticket_id, now=created_at + timedelta(days=45)
    )
    assert status_check["sla_breached"] is True
    assert status_check["remaining_days"] == 0

    with pytest.raises(ValueError, match="description cannot be empty"):
        service.register_grievance("dp-1", GrievanceCategory.GENERAL_PROCESSING, "   ")
