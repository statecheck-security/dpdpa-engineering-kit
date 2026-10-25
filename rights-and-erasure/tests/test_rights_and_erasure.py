from datetime import datetime, timedelta, timezone

import pytest
from erasure_triggers import DataRecord, DPDPAErasureService, ErasureTrigger
from rights_service import DPDPARightsService, InMemoryInventory

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
THREE_YEARS = timedelta(days=1095)


def record(**overrides):
    base = dict(principal_id="dp-1", purpose_key="marketplace_account", consent_status="GRANTED",
                last_approach_date=NOW - timedelta(days=30))
    base.update(overrides)
    return DataRecord(**base)


class TestErasureTriggers:
    @pytest.fixture
    def service(self):
        # Only the listed-platform purpose carries the Third Schedule period.
        return DPDPAErasureService({"marketplace_account": THREE_YEARS}, processor_registry=["ShipRocket"])

    def test_active_customer_is_not_erased(self, service):
        assert service.evaluate(record(), now=NOW).trigger is None

    @pytest.mark.parametrize(
        "overrides, trigger",
        [
            ({"consent_status": "REVOKED"}, ErasureTrigger.CONSENT_WITHDRAWAL),
            ({"pending_erasure_request": True}, ErasureTrigger.PRINCIPAL_REQUEST),
            ({"purpose_completed": True}, ErasureTrigger.PURPOSE_COMPLETION),
        ],
    )
    def test_explicit_triggers(self, service, overrides, trigger):
        evaluation = service.evaluate(record(**overrides), now=NOW)
        assert evaluation.trigger is trigger
        assert evaluation.requires_legal_hold_check
        assert evaluation.cascade_to_processors
        assert not evaluation.requires_48h_notice

    def test_inactivity_past_the_prescribed_period_needs_48h_notice(self, service):
        evaluation = service.evaluate(record(last_approach_date=NOW - timedelta(days=1100)), now=NOW)
        assert evaluation.trigger is ErasureTrigger.INACTIVITY_EXPIRY
        assert evaluation.requires_48h_notice

    def test_recent_rights_exercise_resets_inactivity(self, service):
        r = record(last_approach_date=NOW - timedelta(days=1100), last_rights_exercise_date=NOW - timedelta(days=10))
        assert service.evaluate(r, now=NOW).trigger is None

    def test_purpose_without_a_prescribed_period_never_expires_on_inactivity(self, service):
        """The SOC 2 article defaulted every purpose to three years; the Third Schedule does not."""
        r = record(purpose_key="newsletter", last_approach_date=NOW - timedelta(days=4000))
        assert service.evaluate(r, now=NOW).trigger is None

    def test_no_processors_means_no_cascade(self):
        service = DPDPAErasureService({}, processor_registry=[])
        assert not service.evaluate(record(consent_status="REVOKED"), now=NOW).cascade_to_processors


class RecordingAudit:
    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


@pytest.fixture
def rights():
    inventory = InMemoryInventory(
        systems={
            "crm": {"system_name": "CRM", "purposes": ["support"],
                    "data": {"dp-1": [{"field": "email", "value": "asha@example.in"}]}},
            "billing": {"system_name": "Billing", "purposes": ["invoicing"],
                        "data": {"dp-1": [{"field": "gstin", "value": "29ABCDE1234F1Z5"}]}},
            "analytics": {"system_name": "Analytics", "purposes": ["product"], "data": {"dp-2": []}},
        },
        sharing={"dp-1": [{"name": "ShipRocket", "role": "data_processor"}]},
        holds={"dp-1": {"billing"}},  # tax law keeps invoices
    )
    audit = RecordingAudit()
    return DPDPARightsService(inventory, audit), inventory, audit


def test_access_request_lists_data_purposes_and_recipients(rights):
    service, _, _ = rights
    resp = service.handle_access_request("dp-1")
    assert resp["status"] == "completed"
    assert {s["system"] for s in resp["data_summary"]} == {"CRM", "Billing"}
    assert resp["processors_and_fiduciaries"] == [{"name": "ShipRocket", "role": "data_processor"}]


def test_erasure_respects_legal_holds_and_says_so(rights):
    service, inventory, audit = rights
    resp = service.handle_erasure_request("dp-1", "principal_request")
    assert resp["status"] == "partially_completed"
    assert (resp["systems_erased"], resp["retention_holds"]) == (1, 1)
    assert "dp-1" not in inventory.systems["crm"]["data"]
    assert "dp-1" in inventory.systems["billing"]["data"]
    (event,) = audit.events
    assert event["systems"] == ["crm"]
    assert "asha@example.in" not in str(event)


def test_erasure_without_holds_is_completed(rights):
    service, inventory, _ = rights
    inventory.holds.clear()
    assert service.handle_erasure_request("dp-1", "consent_withdrawal")["status"] == "completed"
