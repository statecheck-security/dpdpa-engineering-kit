import json
from pathlib import Path

import pytest
from transfer_governance import TransferDecision, TransferPolicyEngine, TransferRequest

HERE = Path(__file__).resolve().parent.parent
CONFIG = HERE / "transfer-policy.json"


@pytest.fixture
def engine():
    return TransferPolicyEngine(str(CONFIG))


def req(**overrides) -> TransferRequest:
    base = dict(
        source_region="ap-south-1",
        destination_region="us-east-1",
        data_classification="personal_data",
        data_subject_jurisdiction="IN",
        processor_has_scc=False,
        processor_has_dpa=True,
    )
    base.update(overrides)
    return TransferRequest(**base)


def test_dpdpa_transfer_with_processor_contract_is_permitted(engine):
    # Section 16 is a negative list, and no country is on it yet.
    assert engine.evaluate(req()) is TransferDecision.PERMITTED


def test_missing_processor_contract_needs_review(engine):
    assert engine.evaluate(req(processor_has_dpa=False)) is TransferDecision.REQUIRES_REVIEW


def test_rbi_payment_data_cannot_leave_india(engine):
    assert engine.evaluate(req(sectoral_regulator="RBI")) is TransferDecision.BLOCKED
    assert engine.evaluate(req(sectoral_regulator="RBI", destination_region="ap-south-2")) is TransferDecision.PERMITTED


def test_sdf_specified_data_needs_review(engine):
    decision = engine.evaluate(req(is_sdf=True, data_classification="sdf_specified_data"))
    assert decision is TransferDecision.REQUIRES_REVIEW


def test_restricted_destination_is_blocked(tmp_path):
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["dpdpa_restricted_destinations"] = ["US"]
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    assert TransferPolicyEngine(str(path)).evaluate(req()) is TransferDecision.BLOCKED


def test_gdpr_adequate_destination_is_permitted(engine):
    decision = engine.evaluate(req(source_region="eu-west-1", destination_region="eu-central-1",
                                   data_subject_jurisdiction="EU"))
    assert decision is TransferDecision.PERMITTED


def test_gdpr_non_adequate_destination_needs_scc(engine):
    eu_to_us = dict(source_region="eu-west-1", data_subject_jurisdiction="EU")
    assert engine.evaluate(req(**eu_to_us)) is TransferDecision.BLOCKED
    assert engine.evaluate(req(**eu_to_us, processor_has_scc=True)) is TransferDecision.REQUIRES_SCC


def test_both_regimes_return_the_most_restrictive_decision(engine):
    # DPDPA alone permits this; GDPR blocks it without SCCs.
    assert engine.evaluate(req(data_subject_jurisdiction="BOTH")) is TransferDecision.BLOCKED
    # With SCCs GDPR only asks for them, so that is the overall answer.
    decision = engine.evaluate(req(data_subject_jurisdiction="BOTH", processor_has_scc=True))
    assert decision is TransferDecision.REQUIRES_SCC


def test_unknown_region_is_not_treated_as_india(engine):
    assert engine._region_to_country("ap-southeast-1") == "UNKNOWN"
    # An unmapped destination must not slip past RBI localisation.
    blocked = engine.evaluate(req(sectoral_regulator="RBI", destination_region="ap-southeast-1"))
    assert blocked is TransferDecision.BLOCKED


def test_adequacy_list_matches_the_commission():
    """European Commission adequacy decisions, checked 25 Oct 2026. The US is left out on purpose:
    its adequacy covers only organisations certified under the EU-US Data Privacy Framework."""
    listed = set(json.loads(CONFIG.read_text(encoding="utf-8"))["gdpr_adequate_countries"])
    assert listed == {"EU", "AD", "AR", "BR", "CA", "FO", "GG", "IL", "IM", "JP", "JE", "NZ", "KR", "CH", "GB", "UY"}
    assert "IN" not in listed
