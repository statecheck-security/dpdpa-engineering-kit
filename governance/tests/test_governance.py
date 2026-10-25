import json
from pathlib import Path

import yaml
from governance_config import DPDPA_GOVERNANCE_CONFIG

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
