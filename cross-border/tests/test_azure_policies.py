"""Structural checks for the Azure Policy definitions, plus a small evaluator for their `if` blocks."""
import fnmatch
import json
from pathlib import Path

import pytest

AZURE = Path(__file__).resolve().parent.parent / "azure"
INDIA_REGIONS = {"centralindia", "southindia", "westindia"}


def load(name):
    return json.loads((AZURE / name).read_text(encoding="utf-8"))


def _value(resource, field):
    if field.startswith("tags['"):
        return resource.get("tags", {}).get(field[6:-2])
    return resource.get(field)


def evaluate(cond, resource) -> bool:
    """Evaluates the subset of Azure Policy condition syntax these definitions use."""
    if "allOf" in cond:
        return all(evaluate(c, resource) for c in cond["allOf"])
    if "anyOf" in cond:
        return any(evaluate(c, resource) for c in cond["anyOf"])
    if "not" in cond:
        return not evaluate(cond["not"], resource)
    value = _value(resource, cond["field"])
    if "equals" in cond:
        return str(value).lower() == str(cond["equals"]).lower()
    if "notEquals" in cond:
        return str(value).lower() != str(cond["notEquals"]).lower()
    if "in" in cond:
        return value in cond["in"]
    if "like" in cond:
        return fnmatch.fnmatch(str(value), cond["like"])
    raise NotImplementedError(cond)


@pytest.mark.parametrize("name", sorted(p.name for p in AZURE.glob("*.json")))
def test_definition_shape(name):
    d = load(name)
    assert d["mode"] in {"All", "Indexed"}
    assert set(d["policyRule"]) == {"if", "then"}
    assert d["policyRule"]["then"]["effect"] in {"deny", "audit", "Deny", "Audit"}


def test_location_policy_only_allows_indian_regions():
    rule = load("deny-non-india-locations.json")["policyRule"]["if"]
    location = next(c["not"] for c in rule["allOf"] if "not" in c)
    assert set(location["in"]) == INDIA_REGIONS


@pytest.mark.parametrize(
    "resource, denied",
    [
        ({"type": "Microsoft.Storage/storageAccounts", "location": "eastus",
          "tags": {"data-residency": "india"}}, True),
        ({"type": "Microsoft.Storage/storageAccounts", "location": "centralindia",
          "tags": {"data-residency": "india"}}, False),
        ({"type": "Microsoft.Storage/storageAccounts", "location": "eastus", "tags": {}}, False),  # not tagged
        ({"type": "Microsoft.Web/sites", "location": "eastus", "tags": {"data-residency": "india"}}, False),
    ],
)
def test_location_policy_decisions(resource, denied):
    assert evaluate(load("deny-non-india-locations.json")["policyRule"]["if"], resource) is denied


@pytest.mark.parametrize(
    "key_source, denied",
    [("Microsoft.Storage", True), ("Microsoft.Keyvault", False)],
)
def test_cmk_policy_decisions(key_source, denied):
    resource = {
        "type": "Microsoft.Storage/storageAccounts",
        "tags": {"data-residency": "india"},
        "Microsoft.Storage/storageAccounts/encryption.keySource": key_source,
    }
    assert evaluate(load("require-cmk-storage.json")["policyRule"]["if"], resource) is denied
