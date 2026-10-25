import re
from pathlib import Path

import pytest
from breach_classifier import ClassificationResult, classify

HERE = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    "incident, expected",
    [
        ({"contains_personal_data": False, "action": "exfiltration"}, ClassificationResult.NOT_A_BREACH),
        ({"contains_personal_data": True, "is_authorised": True, "action": "data_deletion"},
         ClassificationResult.NOT_A_BREACH),
        ({"contains_personal_data": True, "action": "exfiltration"}, ClassificationResult.CONFIRMED_BREACH),
        ({"contains_personal_data": True, "action": "Ransomware"}, ClassificationResult.CONFIRMED_BREACH),
        ({"contains_personal_data": True, "action": "port_scan"}, ClassificationResult.ESCALATE_TO_DPO),
        ({"contains_personal_data": True}, ClassificationResult.ESCALATE_TO_DPO),
    ],
)
def test_section_2u_gates(incident, expected):
    assert classify(incident) is expected


@pytest.mark.parametrize("siem_action", ["DataExfiltration", "UnauthorizedAccess", "DataModification", "DataDeletion"])
def test_every_siem_action_is_classified_without_escalation(siem_action):
    """The SIEM rule and the classifier must agree on action names."""
    assert classify({"contains_personal_data": True, "action": siem_action}) is ClassificationResult.CONFIRMED_BREACH


def _conf_stanzas(text: str) -> dict:
    """Parse a Splunk .conf file the way Splunk does: whole-line comments, backslash continuations."""
    stanzas, current, key, buf = {}, None, None, []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if key is not None:  # inside a continued value
            assert not line.lstrip().startswith("#"), f"line {lineno}: comment inside a multi-line value"
            buf.append(line[:-1] if line.endswith("\\") else line)
            if not line.endswith("\\"):
                stanzas[current][key] = "\n".join(buf)
                key = None
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if m := re.fullmatch(r"\[(.+)\]", line.strip()):
            current = m.group(1)
            stanzas[current] = {}
            continue
        k, sep, v = line.partition("=")
        assert sep, f"line {lineno}: expected key = value"
        k, v = k.strip(), v.strip()
        if v.endswith("\\"):
            key, buf = k, [v[:-1]]
        else:
            stanzas[current][k] = v
    assert key is None, "file ends inside a continued value"
    return stanzas


def test_savedsearch_is_valid_conf_and_matches_the_classifier():
    stanza = _conf_stanzas((HERE / "savedsearches.conf").read_text(encoding="utf-8"))["dpdpa_breach_detection"]
    search = stanza["search"]
    assert search.startswith("index=security")
    assert "#" not in search, "SPL has no # comments; use ``` ... ```"
    assert search.count("```") % 2 == 0
    assert search.count("(") == search.count(")")
    assert stanza["action.webhook"] == "1"
    assert stanza["action.webhook.param.url"].startswith("https://")

    for action in re.findall(r"action=(\w+)", search):
        if action != "AccessDenied_Anomalous":  # availability signal; deliberately left for DPO triage
            result = classify({"contains_personal_data": True, "action": action})
            assert result is ClassificationResult.CONFIRMED_BREACH, action
