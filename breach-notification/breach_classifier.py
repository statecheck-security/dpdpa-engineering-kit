# DPDPA breach classifier (simplified)
"""
dpdpa_breach_classifier.py
Applies the Section 2(u) test to a confirmed security incident.
Section 2(u): unauthorised processing OR accidental disclosure /
acquisition / sharing / use / alteration / destruction /
loss of access — that compromises CIA of personal data.
"""

from enum import Enum


class BreachType(Enum):
    UNAUTHORISED_ACQUISITION = "unauthorised_acquisition"  # exfiltration
    ACCIDENTAL_DISCLOSURE    = "accidental_disclosure"
    UNAUTHORISED_ALTERATION  = "unauthorised_alteration"   # integrity
    LOSS_OF_ACCESS           = "loss_of_access"             # availability
    DESTRUCTION              = "destruction"
    UNAUTHORISED_USE         = "unauthorised_use"

class ClassificationResult(Enum):
    CONFIRMED_BREACH     = "confirmed_breach"
    NOT_A_BREACH         = "not_a_breach"
    ESCALATE_TO_DPO      = "escalate_to_dpo"

ACTION_MAP = {
    "exfiltration":         BreachType.UNAUTHORISED_ACQUISITION,
    "data_leak":            BreachType.ACCIDENTAL_DISCLOSURE,
    "unauthorised_access":  BreachType.UNAUTHORISED_USE,
    "data_modification":    BreachType.UNAUTHORISED_ALTERATION,
    "data_deletion":        BreachType.DESTRUCTION,
    "ransomware":           BreachType.LOSS_OF_ACCESS,
    # Action names emitted by the SIEM rule in savedsearches.conf (lowercased)
    "dataexfiltration":     BreachType.UNAUTHORISED_ACQUISITION,
    "unauthorizedaccess":   BreachType.UNAUTHORISED_USE,
    "datamodification":     BreachType.UNAUTHORISED_ALTERATION,
    "datadeletion":         BreachType.DESTRUCTION,
}

def classify(incident: dict) -> ClassificationResult:
    # Gate 1: Does it involve personal data?
    if not incident.get("contains_personal_data"):
        return ClassificationResult.NOT_A_BREACH

    # Gate 2: Was access authorised?
    if incident.get("is_authorised"):
        return ClassificationResult.NOT_A_BREACH

    # Gate 3: Can we classify the breach type?
    action = incident.get("action", "").lower()
    breach_type = ACTION_MAP.get(action)

    if breach_type is None:
        return ClassificationResult.ESCALATE_TO_DPO  # DPO triage

    return ClassificationResult.CONFIRMED_BREACH
