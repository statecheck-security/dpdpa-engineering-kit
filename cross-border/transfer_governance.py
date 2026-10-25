# transfer_governance.py
# Policy engine for cross-border data transfer decisions
# Supports both GDPR SCC requirements and DPDPA Section 16 restrictions

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger("transfer_governance")


class Regime(Enum):
    GDPR = "gdpr"
    DPDPA = "dpdpa"
    BOTH = "both"


class TransferDecision(Enum):
    PERMITTED = "permitted"
    BLOCKED = "blocked"
    REQUIRES_SCC = "requires_scc"
    REQUIRES_REVIEW = "requires_review"


@dataclass
class TransferRequest:
    source_region: str          # e.g., "ap-south-1", "eu-west-1"
    destination_region: str     # e.g., "us-east-1", "eu-central-1"
    data_classification: str    # e.g., "personal_data", "sdf_specified_data" (Rule 13(4))
    data_subject_jurisdiction: str  # "IN", "EU", "BOTH"
    processor_has_scc: bool
    processor_has_dpa: bool     # DPDPA-compliant Data Processing Agreement
    sectoral_regulator: Optional[str] = None  # "RBI", "SEBI", etc.
    is_sdf: bool = False        # Significant Data Fiduciary


class TransferPolicyEngine:
    def __init__(self, config_path: str):
        """
        Load transfer policies from a configuration file.
        The restricted_destinations list is updated via CI/CD
        when MeitY publishes new notifications.
        """
        with open(config_path) as f:
            self.config = json.load(f)
        self.dpdpa_restricted = set(
            self.config.get("dpdpa_restricted_destinations", [])
        )
        self.gdpr_adequate = set(
            self.config.get("gdpr_adequate_countries", [])
        )
        self.sectoral_rules = self.config.get("sectoral_rules", {})

    def evaluate(self, request: TransferRequest) -> TransferDecision:
        """Evaluate a transfer request against all applicable regimes."""
        decisions = []

        if request.data_subject_jurisdiction in ("IN", "BOTH"):
            decisions.append(self._evaluate_dpdpa(request))

        if request.data_subject_jurisdiction in ("EU", "BOTH"):
            decisions.append(self._evaluate_gdpr(request))

        # Return the most restrictive decision
        if TransferDecision.BLOCKED in decisions:
            return TransferDecision.BLOCKED
        if TransferDecision.REQUIRES_REVIEW in decisions:
            return TransferDecision.REQUIRES_REVIEW
        if TransferDecision.REQUIRES_SCC in decisions:
            return TransferDecision.REQUIRES_SCC
        return TransferDecision.PERMITTED

    def _evaluate_dpdpa(self, req: TransferRequest) -> TransferDecision:
        """Apply DPDPA Section 16 / Rule 15 logic."""
        dest_country = self._region_to_country(req.destination_region)

        # Check negative list
        if dest_country in self.dpdpa_restricted:
            logger.warning(
                f"Transfer to {dest_country} blocked by DPDPA restriction"
            )
            return TransferDecision.BLOCKED

        # Check sectoral overrides (RBI, SEBI, etc.)
        if req.sectoral_regulator:
            rule = self.sectoral_rules.get(req.sectoral_regulator, {})
            if rule.get("localisation_required", False):
                if dest_country != "IN":
                    return TransferDecision.BLOCKED

        # SDF localisation: personal data specified by the Central Government under Rule 13(4)
        # (DPDPA has no "sensitive personal data" category)
        if req.is_sdf and req.data_classification == "sdf_specified_data":
            return TransferDecision.REQUIRES_REVIEW

        # Valid processor contract (Section 8(2)) with security-safeguard provision (Rule 6(1)(f))
        if not req.processor_has_dpa:
            return TransferDecision.REQUIRES_REVIEW

        return TransferDecision.PERMITTED

    def _evaluate_gdpr(self, req: TransferRequest) -> TransferDecision:
        """Apply GDPR Chapter V transfer rules."""
        dest_country = self._region_to_country(req.destination_region)

        # Adequacy check
        if dest_country in self.gdpr_adequate:
            return TransferDecision.PERMITTED

        # SCC check
        if req.processor_has_scc:
            return TransferDecision.REQUIRES_SCC  # TIA still needed

        return TransferDecision.BLOCKED

    def _region_to_country(self, region: str) -> str:
        """Map cloud region identifiers to country codes."""
        region_map = {
            "ap-south-1": "IN", "ap-south-2": "IN",
            "centralindia": "IN", "southindia": "IN",
            "eu-west-1": "EU", "eu-central-1": "EU",
            "westeurope": "EU", "northeurope": "EU",
            "us-east-1": "US", "us-west-2": "US",
            "eastus": "US", "westus2": "US",
        }
        return region_map.get(region, "UNKNOWN")
