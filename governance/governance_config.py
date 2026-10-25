# Governance configuration (implements GV.PO-P1, GV.PO-P5 + Section 8(4))
# Enforced via policy engine (e.g., OPA/Rego, AWS Config Rules)

DPDPA_GOVERNANCE_CONFIG = {
    "regulatory_framework": "DPDPA_2023",
    "rules_version": "DPDP_Rules_2025",

    # GV.PO-P3 + Section 10(2)(a): DPO Configuration
    "dpo_config": {
        "required": True,  # Set True if notified as SDF
        "jurisdiction": "IN",
        "reports_to": "board_of_directors",
        "contact_published": True,
    },

    # GV.MT-P1 + Section 10(2)(c): DPIA Schedule
    "dpia_schedule": {
        "frequency_months": 12,
        "trigger_events": [
            "new_processing_activity",
            "significant_change_to_existing",
            "new_data_processor_engagement",
        ],
        "assessor": "independent",  # SDF requirement
    },

    # GV.MT-P3 + Section 10(2)(b): Audit Configuration
    "audit_config": {
        "independent_audit_required": True,  # SDF requirement
        "audit_frequency_months": 12,
        "audit_scope": [
            "consent_management",
            "security_safeguards",
            "data_principal_rights",
            "breach_notification_readiness",
            "data_processor_governance",
        ],
    },

    # GV.MT-P7 + Section 13: Grievance Mechanism
    "grievance_config": {
        "mechanism_type": "web_portal_and_email",
        "response_sla_days": 30,  # Internal target; Rule 14(3) ceiling is 90 days
        "escalation_to_board": True,
        "published_in_notice": True,
    },
}
