-- DPDPA-compliant consent audit table
-- Extends SOC 2 P2.1 with verifiable, immutable consent records
CREATE TABLE consent_audit_log (
    audit_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_principal_id UUID NOT NULL,
    purpose_key     VARCHAR(100) NOT NULL,  -- e.g., 'analytics', 'marketing'
    action          VARCHAR(20) NOT NULL     -- 'GRANTED', 'REVOKED', 'MODIFIED'
        CHECK (action IN ('GRANTED', 'REVOKED', 'MODIFIED')),
    notice_version  VARCHAR(20) NOT NULL,    -- ties to specific privacy notice
    notice_language VARCHAR(10) NOT NULL,    -- ISO 639-1 code (e.g., 'hi', 'ta')
    ip_address      INET,
    user_agent      TEXT,
    consent_source  VARCHAR(50) NOT NULL     -- 'web_form', 'api', 'consent_manager'
        CHECK (consent_source IN ('web_form', 'api', 'consent_manager', 'in_app')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Immutability: no UPDATE or DELETE allowed on this table
-- Enforce via database role permissions or append-only event store.
-- app_service_role must exist and must not own the table (an owner keeps every
-- privilege). Grant only what an append-only log needs; REVOKE alone removes
-- privileges the role usually never had. For protection against the owner and
-- superusers too, add the trigger from consent-manager/ledger.sql.
REVOKE ALL ON consent_audit_log FROM PUBLIC;
GRANT SELECT, INSERT ON consent_audit_log TO app_service_role;
REVOKE UPDATE, DELETE, TRUNCATE ON consent_audit_log FROM app_service_role;

-- Index for Data Principal access requests (Section 11)
CREATE INDEX idx_consent_principal ON consent_audit_log (data_principal_id, created_at DESC);
