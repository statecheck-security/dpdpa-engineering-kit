-- Immutable consent event store (PostgreSQL)
-- Supports Part B Items 3, 4(a), 4(b), 4(c)
CREATE TABLE consent_events (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id    VARCHAR(255) NOT NULL,
    fiduciary_id    VARCHAR(255) NOT NULL,
    event_type      VARCHAR(50) NOT NULL
                    CHECK (event_type IN (
                        'CONSENT_GRANT', 'CONSENT_DENY',
                        'CONSENT_WITHDRAW', 'NOTICE_SERVED',
                        'DATA_SHARE'
                    )),
    purpose_id      VARCHAR(255) NOT NULL,
    notice_hash     VARCHAR(64),    -- SHA-256 of the served notice
    payload_hash    VARCHAR(64),    -- SHA-256 of shared data (for DATA_SHARE)
    metadata        JSONB,          -- Additional structured context
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Immutability: no UPDATE or DELETE allowed via application-level
    -- RBAC. Enforce at database level with a trigger:
    CONSTRAINT no_future_dates CHECK (created_at <= NOW())
);

-- Prevent any UPDATE or DELETE on consent_events
CREATE OR REPLACE FUNCTION prevent_consent_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Consent records are append-only (DPDP Rules 2025, '
        'First Schedule, Part B, Items 3 and 4(c)). '
        'Records must be retained for at least 7 years.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_immutability
    BEFORE UPDATE OR DELETE ON consent_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_consent_modification();

-- TRUNCATE skips row-level triggers, so it needs its own statement-level trigger.
CREATE TRIGGER enforce_immutability_truncate
    BEFORE TRUNCATE ON consent_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION prevent_consent_modification();

-- Index for Data Principal record access (Part B, Item 4(a))
CREATE INDEX idx_consent_principal
    ON consent_events (principal_id, created_at DESC);

-- Retention policy: partition by year for efficient 7-year management
-- (Implementation depends on PostgreSQL partitioning strategy)
