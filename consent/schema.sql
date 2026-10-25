-- One row per approved purpose. Purpose is the fundamental unit of consent
-- under Section 6(1) -- "limited to such personal data as is necessary
-- for such specified purpose."
CREATE TABLE purpose (
    purpose_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT NOT NULL,
    legal_basis      TEXT NOT NULL CHECK (legal_basis IN ('consent', 'legitimate_use')),
    data_categories  TEXT[] NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Notices are versioned. Once a version is active, its content hash is
-- immutable. A policy change creates a new notice_version row.
CREATE TABLE notice_version (
    notice_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose_id        UUID NOT NULL REFERENCES purpose(purpose_id),
    version_number    INT NOT NULL,
    canonical_hash    BYTEA NOT NULL,   -- SHA-256 of canonicalised JSON bundle
    effective_from    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    superseded_at     TIMESTAMPTZ,
    UNIQUE (purpose_id, version_number)
);

-- One translation row per supported language per notice version.
-- Expected count: 23 rows per notice_version (English + 22 scheduled).
CREATE TABLE notice_translation (
    translation_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    notice_version_id    UUID NOT NULL REFERENCES notice_version(notice_version_id),
    language_code        TEXT NOT NULL,  -- ISO 639-1 / BCP-47 (en, hi, bn, ta, ...)
    rendered_content     TEXT NOT NULL,
    content_hash         BYTEA NOT NULL, -- SHA-256 of rendered_content bytes
    translator_signature TEXT NOT NULL,  -- Ed25519 sig by approved translator
    UNIQUE (notice_version_id, language_code)
);

-- A consent record is point-in-time evidence. Bound to the exact
-- notice_version_id the principal saw, and the language it was shown in.
CREATE TABLE consent_record (
    consent_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id         UUID NOT NULL,
    purpose_id           UUID NOT NULL REFERENCES purpose(purpose_id),
    notice_version_id    UUID NOT NULL REFERENCES notice_version(notice_version_id),
    language_shown       TEXT NOT NULL,
    receipt_hash         BYTEA NOT NULL, -- Signed consent receipt (see §§)
    status               TEXT NOT NULL CHECK (status IN ('granted','withdrawn','erased')),
    granted_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    withdrawn_at         TIMESTAMPTZ,
    erasure_confirmed_at TIMESTAMPTZ
);

-- Append-only hash-chained audit log. Each row's this_event_hash binds
-- prev_event_hash + event_payload + occurred_at. Rule 6(1)(c),(e).
CREATE TABLE consent_audit_event (
    event_id        BIGSERIAL,
    consent_id      UUID NOT NULL REFERENCES consent_record(consent_id),
    event_type      TEXT NOT NULL CHECK (event_type IN
                      ('NOTICE_SHOWN','GRANT','VIEW','WITHDRAW','ERASURE_FANOUT','ERASURE_CONFIRMED')),
    prev_event_hash BYTEA,
    this_event_hash BYTEA NOT NULL,
    event_payload   JSONB NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A partitioned table's primary key must include the partition column.
    PRIMARY KEY (event_id, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Monthly partitions. Rule 6(1)(e) and 8(3) floor is 12 months; a longer window
-- (e.g. 24) needs a documented legal basis, since Rule 8(3) then expects erasure.
CREATE TABLE consent_audit_event_2026_04 PARTITION OF consent_audit_event
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

-- Processor fanout for Section 8(7) erasure propagation.
CREATE TABLE processor_fanout (
    fanout_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consent_id             UUID NOT NULL REFERENCES consent_record(consent_id),
    processor_id           TEXT NOT NULL,
    acknowledgement_status TEXT NOT NULL DEFAULT 'pending',
    acknowledged_at        TIMESTAMPTZ
);

CREATE INDEX ON consent_record (principal_id, purpose_id);
CREATE INDEX ON consent_record (status) WHERE status = 'withdrawn';
CREATE INDEX ON consent_audit_event (consent_id, occurred_at);
