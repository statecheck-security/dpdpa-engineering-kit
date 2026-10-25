-- Behaviour checks for consent/schema.sql. Run after loading the schema into an empty database.
-- Each block raises (and psql's ON_ERROR_STOP fails the run) if the schema misbehaves.

DO $$
DECLARE
    p_id UUID;
    nv_id UUID;
    c_id UUID;
    part TEXT;
BEGIN
    INSERT INTO purpose (name, legal_basis, data_categories)
    VALUES ('order_fulfilment', 'consent', ARRAY['name', 'address'])
    RETURNING purpose_id INTO p_id;

    INSERT INTO notice_version (purpose_id, version_number, canonical_hash)
    VALUES (p_id, 1, sha256('notice v1'::bytea))
    RETURNING notice_version_id INTO nv_id;

    INSERT INTO consent_record (principal_id, purpose_id, notice_version_id, language_shown, receipt_hash, status)
    VALUES (gen_random_uuid(), p_id, nv_id, 'hi', sha256('receipt'::bytea), 'granted')
    RETURNING consent_id INTO c_id;

    -- An event in April 2026 lands in the April partition.
    INSERT INTO consent_audit_event (consent_id, event_type, this_event_hash, event_payload, occurred_at)
    VALUES (c_id, 'GRANT', sha256('e1'::bytea), '{"receipt": "r"}', '2026-04-13T10:30:00Z');

    SELECT tableoid::regclass::text INTO part FROM consent_audit_event WHERE consent_id = c_id;
    ASSERT part = 'consent_audit_event_2026_04', format('event routed to %s', part);

    -- An event outside every partition is rejected, so missing partitions surface immediately.
    BEGIN
        INSERT INTO consent_audit_event (consent_id, event_type, this_event_hash, event_payload, occurred_at)
        VALUES (c_id, 'VIEW', sha256('e2'::bytea), '{}', '2026-06-01T00:00:00Z');
        RAISE EXCEPTION 'expected no partition for June 2026';
    EXCEPTION WHEN check_violation OR SQLSTATE '23514' THEN NULL;
    END;

    -- Unknown event types and statuses are rejected by the CHECK constraints.
    BEGIN
        INSERT INTO consent_audit_event (consent_id, event_type, this_event_hash, event_payload, occurred_at)
        VALUES (c_id, 'DELETE', sha256('e3'::bytea), '{}', '2026-04-14T00:00:00Z');
        RAISE EXCEPTION 'expected event_type check to fail';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    BEGIN
        UPDATE consent_record SET status = 'paused' WHERE consent_id = c_id;
        RAISE EXCEPTION 'expected status check to fail';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    -- A notice version number is unique per purpose.
    BEGIN
        INSERT INTO notice_version (purpose_id, version_number, canonical_hash)
        VALUES (p_id, 1, sha256('dup'::bytea));
        RAISE EXCEPTION 'expected unique (purpose_id, version_number) to fail';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
END
$$;
