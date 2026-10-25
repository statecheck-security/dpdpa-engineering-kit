-- Behaviour checks for consent-manager/ledger.sql. Run after loading the ledger into an empty database.

DO $$
BEGIN
    INSERT INTO consent_events (principal_id, fiduciary_id, event_type, purpose_id, notice_hash)
    VALUES ('pseudonym-1', 'fiduciary_abc', 'CONSENT_GRANT', 'marketing', repeat('a', 64));

    BEGIN
        UPDATE consent_events SET purpose_id = 'analytics';
        RAISE EXCEPTION 'expected UPDATE to be blocked';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM NOT LIKE 'Consent records are append-only%' THEN RAISE; END IF;
    END;

    BEGIN
        DELETE FROM consent_events;
        RAISE EXCEPTION 'expected DELETE to be blocked';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM NOT LIKE 'Consent records are append-only%' THEN RAISE; END IF;
    END;

    BEGIN
        TRUNCATE consent_events;
        RAISE EXCEPTION 'expected TRUNCATE to be blocked';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM NOT LIKE 'Consent records are append-only%' THEN RAISE; END IF;
    END;

    ASSERT (SELECT count(*) FROM consent_events) = 1, 'the ledger row must survive';

    BEGIN
        INSERT INTO consent_events (principal_id, fiduciary_id, event_type, purpose_id)
        VALUES ('pseudonym-1', 'fiduciary_abc', 'CONSENT_PAUSE', 'marketing');
        RAISE EXCEPTION 'expected unknown event_type to be rejected';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    BEGIN
        INSERT INTO consent_events (principal_id, fiduciary_id, event_type, purpose_id, created_at)
        VALUES ('pseudonym-1', 'fiduciary_abc', 'CONSENT_GRANT', 'marketing', NOW() + interval '1 day');
        RAISE EXCEPTION 'expected a future timestamp to be rejected';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
END
$$;
