-- Behaviour checks for consent/soc2-consent-audit-log.sql, run as the application role.
SET ROLE app_service_role;

DO $$
BEGIN
    INSERT INTO consent_audit_log (data_principal_id, purpose_key, action, notice_version, notice_language, consent_source)
    VALUES (gen_random_uuid(), 'analytics', 'GRANTED', 'v3', 'ta', 'web_form');

    BEGIN
        UPDATE consent_audit_log SET action = 'REVOKED';
        RAISE EXCEPTION 'expected UPDATE to be denied to the app role';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;

    BEGIN
        DELETE FROM consent_audit_log;
        RAISE EXCEPTION 'expected DELETE to be denied to the app role';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;

    BEGIN
        INSERT INTO consent_audit_log (data_principal_id, purpose_key, action, notice_version, notice_language, consent_source)
        VALUES (gen_random_uuid(), 'analytics', 'GRANTED', 'v3', 'ta', 'email');
        RAISE EXCEPTION 'expected an unknown consent_source to be rejected';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    ASSERT (SELECT count(*) FROM consent_audit_log) = 1;
END
$$;

RESET ROLE;
