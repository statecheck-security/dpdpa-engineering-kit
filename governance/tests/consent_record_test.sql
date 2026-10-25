-- Behaviour checks for governance/consent-record.sql. Run after loading it into an empty database.

DO $$
DECLARE
    c_id UUID;
BEGIN
    INSERT INTO consent_records (principal_id, purpose_id, granted, method, ip_address, version)
    VALUES (gen_random_uuid(), 'marketing_email', true, 'checkbox_affirmative', '203.0.113.7', 'notice-v3')
    RETURNING id INTO c_id;

    ASSERT (SELECT language FROM consent_records WHERE id = c_id) = 'en', 'language defaults to en';
    ASSERT (SELECT granted_at FROM consent_records WHERE id = c_id) IS NOT NULL, 'granted_at defaults to now';

    -- Withdrawal is recorded on the same row (Section 6(4) parity: same API shape as the grant)
    UPDATE consent_records SET withdrawn_at = NOW() WHERE id = c_id;
    ASSERT (SELECT withdrawn_at FROM consent_records WHERE id = c_id) IS NOT NULL;

    BEGIN
        INSERT INTO consent_records (principal_id, purpose_id, granted, method)
        VALUES (gen_random_uuid(), 'marketing_email', true, 'checkbox_affirmative');
        RAISE EXCEPTION 'expected a missing notice version to be rejected';
    EXCEPTION WHEN not_null_violation THEN NULL;
    END;

    BEGIN
        INSERT INTO consent_records (principal_id, purpose_id, granted, method, ip_address, version)
        VALUES (gen_random_uuid(), 'marketing_email', true, 'api_grant', 'not-an-ip', 'notice-v3');
        RAISE EXCEPTION 'expected an invalid IP address to be rejected';
    EXCEPTION WHEN invalid_text_representation THEN NULL;
    END;
END
$$;
