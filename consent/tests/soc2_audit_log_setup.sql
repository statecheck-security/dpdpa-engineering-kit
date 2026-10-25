-- Runs before consent/soc2-consent-audit-log.sql: the table's grants name this role.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_service_role') THEN
        CREATE ROLE app_service_role NOLOGIN;
    END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO app_service_role;
