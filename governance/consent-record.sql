CREATE TABLE consent_records (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id  UUID NOT NULL,
  purpose_id    TEXT NOT NULL,          -- e.g. 'marketing_email', 'order_processing'
  granted       BOOLEAN NOT NULL,
  method        TEXT NOT NULL,          -- 'checkbox_affirmative', 'api_grant'
  ip_address    INET,
  user_agent    TEXT,
  language      TEXT DEFAULT 'en',      -- BCP-47 code per Eighth Schedule
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  withdrawn_at  TIMESTAMPTZ,
  version       TEXT NOT NULL           -- consent notice version at time of grant
);
