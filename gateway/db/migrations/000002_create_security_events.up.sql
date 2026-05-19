CREATE TABLE IF NOT EXISTS security_events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      UUID        NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    event_type  TEXT        NOT NULL,
    decision    TEXT        NOT NULL,
    severity    TEXT        NOT NULL DEFAULT 'info',
    payload     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_run_id     ON security_events (run_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events (event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_decision   ON security_events (decision);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events (created_at);
