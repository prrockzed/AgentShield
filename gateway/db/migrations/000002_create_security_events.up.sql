CREATE TABLE IF NOT EXISTS security_events (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id               UUID,
    event_type           TEXT        NOT NULL,
    source               TEXT        NOT NULL,
    payload              JSONB,
    decision             TEXT        NOT NULL,
    reason               TEXT,
    severity             TEXT        NOT NULL DEFAULT 'INFO',
    matched_signature_id UUID,
    timestamp            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_run_id     ON security_events (run_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events (event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_decision   ON security_events (decision);
CREATE INDEX IF NOT EXISTS idx_security_events_severity   ON security_events (severity);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp  ON security_events (timestamp);
