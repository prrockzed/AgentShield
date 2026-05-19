CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS agent_runs (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    status        TEXT        NOT NULL DEFAULT 'pending',
    agent_type    TEXT        NOT NULL,
    model         TEXT        NOT NULL,
    sandbox_id    TEXT,
    prompt_score  FLOAT,
    output_score  FLOAT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_status     ON agent_runs (status);
CREATE INDEX IF NOT EXISTS idx_agent_runs_created_at ON agent_runs (created_at);
