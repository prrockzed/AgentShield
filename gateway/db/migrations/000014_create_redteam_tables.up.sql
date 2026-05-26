CREATE TABLE redteam_runs (
    id           TEXT        PRIMARY KEY,
    started_at   TIMESTAMPTZ NOT NULL,
    finished_at  TIMESTAMPTZ NOT NULL,
    total        INT         NOT NULL DEFAULT 0,
    passed       INT         NOT NULL DEFAULT 0,
    failed       INT         NOT NULL DEFAULT 0,
    pass_rate    FLOAT       NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_redteam_runs_created_at ON redteam_runs (created_at);

CREATE TABLE redteam_results (
    id               TEXT        PRIMARY KEY,
    run_id           TEXT        NOT NULL REFERENCES redteam_runs(id) ON DELETE CASCADE,
    case_id          TEXT        NOT NULL,
    category         TEXT        NOT NULL,
    description      TEXT        NOT NULL,
    expected         TEXT[]      NOT NULL,
    actual           TEXT        NOT NULL,
    passed           BOOLEAN     NOT NULL,
    actual_response  JSONB,
    error            TEXT,
    duration_ms      FLOAT       NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_redteam_results_run_id   ON redteam_results (run_id);
CREATE INDEX idx_redteam_results_category ON redteam_results (category);
CREATE INDEX idx_redteam_results_passed   ON redteam_results (passed);
