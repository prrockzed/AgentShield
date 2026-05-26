CREATE TABLE IF NOT EXISTS user_security_settings (
    user_id                 UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    prompt_scan             BOOLEAN NOT NULL DEFAULT TRUE,
    tool_intercept          BOOLEAN NOT NULL DEFAULT TRUE,
    output_scan             BOOLEAN NOT NULL DEFAULT TRUE,
    network_intercept       BOOLEAN NOT NULL DEFAULT TRUE,
    filesystem_intercept    BOOLEAN NOT NULL DEFAULT TRUE,
    behavioral_alert        BOOLEAN NOT NULL DEFAULT TRUE,
    hallucination_detection BOOLEAN NOT NULL DEFAULT TRUE,
    browser_intercept       BOOLEAN NOT NULL DEFAULT TRUE,
    code_scan               BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
