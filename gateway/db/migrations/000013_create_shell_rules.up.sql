CREATE TABLE shell_rules (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern    TEXT        NOT NULL UNIQUE,
    reason     TEXT        NOT NULL,
    category   TEXT        NOT NULL,
    source     TEXT        NOT NULL DEFAULT 'custom',
    active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_shell_rules_category ON shell_rules (category);
CREATE INDEX idx_shell_rules_active   ON shell_rules (active);

-- Rename dlp_policies.enabled → active for consistency across all policy tables
ALTER TABLE dlp_policies RENAME COLUMN enabled TO active;
DROP INDEX IF EXISTS idx_dlp_policies_enabled;
CREATE INDEX idx_dlp_policies_active ON dlp_policies (active);

-- Add source column to dlp_policies so seeded vs custom rows can be distinguished
ALTER TABLE dlp_policies ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'seeded';
