-- Phase 5: DLP policies table
-- Security engine uses hardcoded baseline patterns in Phase 5.
-- This table is consumed by Phase 10 (Threat Intelligence / dynamic policy management).

CREATE TABLE IF NOT EXISTS dlp_policies (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    category   TEXT        NOT NULL,
    pattern    TEXT        NOT NULL UNIQUE,
    label      TEXT        NOT NULL,
    action     TEXT        NOT NULL DEFAULT 'REDACT' CHECK (action IN ('REDACT', 'BLOCK', 'FLAG')),
    severity   TEXT        NOT NULL DEFAULT 'HIGH'  CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dlp_policies_category ON dlp_policies (category);
CREATE INDEX IF NOT EXISTS idx_dlp_policies_enabled  ON dlp_policies (enabled);

-- -------------------------------------------------------------------------
-- Seed data — mirrors the hardcoded patterns in output_interceptor.py
-- -------------------------------------------------------------------------

-- Category: secrets
INSERT INTO dlp_policies (category, pattern, label, action, severity) VALUES
    ('secrets', 'AKIA[0-9A-Z]{16}',                                      'AWS_KEY',         'REDACT', 'CRITICAL'),
    ('secrets', 'ghp_[A-Za-z0-9_]{36,255}',                              'GITHUB_TOKEN',    'REDACT', 'CRITICAL'),
    ('secrets', 'gho_[A-Za-z0-9_]{36,255}',                              'GITHUB_TOKEN',    'REDACT', 'CRITICAL'),
    ('secrets', 'sk_live_[0-9a-zA-Z]{20,}',                              'STRIPE_KEY',      'REDACT', 'CRITICAL'),
    ('secrets', 'rk_live_[0-9a-zA-Z]{20,}',                              'STRIPE_KEY',      'REDACT', 'CRITICAL'),
    ('secrets', 'sk-[A-Za-z0-9]{20,}',                                   'OPENAI_KEY',      'REDACT', 'CRITICAL'),
    ('secrets', 'sk-ant-[A-Za-z0-9\-]{20,}',                             'ANTHROPIC_KEY',   'REDACT', 'CRITICAL'),
    ('secrets', 'api[_\-]?key\s*[=:]\s*[A-Za-z0-9\-_]{16,}',            'API_KEY',         'REDACT', 'HIGH'),
    ('secrets', '-----BEGIN\s+(?:\w+\s+)?PRIVATE KEY-----',              'SSH_PRIVATE_KEY', 'REDACT', 'CRITICAL'),
    ('secrets', 'ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'JWT_TOKEN',       'REDACT', 'HIGH'),
    ('secrets', 'password\s*[=:]\s*\S{8,}',                              'PASSWORD',        'REDACT', 'HIGH')
ON CONFLICT (pattern) DO NOTHING;

-- Category: pii
INSERT INTO dlp_policies (category, pattern, label, action, severity) VALUES
    ('pii', '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',       'EMAIL',       'REDACT', 'MEDIUM'),
    ('pii', '(?:\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}',  'PHONE',       'REDACT', 'MEDIUM'),
    ('pii', '\b\d{3}-\d{2}-\d{4}\b',                                    'SSN',         'REDACT', 'HIGH'),
    ('pii', '\b\d{13,16}\b',                                             'CREDIT_CARD', 'REDACT', 'HIGH')
ON CONFLICT (pattern) DO NOTHING;

-- Category: paths
INSERT INTO dlp_policies (category, pattern, label, action, severity) VALUES
    ('paths', '~/\.ssh/\S+',                                 'SENSITIVE_PATH',   'REDACT', 'HIGH'),
    ('paths', '/etc/shadow|/etc/passwd',                     'SENSITIVE_PATH',   'REDACT', 'HIGH'),
    ('paths', '~/\.aws/credentials',                         'SENSITIVE_PATH',   'REDACT', 'HIGH'),
    ('paths', '\S+\.(pem|key|p12|pfx)\b',                   'SENSITIVE_PATH',   'REDACT', 'HIGH'),
    ('paths', '(?m)^[A-Z_][A-Z0-9_]*\s*=\s*\S{8,}$',       'ENV_FILE_CONTENT', 'REDACT', 'HIGH')
ON CONFLICT (pattern) DO NOTHING;

-- Category: entropy
INSERT INTO dlp_policies (category, pattern, label, action, severity) VALUES
    ('entropy', 'shannon_entropy>=4.5,min_length=20', 'HIGH_ENTROPY_SECRET', 'REDACT', 'MEDIUM')
ON CONFLICT (pattern) DO NOTHING;
