-- Phase 13: Filesystem security engine — path-level access control policies.
CREATE TABLE IF NOT EXISTS filesystem_policies (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    path_pattern TEXT        NOT NULL,
    operation    TEXT        NOT NULL DEFAULT 'ALL'
                             CHECK (operation IN ('READ', 'WRITE', 'DELETE', 'ALL')),
    decision     TEXT        NOT NULL DEFAULT 'BLOCKED'
                             CHECK (decision IN ('BLOCKED', 'FLAGGED', 'ALLOWED')),
    severity     TEXT        NOT NULL DEFAULT 'HIGH'
                             CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    category     TEXT        NOT NULL,
    reason       TEXT,
    source       TEXT        NOT NULL DEFAULT 'builtin',
    active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_filesystem_policies_active    ON filesystem_policies (active);
CREATE INDEX IF NOT EXISTS idx_filesystem_policies_category  ON filesystem_policies (category);
CREATE INDEX IF NOT EXISTS idx_filesystem_policies_operation ON filesystem_policies (operation);

-- 20 builtin entries across 5 categories

-- SSH (6)
INSERT INTO filesystem_policies (path_pattern, operation, decision, severity, category, reason, source) VALUES
    ('*/.ssh/id_rsa',     'ALL',   'BLOCKED',  'CRITICAL', 'SSH', 'SSH RSA private key',                             'builtin'),
    ('*/.ssh/id_ed25519', 'ALL',   'BLOCKED',  'CRITICAL', 'SSH', 'SSH Ed25519 private key',                         'builtin'),
    ('*/.ssh/id_dsa',     'ALL',   'BLOCKED',  'CRITICAL', 'SSH', 'SSH DSA private key',                             'builtin'),
    ('*/.ssh/id_ecdsa',   'ALL',   'BLOCKED',  'CRITICAL', 'SSH', 'SSH ECDSA private key',                           'builtin'),
    ('*/.ssh/*',          'READ',  'FLAGGED',  'HIGH',     'SSH', 'SSH directory read — may expose config or keys',  'builtin'),
    ('*/.ssh/*',          'WRITE', 'BLOCKED',  'CRITICAL', 'SSH', 'SSH directory write — backdoor risk',             'builtin'),

-- SYSTEM_AUTH (4)
    ('/etc/shadow',       'ALL',   'BLOCKED',  'CRITICAL', 'SYSTEM_AUTH', 'System password hash database',           'builtin'),
    ('/etc/sudoers',      'ALL',   'BLOCKED',  'CRITICAL', 'SYSTEM_AUTH', 'Sudo privilege configuration',            'builtin'),
    ('/etc/sudoers.d/*',  'ALL',   'BLOCKED',  'CRITICAL', 'SYSTEM_AUTH', 'Sudo privilege configuration fragment',   'builtin'),
    ('/etc/passwd',       'READ',  'FLAGGED',  'MEDIUM',   'SYSTEM_AUTH', 'System user database read',               'builtin'),

-- CLOUD_CREDENTIALS (4)
    ('*/.aws/credentials','ALL',   'BLOCKED',  'CRITICAL', 'CLOUD_CREDENTIALS', 'AWS access keys and secret keys',  'builtin'),
    ('*/.aws/*',          'READ',  'FLAGGED',  'HIGH',     'CLOUD_CREDENTIALS', 'AWS configuration directory read', 'builtin'),
    ('*/.config/gcloud/credentials.db',
                          'ALL',   'BLOCKED',  'CRITICAL', 'CLOUD_CREDENTIALS', 'GCP OAuth credentials database',   'builtin'),
    ('*/.config/gcloud/application_default_credentials.json',
                          'ALL',   'BLOCKED',  'CRITICAL', 'CLOUD_CREDENTIALS', 'GCP application default credentials', 'builtin'),

-- CERT_KEY (3)
    ('*.pem',             'ALL',   'BLOCKED',  'HIGH',     'CERT_KEY', 'PEM certificate or private key file',       'builtin'),
    ('*.p12',             'ALL',   'BLOCKED',  'HIGH',     'CERT_KEY', 'PKCS12 certificate bundle',                 'builtin'),
    ('*.pfx',             'ALL',   'BLOCKED',  'HIGH',     'CERT_KEY', 'PKCS12 certificate bundle (PFX format)',    'builtin'),

-- ENV_FILE (3)
    ('*.env',             'READ',  'FLAGGED',  'HIGH',     'ENV_FILE', 'Environment file — likely contains secrets', 'builtin'),
    ('.env.*',            'READ',  'FLAGGED',  'HIGH',     'ENV_FILE', 'Environment file variant',                   'builtin'),
    ('*/.env',            'READ',  'FLAGGED',  'HIGH',     'ENV_FILE', 'Hidden environment file',                    'builtin');
