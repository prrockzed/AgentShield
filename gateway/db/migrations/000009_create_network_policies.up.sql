-- Phase 12: Network security layer — domain blocklist/allowlist management.
CREATE TABLE IF NOT EXISTS network_policies (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    type       TEXT        NOT NULL DEFAULT 'BLOCKLIST'
                           CHECK (type IN ('BLOCKLIST', 'ALLOWLIST')),
    domain     TEXT        NOT NULL,
    category   TEXT        NOT NULL,
    reason     TEXT,
    source     TEXT        NOT NULL DEFAULT 'builtin',
    active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policies_type_domain ON network_policies (type, domain);
CREATE INDEX        IF NOT EXISTS idx_network_policies_active       ON network_policies (active);
CREATE INDEX        IF NOT EXISTS idx_network_policies_category     ON network_policies (category);

-- 25 builtin BLOCKLIST entries across 3 categories

-- DYNAMIC_DNS (10): legitimate services widely abused for C2 and malware staging
INSERT INTO network_policies (type, domain, category, reason, source) VALUES
    ('BLOCKLIST', 'no-ip.com',          'DYNAMIC_DNS',   'Free dynamic DNS service commonly abused for malware C2 staging',          'builtin'),
    ('BLOCKLIST', 'dyndns.org',         'DYNAMIC_DNS',   'Legacy dynamic DNS service historically abused by botnets',               'builtin'),
    ('BLOCKLIST', 'hopto.org',          'DYNAMIC_DNS',   'No-IP subdomain service abused for C2 and phishing redirectors',          'builtin'),
    ('BLOCKLIST', 'ddns.net',           'DYNAMIC_DNS',   'Dynamic DNS subdomain space with high abuse rate',                        'builtin'),
    ('BLOCKLIST', 'changeip.com',       'DYNAMIC_DNS',   'Dynamic DNS provider documented in abuse.ch tracker reports',            'builtin'),
    ('BLOCKLIST', 'duckdns.org',        'DYNAMIC_DNS',   'Free dynamic DNS used as malware callback redirector',                    'builtin'),
    ('BLOCKLIST', 'freedns.afraid.org', 'DYNAMIC_DNS',   'Free DNS hosting historically abused for phishing and C2',               'builtin'),
    ('BLOCKLIST', 'sytes.net',          'DYNAMIC_DNS',   'No-IP free hostname domain abused for staging malware',                  'builtin'),
    ('BLOCKLIST', 'servehttp.com',      'DYNAMIC_DNS',   'No-IP domain commonly seen in dropper download URLs',                    'builtin'),
    ('BLOCKLIST', 'myftp.biz',          'DYNAMIC_DNS',   'No-IP free domain observed in data-exfiltration campaigns',              'builtin'),

-- C2 (8): developer/testing tools widely documented as C2 relay infrastructure
    ('BLOCKLIST', 'requestbin.com',     'C2',            'HTTP inspection service abused as C2 callback endpoint',                  'builtin'),
    ('BLOCKLIST', 'webhook.site',       'C2',            'Webhook service abused for data-exfiltration callbacks',                  'builtin'),
    ('BLOCKLIST', 'beeceptor.com',      'C2',            'API mocking service misused as lightweight C2 relay',                    'builtin'),
    ('BLOCKLIST', 'pipedream.net',      'C2',            'Workflow platform abused for C2 event collection',                       'builtin'),
    ('BLOCKLIST', 'canarytokens.com',   'C2',            'Token-based callback infrastructure used in malware campaigns',          'builtin'),
    ('BLOCKLIST', 'interactsh.com',     'C2',            'OOB interaction server used in exploitation payloads',                   'builtin'),
    ('BLOCKLIST', 'oast.pro',           'C2',            'OAST server used for blind SSRF detection payloads',                     'builtin'),
    ('BLOCKLIST', 'oast.online',        'C2',            'OAST interaction domain observed in active exploitation campaigns',      'builtin'),

-- MALWARE_DROP (7): paste/file-sharing services used to host and deliver payloads
    ('BLOCKLIST', 'paste.ee',           'MALWARE_DROP',  'Pastebin alternative used to host encoded malware payloads',             'builtin'),
    ('BLOCKLIST', 'hastebin.com',       'MALWARE_DROP',  'Code-sharing service hosting base64-encoded dropper scripts',           'builtin'),
    ('BLOCKLIST', 'ghostbin.co',        'MALWARE_DROP',  'Anonymous paste service used for PowerShell dropper staging',           'builtin'),
    ('BLOCKLIST', 'controlc.com',       'MALWARE_DROP',  'Paste service observed hosting encoded RAT payloads',                   'builtin'),
    ('BLOCKLIST', 'ix.io',              'MALWARE_DROP',  'Minimalist paste service used in curl-pipe-sh attack chains',           'builtin'),
    ('BLOCKLIST', 'termbin.com',        'MALWARE_DROP',  'netcat-based paste service used in post-exploitation',                  'builtin'),
    ('BLOCKLIST', 'transfer.sh',        'MALWARE_DROP',  'Ephemeral file-sharing service used to stage and serve malware',        'builtin');
