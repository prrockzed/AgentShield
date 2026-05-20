-- Migration: 000003_create_injection_signatures
-- Creates the injection_signatures table and seeds 50+ baseline patterns.
-- The security engine does NOT read this table in Phase 4 (patterns are
-- hardcoded in prompt_interceptor.py). This table is consumed in Phase 10
-- (Threat Intelligence) when patterns are loaded from DB → Redis.

CREATE TABLE IF NOT EXISTS injection_signatures (
    id          BIGSERIAL PRIMARY KEY,
    category    TEXT        NOT NULL,
    pattern     TEXT        NOT NULL UNIQUE,
    reason      TEXT        NOT NULL,
    weight      NUMERIC(4,2) NOT NULL CHECK (weight >= 0 AND weight <= 1),
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_injection_signatures_category
    ON injection_signatures (category);

CREATE INDEX IF NOT EXISTS idx_injection_signatures_enabled
    ON injection_signatures (enabled);

-- ---------------------------------------------------------------------------
-- Seed data — 8 categories, 50+ patterns
-- ---------------------------------------------------------------------------

-- Direct injection (weight 0.9)
INSERT INTO injection_signatures (category, pattern, reason, weight) VALUES
  ('direct_injection', 'ignore\s+all\s+previous\s+instructions',    'direct_injection', 0.9),
  ('direct_injection', 'ignore\s+all\s+prior\s+instructions',       'direct_injection', 0.9),
  ('direct_injection', 'disregard\s+all\s+prior',                   'direct_injection', 0.9),
  ('direct_injection', 'forget\s+your\s+(previous\s+)?instructions','direct_injection', 0.9),
  ('direct_injection', 'you\s+are\s+now\s+DAN',                     'direct_injection', 0.9),
  ('direct_injection', 'do\s+not\s+follow\s+(your\s+)?instructions','direct_injection', 0.9),
  ('direct_injection', 'override\s+your\s+instructions',             'direct_injection', 0.9)
ON CONFLICT (pattern) DO NOTHING;

-- Jailbreak variants (weight 0.8–0.9)
INSERT INTO injection_signatures (category, pattern, reason, weight) VALUES
  ('jailbreak', 'developer\s+mode\s+enabled',  'jailbreak', 0.9),
  ('jailbreak', 'do\s+anything\s+now',          'jailbreak', 0.9),
  ('jailbreak', '\b(STAN|DUDE|AIM|JAILBREAK)\b','jailbreak', 0.9),
  ('jailbreak', 'no\s+restrictions',             'jailbreak', 0.8),
  ('jailbreak', 'without\s+restrictions',        'jailbreak', 0.8),
  ('jailbreak', 'remove\s+(all\s+)?restrictions','jailbreak', 0.8),
  ('jailbreak', 'jailbreak',                     'jailbreak', 0.9),
  ('jailbreak', 'unrestricted\s+mode',           'jailbreak', 0.8)
ON CONFLICT (pattern) DO NOTHING;

-- Safety bypass (weight 0.8)
INSERT INTO injection_signatures (category, pattern, reason, weight) VALUES
  ('safety_bypass', 'bypass\s+.*(safety|filter|restrictions)',      'safety_bypass', 0.8),
  ('safety_bypass', 'override\s+.*programming',                      'safety_bypass', 0.8),
  ('safety_bypass', 'you\s+have\s+no\s+restrictions',               'safety_bypass', 0.8),
  ('safety_bypass', 'ignore\s+your\s+(safety\s+)?(guidelines|rules|constraints)', 'safety_bypass', 0.8),
  ('safety_bypass', 'disable\s+(your\s+)?(safety|content|ethical)\s+(filter|mode|guidelines)', 'safety_bypass', 0.8)
ON CONFLICT (pattern) DO NOTHING;

-- System prompt extraction (weight 0.8–0.9)
INSERT INTO injection_signatures (category, pattern, reason, weight) VALUES
  ('system_prompt_extraction', 'reveal\s+.*system\s+prompt',                'system_prompt_extraction', 0.9),
  ('system_prompt_extraction', 'repeat\s+.*original\s+instructions',        'system_prompt_extraction', 0.9),
  ('system_prompt_extraction', 'what\s+are\s+your\s+instructions',          'system_prompt_extraction', 0.9),
  ('system_prompt_extraction', 'show\s+me\s+your\s+(system\s+)?prompt',    'system_prompt_extraction', 0.9),
  ('system_prompt_extraction', 'print\s+your\s+(system\s+)?prompt',        'system_prompt_extraction', 0.9),
  ('system_prompt_extraction', 'output\s+your\s+(initial\s+)?instructions','system_prompt_extraction', 0.9),
  ('system_prompt_extraction', 'display\s+your\s+configuration',           'system_prompt_extraction', 0.8)
ON CONFLICT (pattern) DO NOTHING;

-- Instruction override (weight 0.6–0.7)
INSERT INTO injection_signatures (category, pattern, reason, weight) VALUES
  ('instruction_override', 'from\s+now\s+on',                            'instruction_override', 0.6),
  ('instruction_override', 'starting\s+now.*ignore',                      'instruction_override', 0.7),
  ('instruction_override', 'ignore\s+the\s+above',                        'instruction_override', 0.7),
  ('instruction_override', 'your\s+new\s+(role|persona)',                  'instruction_override', 0.7),
  ('instruction_override', 'act\s+as\s+if\s+you\s+(have\s+no|are\s+not)', 'instruction_override', 0.7),
  ('instruction_override', 'pretend\s+(you\s+are|to\s+be)\s+an?\s+(AI|assistant|model)\s+without', 'instruction_override', 0.7),
  ('instruction_override', 'new\s+instructions\s+follow',                  'instruction_override', 0.6)
ON CONFLICT (pattern) DO NOTHING;

-- Identity / privilege claims (weight 0.6)
INSERT INTO injection_signatures (category, pattern, reason, weight) VALUES
  ('identity_claim', 'I\s+am\s+(your\s+)?(developer|creator|admin|owner|master)', 'identity_claim', 0.6),
  ('identity_claim', 'as\s+(your\s+)?(owner|master|creator|developer)',            'identity_claim', 0.6),
  ('identity_claim', 'you\s+are\s+in\s+debug\s+mode',                             'identity_claim', 0.6),
  ('identity_claim', 'maintenance\s+mode\s+activated',                             'identity_claim', 0.6),
  ('identity_claim', 'I\s+have\s+(root\s+)?admin\s+access',                       'identity_claim', 0.6)
ON CONFLICT (pattern) DO NOTHING;

-- Data exfiltration (weight 0.8–0.9)
INSERT INTO injection_signatures (category, pattern, reason, weight) VALUES
  ('data_exfiltration', 'exfiltrate\s+.*secrets',                   'data_exfiltration', 0.9),
  ('data_exfiltration', 'send\s+.*credentials.*https?://',           'data_exfiltration', 0.9),
  ('data_exfiltration', 'leak\s+.*passwords',                        'data_exfiltration', 0.8),
  ('data_exfiltration', 'extract\s+.*api\s+keys',                    'data_exfiltration', 0.8),
  ('data_exfiltration', 'upload\s+.*\.env\b',                        'data_exfiltration', 0.8),
  ('data_exfiltration', 'transmit\s+.*(private|secret|sensitive)',   'data_exfiltration', 0.8),
  ('data_exfiltration', 'POST\s+.*password',                         'data_exfiltration', 0.8)
ON CONFLICT (pattern) DO NOTHING;

-- Social engineering (weight 0.3–0.5)
INSERT INTO injection_signatures (category, pattern, reason, weight) VALUES
  ('social_engineering', 'my\s+grandmother\s+(used\s+to\s+)?tell',  'social_engineering', 0.4),
  ('social_engineering', 'as\s+a\s+security\s+researcher',          'social_engineering', 0.3),
  ('social_engineering', 'hypothetically\s+speaking',                'social_engineering', 0.3),
  ('social_engineering', 'for\s+educational\s+purposes\s+only',     'social_engineering', 0.3),
  ('social_engineering', 'in\s+a\s+fictional\s+scenario',           'social_engineering', 0.4),
  ('social_engineering', 'pretend\s+(this\s+is\s+)?a\s+game',       'social_engineering', 0.4),
  ('social_engineering', 'roleplay\s+as',                            'social_engineering', 0.4),
  ('social_engineering', 'imagine\s+you\s+have\s+no\s+(guidelines|restrictions|rules)', 'social_engineering', 0.5)
ON CONFLICT (pattern) DO NOTHING;
