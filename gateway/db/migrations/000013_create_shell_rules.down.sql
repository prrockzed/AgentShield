DROP TABLE IF EXISTS shell_rules;
ALTER TABLE dlp_policies RENAME COLUMN active TO enabled;
ALTER TABLE dlp_policies DROP COLUMN IF EXISTS source;
