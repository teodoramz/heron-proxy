-- Optional poster name and icon for a chat channel that allows an integration
-- to override them.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS post_as   TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS post_icon TEXT NOT NULL DEFAULT '';
