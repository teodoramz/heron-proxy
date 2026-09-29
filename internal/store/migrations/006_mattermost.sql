-- Mattermost takes the same {"text": ...} shape as Slack, and any channel can
-- carry a template so the message body is the operator's to write.
ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_channel_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_channel_check
    CHECK (channel IN ('webhook', 'slack', 'discord', 'mattermost'));

ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS template TEXT NOT NULL DEFAULT '';
