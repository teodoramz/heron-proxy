-- Only Mattermost and plain webhooks are supported. Existing Slack and Discord
-- rules keep their target URL but become plain webhooks and are switched off,
-- rather than being deleted or left sending a body the receiver would reject.
UPDATE alert_rules SET channel = 'webhook', enabled = FALSE
WHERE channel IN ('slack', 'discord');

ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_channel_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_channel_check
    CHECK (channel IN ('webhook', 'mattermost'));
