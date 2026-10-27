-- Applications whose traffic is proxied and inspected but never recorded.
ALTER TABLE apps ADD COLUMN IF NOT EXISTS no_log BOOLEAN NOT NULL DEFAULT false;
