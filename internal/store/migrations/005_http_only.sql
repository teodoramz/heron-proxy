-- Applications served over plain HTTP only: the proxy mints no certificate
-- for their hostnames and presents none.
ALTER TABLE apps ADD COLUMN IF NOT EXISTS http_only BOOLEAN NOT NULL DEFAULT FALSE;
