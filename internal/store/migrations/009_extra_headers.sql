-- Headers the proxy adds to the upstream request, for an application that
-- needs its own.
ALTER TABLE apps ADD COLUMN IF NOT EXISTS extra_headers JSONB NOT NULL DEFAULT '[]'::jsonb;
