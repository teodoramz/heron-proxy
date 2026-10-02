-- Where "/" should send a visitor, for an application that lives under a path.
ALTER TABLE apps ADD COLUMN IF NOT EXISTS root_redirect TEXT NOT NULL DEFAULT '';
