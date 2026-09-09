-- The proxy's own certificate authority. One row: the key that signs
-- certificates minted on the fly for hosts with no uploaded certificate.
CREATE TABLE IF NOT EXISTS certificate_authority (
    id            BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    cert_pem      TEXT NOT NULL,
    key_encrypted BYTEA NOT NULL,
    fingerprint   TEXT NOT NULL,
    not_after     TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS certificate_authority_bump ON certificate_authority;
CREATE TRIGGER certificate_authority_bump
    AFTER INSERT OR UPDATE OR DELETE ON certificate_authority
    FOR EACH STATEMENT EXECUTE FUNCTION bump_config_version();
