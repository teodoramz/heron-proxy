CREATE TABLE IF NOT EXISTS apps (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    hostnames           TEXT[] NOT NULL DEFAULT '{}',
    upstream_url        TEXT NOT NULL,
    upstream_tls_verify BOOLEAN NOT NULL DEFAULT TRUE,
    preserve_host       BOOLEAN NOT NULL DEFAULT FALSE,
    trusted_cidrs       TEXT[] NOT NULL DEFAULT '{}',
    client_ip_header    TEXT NOT NULL DEFAULT 'X-Real-IP',
    retention_days      INT NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 1 AND 3650),
    capture             JSONB NOT NULL DEFAULT '{}',
    redaction           JSONB NOT NULL DEFAULT '{}',
    waf                 JSONB NOT NULL DEFAULT '{}',
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS certificates (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id        TEXT REFERENCES apps(id) ON DELETE CASCADE,
    sni_names     TEXT[] NOT NULL DEFAULT '{}',
    cert_pem      TEXT NOT NULL,
    key_encrypted BYTEA NOT NULL,
    fingerprint   TEXT NOT NULL,
    not_before    TIMESTAMPTZ,
    not_after     TIMESTAMPTZ,
    is_default    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS certificates_app_id_idx ON certificates (app_id);

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS app_access (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id  TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, app_id)
);

CREATE TABLE IF NOT EXISTS saved_filters (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    query      JSONB NOT NULL,
    shared     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_exclusions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id     TEXT REFERENCES apps(id) ON DELETE CASCADE,
    rule_id    BIGINT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT '',
    seclang    TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rule_exclusions_app_idx ON rule_exclusions (app_id, rule_id);

CREATE TABLE IF NOT EXISTS fp_marks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id   UUID NOT NULL,
    app_id     TEXT NOT NULL,
    rule_id    BIGINT NOT NULL,
    verdict    TEXT NOT NULL CHECK (verdict IN ('false_positive', 'true_positive', 'unsure')),
    note       TEXT NOT NULL DEFAULT '',
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (event_id, rule_id)
);
CREATE INDEX IF NOT EXISTS fp_marks_app_rule_idx ON fp_marks (app_id, rule_id, verdict);

CREATE TABLE IF NOT EXISTS event_annotations (
    event_id   UUID PRIMARY KEY,
    app_id     TEXT NOT NULL,
    tags       TEXT[] NOT NULL DEFAULT '{}',
    note       TEXT NOT NULL DEFAULT '',
    bookmarked BOOLEAN NOT NULL DEFAULT FALSE,
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS event_annotations_bookmarked_idx ON event_annotations (app_id) WHERE bookmarked;

CREATE TABLE IF NOT EXISTS alert_rules (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT NOT NULL,
    app_id           TEXT REFERENCES apps(id) ON DELETE CASCADE,
    condition        JSONB NOT NULL,
    channel          TEXT NOT NULL CHECK (channel IN ('webhook', 'slack', 'discord')),
    target_url       TEXT NOT NULL,
    throttle_seconds INT NOT NULL DEFAULT 300,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    last_fired_at    TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id      BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action  TEXT NOT NULL,
    detail  JSONB NOT NULL DEFAULT '{}',
    ts      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);

CREATE TABLE IF NOT EXISTS config_version (
    id      BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    version BIGINT NOT NULL DEFAULT 1
);
INSERT INTO config_version (id, version) VALUES (TRUE, 1) ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION bump_config_version() RETURNS TRIGGER AS $$
BEGIN
    UPDATE config_version SET version = version + 1 WHERE id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS apps_bump ON apps;
CREATE TRIGGER apps_bump AFTER INSERT OR UPDATE OR DELETE ON apps
    FOR EACH STATEMENT EXECUTE FUNCTION bump_config_version();

DROP TRIGGER IF EXISTS certificates_bump ON certificates;
CREATE TRIGGER certificates_bump AFTER INSERT OR UPDATE OR DELETE ON certificates
    FOR EACH STATEMENT EXECUTE FUNCTION bump_config_version();

DROP TRIGGER IF EXISTS rule_exclusions_bump ON rule_exclusions;
CREATE TRIGGER rule_exclusions_bump AFTER INSERT OR UPDATE OR DELETE ON rule_exclusions
    FOR EACH STATEMENT EXECUTE FUNCTION bump_config_version();
