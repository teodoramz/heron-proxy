CREATE TABLE IF NOT EXISTS traffic
(
    ts                DateTime64(3, 'UTC'),
    id                UUID,
    app_id            LowCardinality(String),
    retention_days    UInt16 DEFAULT 90,

    client_ip         IPv6,
    client_ip_claimed IPv6,
    client_port       UInt16,
    country           LowCardinality(String),
    asn               UInt32,
    as_org            String,
    ja3               String,
    ja4               String,

    method            LowCardinality(String),
    scheme            LowCardinality(String),
    host              String,
    path              String,
    query             String,
    http_version      LowCardinality(String),
    req_headers       Map(String, String),
    req_body_size     UInt64,
    req_body_inline   String,
    req_body_sha256   String,
    req_body_blob     String,
    req_truncated     UInt8,
    user_agent        String,

    status            UInt16,
    resp_headers      Map(String, String),
    resp_size         UInt64,
    resp_content_type LowCardinality(String),

    duration_ms       UInt32,
    upstream_ms       UInt32,
    waf_ms            UInt32,

    anomaly_score     UInt16,
    rule_ids          Array(UInt32),
    rule_msgs         Array(String),
    rule_tags         Array(LowCardinality(String)),
    rule_severity     UInt8,
    paranoia_max      UInt8,
    would_block       UInt8,

    upstream          String,
    error             String,
    is_websocket      UInt8,

    INDEX idx_client_ip client_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_rule_ids  rule_ids  TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_path      path      TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4,
    INDEX idx_ua        user_agent TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4,
    INDEX idx_body      req_body_inline TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_status    status    TYPE minmax GRANULARITY 4,
    INDEX idx_host      host      TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (app_id, ts, id)
TTL toDateTime(ts) + toIntervalDay(retention_days)
SETTINGS index_granularity = 8192
