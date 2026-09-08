CREATE TABLE IF NOT EXISTS ip_stats_1h
(
    app_id    LowCardinality(String),
    hour      DateTime,
    client_ip IPv6,
    requests  SimpleAggregateFunction(sum, UInt64),
    anomaly   SimpleAggregateFunction(sum, UInt64),
    s4xx      SimpleAggregateFunction(sum, UInt64),
    s5xx      SimpleAggregateFunction(sum, UInt64),
    blocked   SimpleAggregateFunction(sum, UInt64),
    paths     AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (app_id, hour, client_ip)
TTL hour + INTERVAL 400 DAY
