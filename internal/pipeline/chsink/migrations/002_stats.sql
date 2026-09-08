CREATE TABLE IF NOT EXISTS traffic_stats_1m
(
    app_id      LowCardinality(String),
    minute      DateTime,
    requests    SimpleAggregateFunction(sum, UInt64),
    s2xx        SimpleAggregateFunction(sum, UInt64),
    s3xx        SimpleAggregateFunction(sum, UInt64),
    s4xx        SimpleAggregateFunction(sum, UInt64),
    s5xx        SimpleAggregateFunction(sum, UInt64),
    blocked     SimpleAggregateFunction(sum, UInt64),
    bytes       SimpleAggregateFunction(sum, UInt64),
    duration    AggregateFunction(quantiles(0.5, 0.95, 0.99), UInt32),
    clients     AggregateFunction(uniq, IPv6)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (app_id, minute)
TTL minute + INTERVAL 400 DAY
