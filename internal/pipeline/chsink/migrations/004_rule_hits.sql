CREATE TABLE IF NOT EXISTS rule_hits_1h
(
    app_id  LowCardinality(String),
    hour    DateTime,
    rule_id UInt32,
    hits    SimpleAggregateFunction(sum, UInt64),
    clients AggregateFunction(uniq, IPv6)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (app_id, hour, rule_id)
TTL hour + INTERVAL 400 DAY
