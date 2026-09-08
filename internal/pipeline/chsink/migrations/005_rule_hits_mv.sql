CREATE MATERIALIZED VIEW IF NOT EXISTS rule_hits_1h_mv TO rule_hits_1h AS
SELECT
    app_id,
    toStartOfHour(ts) AS hour,
    rule_id,
    count()             AS hits,
    uniqState(client_ip) AS clients
FROM traffic
ARRAY JOIN rule_ids AS rule_id
GROUP BY app_id, hour, rule_id
