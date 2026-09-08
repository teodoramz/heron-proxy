CREATE MATERIALIZED VIEW IF NOT EXISTS traffic_stats_1m_mv TO traffic_stats_1m AS
SELECT
    app_id,
    toStartOfMinute(ts) AS minute,
    count()                                        AS requests,
    countIf(status >= 200 AND status < 300)        AS s2xx,
    countIf(status >= 300 AND status < 400)        AS s3xx,
    countIf(status >= 400 AND status < 500)        AS s4xx,
    countIf(status >= 500)                         AS s5xx,
    countIf(would_block = 1)                       AS blocked,
    sum(resp_size)                                 AS bytes,
    quantilesState(0.5, 0.95, 0.99)(duration_ms)   AS duration,
    uniqState(client_ip)                           AS clients
FROM traffic
GROUP BY app_id, minute
