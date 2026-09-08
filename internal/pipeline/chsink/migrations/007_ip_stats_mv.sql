CREATE MATERIALIZED VIEW IF NOT EXISTS ip_stats_1h_mv TO ip_stats_1h AS
SELECT
    app_id,
    toStartOfHour(ts) AS hour,
    client_ip,
    count()                                 AS requests,
    sum(anomaly_score)                      AS anomaly,
    countIf(status >= 400 AND status < 500) AS s4xx,
    countIf(status >= 500)                  AS s5xx,
    countIf(would_block = 1)                AS blocked,
    uniqState(path)                         AS paths
FROM traffic
GROUP BY app_id, hour, client_ip
