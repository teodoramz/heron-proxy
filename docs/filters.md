# Filters

Filters compose with AND/OR groups and negation, serialize into the URL so any
view is a shareable link, and can be saved per person or shared with the team.

Every filter is translated through an allowlist of columns and operators, and
every value is bound as a parameter.

## Fields

### Time and scope

| Field | Operators | Notes |
| --- | --- | --- |
| time range | — | Always applied. Set from the range buttons. |
| `app_id` | `eq` `ne` `in` `contains` `prefix` | Also set by the app selector. |

### Request

| Field | Operators | Notes |
| --- | --- | --- |
| `method` | `eq` `ne` `in` `contains` `prefix` | |
| `scheme` | `eq` `ne` `in` | `http` or `https`. |
| `host` | `eq` `ne` `contains` `prefix` `suffix` `regex` `in` | |
| `path` | `eq` `ne` `contains` `prefix` `suffix` `regex` `in` | Token-indexed. |
| `query` | `eq` `ne` `contains` `prefix` `suffix` `regex` | Raw query string, after redaction. |
| `http_version` | `eq` `ne` `in` | |
| `user_agent` | `eq` `ne` `contains` `prefix` `regex` | Token-indexed. |
| `body` | `eq` `ne` `contains` `prefix` `regex` | The stored request body. Token-indexed. |
| `req_body_size` | `eq` `ne` `lt` `lte` `gt` `gte` `in` | True size, even when truncated. |
| `req_truncated` | `eq` | Body exceeded the capture cap. |
| `req_header` | `eq` `contains` `exists` | Needs a header name. |

### Response

| Field | Operators | Notes |
| --- | --- | --- |
| `status` | `eq` `ne` `lt` `lte` `gt` `gte` `in` | `gte 400` for errors, `in [401,403]` for auth failures. |
| `resp_size` | `eq` `ne` `lt` `lte` `gt` `gte` | |
| `resp_content_type` | `eq` `ne` `in` `contains` | |
| `resp_header` | `eq` `contains` `exists` | Needs a header name. |

### Source

| Field | Operators | Notes |
| --- | --- | --- |
| `client_ip` | `eq` `ne` `cidr` `in` | The attributed address. `cidr` accepts IPv4 and IPv6. |
| `client_ip_claimed` | `eq` `ne` `cidr` `in` | The `X-Forwarded-For` value, believed or not. |
| `country` | `eq` `ne` `in` | Two-letter code. Needs the GeoIP database. |
| `asn` | `eq` `ne` `lt` `gt` `in` | Needs the ASN database. |
| `as_org` | `eq` `contains` `prefix` | |
| `ja3` | `eq` `ne` `contains` `prefix` | MD5 of the JA3 string. |
| `ja4` | `eq` `ne` `contains` `prefix` | Prefix-match to group by TLS stack. |

### WAF

| Field | Operators | Notes |
| --- | --- | --- |
| `rule_id` | `has` `in` | `has 942100` for one rule; `in` for any of several. |
| `rule_tag` | `has` `in` | For example `attack-sqli`, `attack-xss`, `attack-lfi`. |
| `anomaly_score` | `eq` `lt` `lte` `gt` `gte` `in` | |
| `rule_severity` | `eq` `lt` `gt` `gte` | Higher is more severe: critical 5, error 4, warning 3, notice 2. |
| `paranoia_max` | `eq` `lt` `gt` `gte` | Highest paranoia level among the rules that fired. |
| `would_block` | `eq` | CRS would have blocked this request. |

### Operational

| Field | Operators | Notes |
| --- | --- | --- |
| `duration_ms` | `eq` `lt` `lte` `gt` `gte` | Total time through the proxy. |
| `upstream_ms` | `eq` `lt` `gt` `gte` | Time the upstream took. |
| `waf_ms` | `eq` `lt` `gt` `gte` | Time rule evaluation took. |
| `upstream` | `eq` `contains` `prefix` | The resolved upstream URL. |
| `error` | `eq` `contains` `exists` | `exists` finds every failed request. |
| `is_websocket` | `eq` | |
| `id` | `eq` `in` | Event UUID, matching the `X-Request-Id` in your app logs. |

## Operators

| Operator | Meaning |
| --- | --- |
| `eq`, `ne` | Exact match. |
| `lt`, `lte`, `gt`, `gte` | Numeric comparison. |
| `in` | Any of a list. |
| `contains` | Case-insensitive substring. |
| `prefix`, `suffix` | Starts or ends with. |
| `regex` | RE2 match, up to 256 characters. |
| `cidr` | Address inside a prefix. |
| `has` | Array contains the value. |
| `exists` | Field is present and non-empty. |

## Examples

Requests CRS would have blocked, on one app:

```
app_id eq shop
would_block eq true
```

SQL injection attempts from outside a known network:

```
rule_tag has attack-sqli
NOT ( client_ip cidr 10.0.0.0/8 )
```

Slow authenticated writes:

```
method in [POST, PUT, PATCH]
duration_ms gte 1000
req_header exists authorization
```

One actor across a whole session, regardless of address:

```
ja4 eq t13d1516h2_8daaf6152771_02713d6af862
```

## Counts and paging

Counts are exact below 10,000 rows and shown as `10,000+` above it. Paging is
keyset on `(timestamp, id)`, so deep pages cost the same as the first.
