// Package event defines the traffic record produced by the proxy and stored in ClickHouse.
package event

import (
	"net/netip"
	"time"
)

// Event is one recorded HTTP transaction. Field order matches the ClickHouse
// column order used by the batch writer.
type Event struct {
	TS    time.Time `json:"ts"`
	ID    string    `json:"id"`
	AppID string    `json:"app_id"`

	ClientIP        netip.Addr `json:"client_ip"`
	ClientIPClaimed netip.Addr `json:"client_ip_claimed"`
	ClientPort      uint16     `json:"client_port"`
	Country         string     `json:"country"`
	ASN             uint32     `json:"asn"`
	ASOrg           string     `json:"as_org"`
	JA3             string     `json:"ja3"`
	JA4             string     `json:"ja4"`

	Method       string            `json:"method"`
	Scheme       string            `json:"scheme"`
	Host         string            `json:"host"`
	Path         string            `json:"path"`
	Query        string            `json:"query"`
	HTTPVersion  string            `json:"http_version"`
	ReqHeaders   map[string]string `json:"req_headers"`
	ReqBodySize  uint64            `json:"req_body_size"`
	ReqBody      string            `json:"req_body_inline"`
	ReqBodySHA   string            `json:"req_body_sha256"`
	ReqBodyBlob  string            `json:"req_body_blob"`
	ReqTruncated bool              `json:"req_truncated"`
	UserAgent    string            `json:"user_agent"`

	Status          uint16            `json:"status"`
	RespHeaders     map[string]string `json:"resp_headers"`
	RespSize        uint64            `json:"resp_size"`
	RespContentType string            `json:"resp_content_type"`

	DurationMS uint32 `json:"duration_ms"`
	UpstreamMS uint32 `json:"upstream_ms"`
	WAFMS      uint32 `json:"waf_ms"`

	AnomalyScore uint16   `json:"anomaly_score"`
	RuleIDs      []uint32 `json:"rule_ids"`
	RuleMsgs     []string `json:"rule_msgs"`
	RuleTags     []string `json:"rule_tags"`
	RuleSeverity uint8    `json:"rule_severity"`
	ParanoiaMax  uint8    `json:"paranoia_max"`
	WouldBlock   bool     `json:"would_block"`

	Upstream    string `json:"upstream"`
	Error       string `json:"error"`
	IsWebsocket bool   `json:"is_websocket"`
}
