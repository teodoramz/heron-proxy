package query

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Cursor marks a position in a result set.
//
// The timestamp and id are always present and together are unique, which is
// what makes the ordering total. Sort carries the value of the column being
// ordered by, when that is not the timestamp.
type Cursor struct {
	TS   time.Time `json:"t"`
	ID   string    `json:"i"`
	Sort any       `json:"v,omitempty"`
}

type wireCursor struct {
	Millis int64  `json:"t"`
	ID     string `json:"i"`
	Sort   any    `json:"v,omitempty"`
}

// EncodeCursor renders a cursor as an opaque token.
func EncodeCursor(c Cursor) string {
	body, err := json.Marshal(wireCursor{Millis: c.TS.UnixMilli(), ID: c.ID, Sort: c.Sort})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(body)
}

// DecodeCursor parses a token produced by EncodeCursor.
func DecodeCursor(token string) (Cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Cursor{}, fmt.Errorf("query: invalid cursor encoding: %w", err)
	}
	var w wireCursor
	if err := json.Unmarshal(raw, &w); err != nil {
		return Cursor{}, fmt.Errorf("query: malformed cursor")
	}
	if !validUUID(w.ID) {
		return Cursor{}, fmt.Errorf("query: invalid cursor id")
	}
	return Cursor{TS: time.UnixMilli(w.Millis).UTC(), ID: w.ID, Sort: w.Sort}, nil
}

// validUUID checks the canonical 8-4-4-4-12 hexadecimal form.
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
