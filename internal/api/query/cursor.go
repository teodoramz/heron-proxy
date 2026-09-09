package query

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Cursor marks a position in a result set, ordered by (ts, id).
type Cursor struct {
	TS time.Time
	ID string
}

// EncodeCursor renders a cursor as an opaque token.
func EncodeCursor(c Cursor) string {
	raw := strconv.FormatInt(c.TS.UnixMilli(), 10) + "|" + c.ID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor parses a token produced by EncodeCursor.
func DecodeCursor(token string) (Cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Cursor{}, fmt.Errorf("query: invalid cursor encoding: %w", err)
	}
	millis, id, found := strings.Cut(string(raw), "|")
	if !found {
		return Cursor{}, fmt.Errorf("query: malformed cursor")
	}
	ms, err := strconv.ParseInt(millis, 10, 64)
	if err != nil {
		return Cursor{}, fmt.Errorf("query: invalid cursor timestamp: %w", err)
	}
	if !validUUID(id) {
		return Cursor{}, fmt.Errorf("query: invalid cursor id")
	}
	return Cursor{TS: time.UnixMilli(ms).UTC(), ID: id}, nil
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
