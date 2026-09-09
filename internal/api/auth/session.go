package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidSession reports a token that is malformed, forged or expired.
var ErrInvalidSession = errors.New("auth: invalid session")

// Signer issues and verifies session tokens. Tokens are stateless: they carry
// the user ID and an expiry, authenticated with HMAC-SHA256. Revocation happens
// by disabling the user, which is checked on every request.
type Signer struct {
	key []byte
	ttl time.Duration
}

// NewSigner returns a Signer. An empty key generates a random one, which
// invalidates existing sessions on restart.
func NewSigner(key []byte, ttl time.Duration) (*Signer, error) {
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("auth: session key: %w", err)
		}
	}
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &Signer{key: key, ttl: ttl}, nil
}

// TTL returns the session lifetime.
func (s *Signer) TTL() time.Duration { return s.ttl }

// Issue returns a signed token for a user.
func (s *Signer) Issue(userID string) string {
	expiry := time.Now().Add(s.ttl).UnixMilli()
	payload := userID + "|" + strconv.FormatInt(expiry, 10)
	return payload + "|" + s.sign(payload)
}

// Verify returns the user ID carried by a valid token.
func (s *Signer) Verify(token string) (string, error) {
	idx := strings.LastIndex(token, "|")
	if idx < 0 {
		return "", ErrInvalidSession
	}
	payload, mac := token[:idx], token[idx+1:]
	if !hmac.Equal([]byte(s.sign(payload)), []byte(mac)) {
		return "", ErrInvalidSession
	}
	userID, expiryStr, found := strings.Cut(payload, "|")
	if !found {
		return "", ErrInvalidSession
	}
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return "", ErrInvalidSession
	}
	if time.Now().UnixMilli() > expiry {
		return "", ErrInvalidSession
	}
	return userID, nil
}

func (s *Signer) sign(payload string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// NewCSRFToken returns a random token for the double-submit cookie pattern.
func NewCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: csrf token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
