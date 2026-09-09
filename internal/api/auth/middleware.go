package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/amzteodor/proxy-waf/internal/store"
)

// Cookie names.
const (
	SessionCookie = "pw_session"
	CSRFCookie    = "pw_csrf"
	CSRFHeader    = "X-CSRF-Token"
)

// UserStore is the subset of the configuration store the middleware needs.
type UserStore interface {
	GetUser(ctx context.Context, id string) (store.User, error)
	AppAccess(ctx context.Context, userID string) ([]string, error)
}

type ctxKey struct{}

// Session is the authenticated caller.
type Session struct {
	User store.User
	Apps []string // empty means every app
}

// CanSeeApp reports whether the session may view an app.
func (s Session) CanSeeApp(appID string) bool {
	if len(s.Apps) == 0 {
		return true
	}
	for _, id := range s.Apps {
		if id == appID {
			return true
		}
	}
	return false
}

// Middleware authenticates requests and enforces CSRF on mutations.
type Middleware struct {
	Signer *Signer
	Store  UserStore
	Secure bool
	Logger *slog.Logger
}

// Authenticate rejects requests without a valid session.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		userID, err := m.Signer.Verify(cookie.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "session expired")
			return
		}
		user, err := m.Store.GetUser(r.Context(), userID)
		if err != nil || !user.Enabled {
			writeError(w, http.StatusUnauthorized, "account unavailable")
			return
		}
		apps, err := m.Store.AppAccess(r.Context(), userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not resolve access")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, Session{User: user, Apps: apps})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CSRF rejects unsafe methods whose header does not match the CSRF cookie.
func (m *Middleware) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(CSRFCookie)
		header := r.Header.Get(CSRFHeader)
		if err != nil || header == "" ||
			subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			writeError(w, http.StatusForbidden, "csrf token mismatch")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole gates a handler on a minimum role.
func RequireRole(min store.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, ok := FromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if !s.User.Role.AtLeast(min) {
				writeError(w, http.StatusForbidden, "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// FromContext returns the authenticated session.
func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(Session)
	return s, ok
}

// SetSessionCookies writes the session and CSRF cookies.
func (m *Middleware) SetSessionCookies(w http.ResponseWriter, userID string) (string, error) {
	csrf, err := NewCSRFToken()
	if err != nil {
		return "", err
	}
	expires := time.Now().Add(m.Signer.TTL())
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    m.Signer.Issue(userID),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookie,
		Value:    csrf,
		Path:     "/",
		HttpOnly: false, // the browser must read it to echo it back
		Secure:   m.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	return csrf, nil
}

// ClearSessionCookies expires both cookies.
func (m *Middleware) ClearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{SessionCookie, CSRFCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == SessionCookie, Secure: m.Secure,
		})
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
