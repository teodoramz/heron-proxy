package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amzteodor/heron/internal/store"
)

type fakeUsers struct {
	users map[string]store.User
	apps  map[string][]string
	err   error
}

func (f *fakeUsers) GetUser(_ context.Context, id string) (store.User, error) {
	if f.err != nil {
		return store.User{}, f.err
	}
	u, ok := f.users[id]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) AppAccess(_ context.Context, id string) ([]string, error) {
	return f.apps[id], nil
}

func newMiddleware(t *testing.T, users *fakeUsers) *Middleware {
	t.Helper()
	signer, err := NewSigner([]byte("test-session-key-0123456789abcdef"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &Middleware{Signer: signer, Store: users}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash format = %q", hash)
	}
	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Errorf("correct password rejected: ok=%v err=%v", ok, err)
	}
	ok, _ = VerifyPassword("wrong password", hash)
	if ok {
		t.Error("wrong password accepted")
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Error("identical passwords produced identical hashes")
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	for _, h := range []string{"", "plaintext", "$argon2id$broken", "$bcrypt$v=19$m=1,t=1,p=1$a$b"} {
		if _, err := VerifyPassword("x", h); err == nil {
			t.Errorf("VerifyPassword(%q) returned no error", h)
		}
	}
}

func TestSessionRoundTrip(t *testing.T) {
	s, _ := NewSigner([]byte("key"), time.Hour)
	token := s.Issue("user-1")
	got, err := s.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != "user-1" {
		t.Errorf("user = %q", got)
	}
}

func TestSessionRejectsTampering(t *testing.T) {
	s, _ := NewSigner([]byte("key"), time.Hour)
	token := s.Issue("user-1")
	forged := strings.Replace(token, "user-1", "user-2", 1)
	if _, err := s.Verify(forged); err == nil {
		t.Error("tampered token accepted")
	}
}

func TestSessionRejectsWrongKey(t *testing.T) {
	a, _ := NewSigner([]byte("key-a"), time.Hour)
	b, _ := NewSigner([]byte("key-b"), time.Hour)
	if _, err := b.Verify(a.Issue("user-1")); err == nil {
		t.Error("token signed with another key accepted")
	}
}

func TestSessionExpires(t *testing.T) {
	s, _ := NewSigner([]byte("key"), time.Nanosecond)
	token := s.Issue("user-1")
	time.Sleep(2 * time.Millisecond)
	if _, err := s.Verify(token); err == nil {
		t.Error("expired token accepted")
	}
}

func TestSessionRejectsGarbage(t *testing.T) {
	s, _ := NewSigner([]byte("key"), time.Hour)
	for _, token := range []string{"", "nopipe", "a|b|c"} {
		if _, err := s.Verify(token); err == nil {
			t.Errorf("Verify(%q) accepted", token)
		}
	}
}

func TestAuthenticateRequiresCookie(t *testing.T) {
	m := newMiddleware(t, &fakeUsers{users: map[string]store.User{}})
	rec := httptest.NewRecorder()
	m.Authenticate(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAuthenticateAcceptsValidSession(t *testing.T) {
	users := &fakeUsers{
		users: map[string]store.User{"u1": {ID: "u1", Role: store.RoleAnalyst, Enabled: true}},
		apps:  map[string][]string{"u1": {"app1"}},
	}
	m := newMiddleware(t, users)

	var seen Session
	handler := m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: m.Signer.Issue("u1")})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if seen.User.ID != "u1" || len(seen.Apps) != 1 {
		t.Errorf("session = %+v", seen)
	}
}

func TestAuthenticateRejectsDisabledUser(t *testing.T) {
	users := &fakeUsers{users: map[string]store.User{"u1": {ID: "u1", Enabled: false}}}
	m := newMiddleware(t, users)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: m.Signer.Issue("u1")})
	rec := httptest.NewRecorder()
	m.Authenticate(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a disabled account", rec.Code)
	}
}

func TestRequireRole(t *testing.T) {
	cases := []struct {
		have store.Role
		need store.Role
		want int
	}{
		{store.RoleAdmin, store.RoleAdmin, http.StatusOK},
		{store.RoleAdmin, store.RoleAnalyst, http.StatusOK},
		{store.RoleAnalyst, store.RoleAnalyst, http.StatusOK},
		{store.RoleAnalyst, store.RoleAdmin, http.StatusForbidden},
	}
	for _, c := range cases {
		users := &fakeUsers{users: map[string]store.User{"u1": {ID: "u1", Role: c.have, Enabled: true}}}
		m := newMiddleware(t, users)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: m.Signer.Issue("u1")})
		rec := httptest.NewRecorder()
		m.Authenticate(RequireRole(c.need)(okHandler())).ServeHTTP(rec, req)

		if rec.Code != c.want {
			t.Errorf("role %s needing %s: status = %d, want %d", c.have, c.need, rec.Code, c.want)
		}
	}
}

func TestRequireRoleWithoutSession(t *testing.T) {
	rec := httptest.NewRecorder()
	RequireRole(store.RoleAnalyst)(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCSRFAllowsSafeMethods(t *testing.T) {
	m := newMiddleware(t, &fakeUsers{})
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		rec := httptest.NewRecorder()
		m.CSRF(okHandler()).ServeHTTP(rec, httptest.NewRequest(method, "/", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s blocked by CSRF: %d", method, rec.Code)
		}
	}
}

func TestCSRFRejectsMissingToken(t *testing.T) {
	m := newMiddleware(t, &fakeUsers{})
	rec := httptest.NewRecorder()
	m.CSRF(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestCSRFRejectsMismatch(t *testing.T) {
	m := newMiddleware(t, &fakeUsers{})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "cookie-value"})
	req.Header.Set(CSRFHeader, "header-value")
	rec := httptest.NewRecorder()
	m.CSRF(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestCSRFAcceptsMatch(t *testing.T) {
	m := newMiddleware(t, &fakeUsers{})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "same"})
	req.Header.Set(CSRFHeader, "same")
	rec := httptest.NewRecorder()
	m.CSRF(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSetAndClearSessionCookies(t *testing.T) {
	m := newMiddleware(t, &fakeUsers{})
	rec := httptest.NewRecorder()
	csrf, err := m.SetSessionCookies(rec, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if csrf == "" {
		t.Error("empty CSRF token")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("got %d cookies, want 2", len(cookies))
	}
	for _, c := range cookies {
		if c.Name == SessionCookie && !c.HttpOnly {
			t.Error("session cookie is not HttpOnly")
		}
		if c.Name == CSRFCookie && c.HttpOnly {
			t.Error("CSRF cookie must be readable by the browser")
		}
	}

	rec2 := httptest.NewRecorder()
	m.ClearSessionCookies(rec2)
	for _, c := range rec2.Result().Cookies() {
		if c.MaxAge >= 0 {
			t.Errorf("cookie %s not expired", c.Name)
		}
	}
}

func TestSessionAppScoping(t *testing.T) {
	s := Session{Apps: []string{"a"}}
	if !s.CanSeeApp("a") || s.CanSeeApp("b") {
		t.Error("scoping wrong")
	}
	if !(Session{}).CanSeeApp("anything") {
		t.Error("empty scope must mean all apps")
	}
}
