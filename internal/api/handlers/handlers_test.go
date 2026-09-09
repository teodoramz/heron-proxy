package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/amzteodor/heron/internal/api"
	"github.com/amzteodor/heron/internal/api/auth"
	"github.com/amzteodor/heron/internal/api/handlers"
	"github.com/amzteodor/heron/internal/api/reader"
	"github.com/amzteodor/heron/internal/config"
	"github.com/amzteodor/heron/internal/pipeline/blob"
	"github.com/amzteodor/heron/internal/pipeline/chsink"
	"github.com/amzteodor/heron/internal/pipeline/event"
	"github.com/amzteodor/heron/internal/store"
)

var seedTime = time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

type harness struct {
	server *httptest.Server
	store  *store.Store
	events []event.Event
}

// newHarness builds the full API against the live test databases.
func newHarness(t *testing.T) *harness {
	t.Helper()
	pgDSN := os.Getenv("POSTGRES_TEST_DSN")
	chDSN := os.Getenv("CLICKHOUSE_TEST_DSN")
	if pgDSN == "" || chDSN == "" {
		t.Skip("POSTGRES_TEST_DSN and CLICKHOUSE_TEST_DSN must both be set")
	}
	ctx := context.Background()

	db, err := store.Open(ctx, pgDSN, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Pool().Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	ch, err := chsink.Open(chDSN)
	if err != nil {
		t.Fatalf("chsink.Open: %v", err)
	}
	t.Cleanup(func() { ch.Close() })
	if err := ch.Migrate(ctx); err != nil {
		t.Fatalf("chsink.Migrate: %v", err)
	}
	for _, table := range []string{"traffic", "traffic_stats_1m", "rule_hits_1h", "ip_stats_1h"} {
		if err := ch.Conn().Exec(ctx, "TRUNCATE TABLE IF EXISTS "+table); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
	events := seedEvents()
	if err := ch.WriteBatch(ctx, events); err != nil {
		t.Fatalf("seed traffic: %v", err)
	}

	for _, id := range []string{"api", "web"} {
		app := config.App{
			ID: id, Name: id, Hostnames: []string{id + ".example"},
			UpstreamURL: "http://127.0.0.1:9", Enabled: true,
			Capture: config.DefaultCapture(), Redaction: config.DefaultRedaction(), WAF: config.DefaultWAF(),
		}
		if err := db.SaveApp(ctx, app); err != nil {
			t.Fatalf("SaveApp: %v", err)
		}
	}

	signer, err := auth.NewSigner([]byte("test-session-key"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mw := &auth.Middleware{Signer: signer, Store: db}
	h := &handlers.Handler{
		Reader: reader.New(ch.Conn()),
		Store:  db,
		Blobs:  blob.New(t.TempDir()),
		Auth:   mw,
		Logger: newTestLogger(),
	}
	srv := httptest.NewServer(api.NewRouter(api.Options{Handler: h, Auth: mw}))
	t.Cleanup(srv.Close)

	return &harness{server: srv, store: db, events: events}
}

func seedEvents() []event.Event {
	mk := func(i int, app, method, path string, status, anomaly uint16, ip string, rules []uint32, tags []string, block bool) event.Event {
		return event.Event{
			TS:            seedTime.Add(time.Duration(i) * time.Minute),
			ID:            uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprintf("api-event-%d", i))).String(),
			AppID:         app,
			RetentionDays: 90,
			ClientIP:      netip.MustParseAddr(ip),
			Country:       "DE",
			ASN:           64512,
			JA4:           "t13d1516h2_8daaf6152771_02713d6af862",
			Method:        method,
			Scheme:        "https",
			Host:          app + ".example",
			Path:          path,
			Query:         "page=1",
			HTTPVersion:   "HTTP/1.1",
			ReqHeaders:    map[string]string{"user-agent": "curl/8"},
			ReqBody:       `{"secret":"value"}`,
			ReqBodySize:   18,
			UserAgent:     "curl/8",
			Status:        status,
			RespHeaders:   map[string]string{"server": "nginx"},
			RespSize:      100,
			DurationMS:    12,
			AnomalyScore:  anomaly,
			RuleIDs:       rules,
			RuleMsgs:      []string{"detected"},
			RuleTags:      tags,
			WouldBlock:    block,
		}
	}
	return []event.Event{
		mk(0, "api", "GET", "/v1/users", 200, 0, "203.0.113.1", nil, nil, false),
		mk(1, "api", "POST", "/v1/login", 403, 15, "203.0.113.9", []uint32{942100}, []string{"attack-sqli"}, true),
		mk(2, "web", "GET", "/index.html", 200, 0, "198.51.100.4", nil, nil, false),
	}
}

// client is an authenticated API client that carries session and CSRF state.
type client struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

// login creates a user with the given role and returns a client signed in as them.
func (h *harness) login(t *testing.T, username string, role store.Role, apps []string) *client {
	t.Helper()
	ctx := context.Background()
	const password = "correct-horse-battery-staple"

	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	user, err := h.store.CreateUser(ctx, username, hash, role)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if len(apps) > 0 {
		if err := h.store.SetAppAccess(ctx, user.ID, apps); err != nil {
			t.Fatal(err)
		}
	}

	jar := newJar()
	c := &client{t: t, base: h.server.URL, http: &http.Client{Jar: jar}}
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := c.http.Post(c.base+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	c.csrf = out.CSRFToken
	return c
}

func (c *client) do(method, path string, body any) *http.Response {
	c.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(auth.CSRFHeader, c.csrf)
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func (c *client) get(path string) *http.Response { return c.do(http.MethodGet, path, nil) }

// decode reads a JSON response, failing if the status is unexpected.
func (c *client) decode(resp *http.Response, want int, out any) {
	c.t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != want {
		var body bytes.Buffer
		body.ReadFrom(resp.Body)
		c.t.Fatalf("status = %d, want %d: %s", resp.StatusCode, want, body.String())
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			c.t.Fatalf("decode: %v", err)
		}
	}
}
