package handlers_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amzteodor/heron/internal/store"
)

func TestLoginRejectsBadCredentials(t *testing.T) {
	h := newHarness(t)
	h.login(t, "admin", store.RoleAdmin, nil)

	c := &client{t: t, base: h.server.URL, http: &http.Client{Jar: newJar()}}
	resp := c.do(http.MethodPost, "/api/auth/login",
		map[string]string{"username": "admin", "password": "wrong"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestLoginRejectsUnknownEmail(t *testing.T) {
	h := newHarness(t)
	c := &client{t: t, base: h.server.URL, http: &http.Client{Jar: newJar()}}
	resp := c.do(http.MethodPost, "/api/auth/login",
		map[string]string{"username": "nobody", "password": "whatever12345"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestUnauthenticatedRequestsRejected(t *testing.T) {
	h := newHarness(t)
	c := &client{t: t, base: h.server.URL, http: &http.Client{Jar: newJar()}}
	for _, path := range []string{"/api/traffic", "/api/me", "/api/apps", "/api/stats/summary"} {
		resp := c.get(path)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401", path, resp.StatusCode)
		}
	}
}

func TestMe(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)

	var out struct {
		User store.User `json:"user"`
	}
	c.decode(c.get("/api/me"), http.StatusOK, &out)
	if out.User.Username != "reader" || out.User.Role != store.RoleAnalyst {
		t.Errorf("user = %+v", out.User)
	}
}

func TestListTraffic(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)

	var page struct {
		Events []map[string]any `json:"events"`
	}
	c.decode(c.get("/api/traffic?"+seedRange()), http.StatusOK, &page)
	if len(page.Events) != 3 {
		t.Fatalf("got %d events, want 3", len(page.Events))
	}
}

func TestTrafficSearchWithFilter(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)

	filter := map[string]any{
		"from": seedTime.Add(-time.Hour).Format(time.RFC3339),
		"to":   seedTime.Add(time.Hour).Format(time.RFC3339),
		"root": map[string]any{
			"op": "and",
			"conditions": []map[string]any{
				{"field": "would_block", "op": "eq", "value": true},
			},
		},
	}
	var page struct {
		Events []map[string]any `json:"events"`
	}
	c.decode(c.do(http.MethodPost, "/api/traffic/search", filter), http.StatusOK, &page)
	if len(page.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(page.Events))
	}
	if page.Events[0]["path"] != "/v1/login" {
		t.Errorf("path = %v", page.Events[0]["path"])
	}
}

func TestTrafficRejectsUnknownFilterField(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)

	filter := map[string]any{"root": map[string]any{"op": "and", "conditions": []map[string]any{
		{"field": "password", "op": "eq", "value": "x"},
	}}}
	resp := c.do(http.MethodPost, "/api/traffic/search", filter)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAppScopingHidesOtherApps(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "scoped", store.RoleAnalyst, []string{"web"})

	var page struct {
		Events []map[string]any `json:"events"`
	}
	c.decode(c.get("/api/traffic?"+seedRange()), http.StatusOK, &page)
	if len(page.Events) != 1 {
		t.Fatalf("got %d events, want only the web app's", len(page.Events))
	}
	if page.Events[0]["app_id"] != "web" {
		t.Errorf("app_id = %v", page.Events[0]["app_id"])
	}
}

// TestScopedUserCannotWidenScope is the important half of app scoping: asking
// for another app explicitly must not grant access to it.
func TestScopedUserCannotWidenScope(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "scoped", store.RoleAnalyst, []string{"web"})

	resp := c.get("/api/traffic?app=api&" + seedRange())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestGetTrafficDetail(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)

	var detail map[string]any
	c.decode(c.get("/api/traffic/"+h.events[1].ID), http.StatusOK, &detail)
	if detail["path"] != "/v1/login" {
		t.Errorf("path = %v", detail["path"])
	}
	rules, _ := detail["matched_rules"].([]any)
	if len(rules) != 1 {
		t.Errorf("matched_rules = %v", detail["matched_rules"])
	}
	if detail["body"] == nil || !strings.Contains(detail["body"].(string), "secret") {
		t.Errorf("analyst should see the body, got %v", detail["body"])
	}
}

func TestGetTrafficMissing(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)
	resp := c.get("/api/traffic/3a1f2b4c-5d6e-4f70-8192-a3b4c5d6e7f8")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestExportFormats(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)
	id := h.events[1].ID

	resp := c.get("/api/traffic/" + id + "/export")
	body := readAll(t, resp, http.StatusOK)
	if !strings.HasPrefix(body, "POST /v1/login") {
		t.Errorf("raw export = %q", body)
	}

	resp = c.get("/api/traffic/" + id + "/export?format=curl")
	body = readAll(t, resp, http.StatusOK)
	if !strings.HasPrefix(body, "curl -X POST") {
		t.Errorf("curl export = %q", body)
	}

	var har map[string]any
	c.decode(c.get("/api/traffic/"+id+"/export?format=har"), http.StatusOK, &har)
	if har["log"] == nil {
		t.Errorf("har export = %v", har)
	}
}

func TestCount(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)

	var out struct {
		Count  int  `json:"count"`
		Capped bool `json:"capped"`
	}
	c.decode(c.get("/api/traffic/count?"+seedRange()), http.StatusOK, &out)
	if out.Count != 3 || out.Capped {
		t.Errorf("count = %d capped = %v", out.Count, out.Capped)
	}
}

func TestStatsEndpoints(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)
	rng := "?" + seedRange()

	var summary struct {
		Requests int `json:"requests"`
	}
	c.decode(c.get("/api/stats/summary"+rng), http.StatusOK, &summary)
	if summary.Requests != 3 {
		t.Errorf("requests = %d, want 3", summary.Requests)
	}

	for _, path := range []string{"/api/stats/series", "/api/stats/rules", "/api/stats/ips",
		"/api/stats/top/path", "/api/simulate"} {
		resp := c.get(path + rng)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d", path, resp.StatusCode)
		}
	}
}

func TestSimulateThreshold(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)

	var sim struct {
		Total      int `json:"total"`
		WouldBlock int `json:"would_block"`
	}
	c.decode(c.get("/api/simulate?threshold=5&"+seedRange()),
		http.StatusOK, &sim)
	if sim.Total != 3 || sim.WouldBlock != 1 {
		t.Errorf("total=%d blocked=%d, want 3 and 1", sim.Total, sim.WouldBlock)
	}
}

func TestSimulateRejectsBadThreshold(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)
	resp := c.get("/api/simulate?threshold=abc")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestIPProfile(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)

	var profile struct {
		ClientIP string `json:"client_ip"`
		Stat     struct {
			Requests int `json:"requests"`
		} `json:"stat"`
	}
	c.decode(c.get("/api/ip/203.0.113.9?"+seedRange()),
		http.StatusOK, &profile)
	if profile.Stat.Requests != 1 {
		t.Errorf("requests = %d, want 1", profile.Stat.Requests)
	}
}

func TestRoleGating(t *testing.T) {
	h := newHarness(t)
	analyst := h.login(t, "analyst", store.RoleAnalyst, nil)

	// An analyst may not manage apps.
	resp := analyst.do(http.MethodPost, "/api/apps", map[string]any{
		"id": "new", "hostnames": []string{"new.example"}, "upstream_url": "http://127.0.0.1:9",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("analyst create app = %d, want 403", resp.StatusCode)
	}

	// Analyst may not list users.
	resp = analyst.get("/api/users")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("analyst list users = %d, want 403", resp.StatusCode)
	}
}

func TestCSRFRequiredForMutations(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)
	c.csrf = "" // drop the token

	resp := c.do(http.MethodPost, "/api/apps", map[string]any{"id": "x"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 without a CSRF token", resp.StatusCode)
	}
}

func TestAppCRUD(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	app := map[string]any{
		"id": "shop", "name": "Shop", "hostnames": []string{"shop.example"},
		"upstream_url": "https://10.0.0.5:8443", "enabled": true,
	}
	c.decode(c.do(http.MethodPost, "/api/apps", app), http.StatusOK, nil)

	var got map[string]any
	c.decode(c.get("/api/apps/shop"), http.StatusOK, &got)
	if got["name"] != "Shop" {
		t.Errorf("name = %v", got["name"])
	}
	if got["client_ip_header"] != "X-Real-IP" {
		t.Errorf("defaults not applied: %v", got["client_ip_header"])
	}

	resp := c.do(http.MethodDelete, "/api/apps/shop", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d", resp.StatusCode)
	}
	resp = c.get("/api/apps/shop")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", resp.StatusCode)
	}
}

func TestAppValidation(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	cases := []map[string]any{
		{"id": "", "hostnames": []string{"a.example"}, "upstream_url": "http://127.0.0.1:9"},
		{"id": "a", "hostnames": []string{}, "upstream_url": "http://127.0.0.1:9"},
		{"id": "a", "hostnames": []string{"a.example"}, "upstream_url": "not-a-url"},
		{"id": "a", "hostnames": []string{"a.example"}, "upstream_url": "ftp://x/"},
	}
	for i, body := range cases {
		resp := c.do(http.MethodPost, "/api/apps", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("case %d: status = %d, want 400", i, resp.StatusCode)
		}
	}
}

func TestUserManagement(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	var created struct {
		ID string `json:"id"`
	}
	c.decode(c.do(http.MethodPost, "/api/users", map[string]any{
		"username": "newcomer", "password": "a-long-enough-password", "role": "analyst",
	}), http.StatusCreated, &created)

	resp := c.do(http.MethodPatch, "/api/users/"+created.ID,
		map[string]any{"role": "analyst", "enabled": true})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("patch = %d", resp.StatusCode)
	}

	resp = c.do(http.MethodDelete, "/api/users/"+created.ID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d", resp.StatusCode)
	}
}

func TestUserCreationValidation(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	for _, body := range []map[string]any{
		{"username": "shorty", "password": "short", "role": "admin"},
		{"username": "", "password": "a-long-enough-password", "role": "admin"},
		{"username": "rooty", "password": "a-long-enough-password", "role": "root"},
	} {
		resp := c.do(http.MethodPost, "/api/users", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body %v: status = %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestAdminCannotDeleteSelf(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	var me struct {
		User store.User `json:"user"`
	}
	c.decode(c.get("/api/me"), http.StatusOK, &me)

	resp := c.do(http.MethodDelete, "/api/users/"+me.User.ID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAnnotationAndVerdictFlow(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)
	id := h.events[1].ID

	c.decode(c.do(http.MethodPost, "/api/traffic/"+id+"/annotate", map[string]any{
		"app_id": "api", "tags": []string{"recon"}, "note": "scanner", "bookmarked": true,
	}), http.StatusOK, nil)

	c.decode(c.do(http.MethodPost, "/api/traffic/"+id+"/verdict", map[string]any{
		"app_id": "api", "rule_id": 942100, "verdict": "false_positive", "note": "editor markup",
	}), http.StatusOK, nil)

	var detail map[string]any
	c.decode(c.get("/api/traffic/"+id), http.StatusOK, &detail)
	if detail["annotation"] == nil {
		t.Error("annotation not returned with the event")
	}
	marks, _ := detail["fp_marks"].([]any)
	if len(marks) != 1 {
		t.Errorf("fp_marks = %v", detail["fp_marks"])
	}

	var bookmarks struct {
		EventIDs []string `json:"event_ids"`
	}
	c.decode(c.get("/api/traffic/bookmarks"), http.StatusOK, &bookmarks)
	if len(bookmarks.EventIDs) != 1 || bookmarks.EventIDs[0] != id {
		t.Errorf("bookmarks = %v", bookmarks.EventIDs)
	}
}

func TestExclusionFlow(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)

	var preview struct {
		SecLang string `json:"seclang"`
	}
	c.decode(c.do(http.MethodPost, "/api/exclusions/preview", map[string]any{
		"rule_id": 942100, "target": "ARGS:comment",
	}), http.StatusOK, &preview)
	if preview.SecLang != `SecRuleUpdateTargetById 942100 "!ARGS:comment"` {
		t.Errorf("seclang = %q", preview.SecLang)
	}

	var created struct {
		ID      string `json:"id"`
		SecLang string `json:"seclang"`
	}
	c.decode(c.do(http.MethodPost, "/api/exclusions", map[string]any{
		"app_id": "api", "rule_id": 942100, "target": "ARGS:comment",
		"reason": "editor markup", "enabled": true,
	}), http.StatusCreated, &created)

	var list struct {
		Exclusions []map[string]any `json:"exclusions"`
	}
	c.decode(c.get("/api/exclusions?app=api"), http.StatusOK, &list)
	if len(list.Exclusions) != 1 {
		t.Fatalf("got %d exclusions", len(list.Exclusions))
	}

	resp := c.do(http.MethodPatch, "/api/exclusions/"+created.ID, map[string]any{"enabled": false})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("patch = %d", resp.StatusCode)
	}
	resp = c.do(http.MethodDelete, "/api/exclusions/"+created.ID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d", resp.StatusCode)
	}
}

// TestScopedUserCannotTouchAnotherAppsExclusion covers the whole exclusion
// surface: a scoped analyst must not read, disable or delete tuning that
// belongs to an app they were never granted.
func TestScopedUserCannotTouchAnotherAppsExclusion(t *testing.T) {
	h := newHarness(t)
	owner := h.login(t, "owner", store.RoleAnalyst, nil)

	var created struct {
		ID string `json:"id"`
	}
	owner.decode(owner.do(http.MethodPost, "/api/exclusions", map[string]any{
		"app_id": "api", "rule_id": 942100, "target": "ARGS:comment", "enabled": true,
	}), http.StatusCreated, &created)

	other := h.login(t, "scoped", store.RoleAnalyst, []string{"web"})

	var list struct {
		Exclusions []map[string]any `json:"exclusions"`
	}
	other.decode(other.get("/api/exclusions"), http.StatusOK, &list)
	for _, e := range list.Exclusions {
		if e["app_id"] != "web" {
			t.Errorf("listed an exclusion for %v", e["app_id"])
		}
	}

	resp := other.get("/api/exclusions?app=api")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("list by app = %d, want 403", resp.StatusCode)
	}

	resp = other.do(http.MethodPatch, "/api/exclusions/"+created.ID, map[string]any{"enabled": false})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("patch = %d, want 403", resp.StatusCode)
	}

	resp = other.do(http.MethodDelete, "/api/exclusions/"+created.ID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("delete = %d, want 403", resp.StatusCode)
	}
}

// TestVerdictAppComesFromTheEvent stops a scoped caller naming an app they can
// see while marking an event that belongs to one they cannot.
func TestVerdictAppComesFromTheEvent(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "scoped", store.RoleAnalyst, []string{"web"})

	var apiEvent string
	for _, e := range h.events {
		if e.AppID == "api" {
			apiEvent = e.ID
			break
		}
	}
	if apiEvent == "" {
		t.Skip("no seeded event for the api app")
	}

	resp := c.do(http.MethodPost, "/api/traffic/"+apiEvent+"/verdict", map[string]any{
		"app_id": "web", "rule_id": 942100, "verdict": "false_positive",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("verdict = %d, want 403", resp.StatusCode)
	}
}

func TestExclusionRequiresRuleID(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)
	resp := c.do(http.MethodPost, "/api/exclusions", map[string]any{"app_id": "api"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSavedFilters(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)

	var saved struct {
		ID string `json:"id"`
	}
	c.decode(c.do(http.MethodPost, "/api/filters", map[string]any{
		"name":  "blocked",
		"query": map[string]any{"root": map[string]any{"op": "and", "conditions": []map[string]any{{"field": "would_block", "op": "eq", "value": true}}}},
	}), http.StatusCreated, &saved)

	var list struct {
		Filters []map[string]any `json:"filters"`
	}
	c.decode(c.get("/api/filters"), http.StatusOK, &list)
	if len(list.Filters) != 1 {
		t.Fatalf("got %d filters", len(list.Filters))
	}

	resp := c.do(http.MethodDelete, "/api/filters/"+saved.ID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d", resp.StatusCode)
	}
}

func TestSavedFilterRejectsInvalidQuery(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)
	resp := c.do(http.MethodPost, "/api/filters", map[string]any{
		"name":  "bad",
		"query": map[string]any{"root": map[string]any{"op": "and", "conditions": []map[string]any{{"field": "nope", "op": "eq", "value": 1}}}},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestFilterSchema(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)

	var schema struct {
		Fields []struct {
			Field     string   `json:"field"`
			Kind      string   `json:"kind"`
			Operators []string `json:"operators"`
		} `json:"fields"`
	}
	c.decode(c.get("/api/filters/schema"), http.StatusOK, &schema)
	if len(schema.Fields) < 30 {
		t.Errorf("schema lists %d fields", len(schema.Fields))
	}
	for _, f := range schema.Fields {
		if len(f.Operators) == 0 {
			t.Errorf("field %q has no operators", f.Field)
		}
	}
}

func TestAlertCRUD(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	var created struct {
		ID string `json:"id"`
	}
	c.decode(c.do(http.MethodPost, "/api/alerts", map[string]any{
		"name": "sqli", "app_id": "api", "channel": "webhook",
		"target_url": "https://hook.example", "throttle_seconds": 60, "enabled": true,
		"condition": map[string]any{"rule_tags": []string{"attack-sqli"}},
	}), http.StatusOK, &created)

	var list struct {
		Alerts []map[string]any `json:"alerts"`
	}
	c.decode(c.get("/api/alerts"), http.StatusOK, &list)
	if len(list.Alerts) != 1 {
		t.Fatalf("got %d alerts", len(list.Alerts))
	}

	resp := c.do(http.MethodDelete, "/api/alerts/"+created.ID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d", resp.StatusCode)
	}
}

func TestAuditLogRecordsChanges(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	c.decode(c.do(http.MethodPost, "/api/apps", map[string]any{
		"id": "audited", "hostnames": []string{"audited.example"}, "upstream_url": "http://127.0.0.1:9",
	}), http.StatusOK, nil)

	var out struct {
		Entries []struct {
			Action string `json:"action"`
		} `json:"entries"`
	}
	c.decode(c.get("/api/audit"), http.StatusOK, &out)

	var found bool
	for _, e := range out.Entries {
		if e.Action == "app.save" {
			found = true
		}
	}
	if !found {
		t.Errorf("app.save not audited: %+v", out.Entries)
	}
}

func TestReplayRefusesPrivateCustomTarget(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	resp := c.do(http.MethodPost, "/api/traffic/"+h.events[0].ID+"/replay",
		map[string]any{"target": "http://169.254.169.254/latest/meta-data/"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for the metadata address", resp.StatusCode)
	}
}

func TestReplayCustomTargetRequiresAdmin(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "analyst", store.RoleAnalyst, nil)

	resp := c.do(http.MethodPost, "/api/traffic/"+h.events[0].ID+"/replay",
		map[string]any{"target": "https://example.com"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)

	resp := c.do(http.MethodPost, "/api/auth/logout", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	resp = c.get("/api/me")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("after logout = %d, want 401", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

// TestNewAppGetsWorkingDefaults guards the failure mode where omitted JSON
// fields become Go zero values, leaving a new app recording nothing.
func TestNewAppGetsWorkingDefaults(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	c.decode(c.do(http.MethodPost, "/api/apps", map[string]any{
		"id": "minimal", "hostnames": []string{"minimal.example"},
		"upstream_url": "http://127.0.0.1:9",
	}), http.StatusOK, nil)

	var got struct {
		Enabled bool `json:"enabled"`
		Capture struct {
			Enabled bool `json:"enabled"`
		} `json:"capture"`
		Redaction struct {
			Enabled bool `json:"enabled"`
		} `json:"redaction"`
		WAF struct {
			Enabled       bool `json:"enabled"`
			ParanoiaLevel int  `json:"paranoia_level"`
			Threshold     int  `json:"threshold"`
		} `json:"waf"`
	}
	c.decode(c.get("/api/apps/minimal"), http.StatusOK, &got)

	if !got.Enabled {
		t.Error("a new app is not enabled")
	}
	if !got.Capture.Enabled {
		t.Error("capture is off on a new app; nothing would be recorded")
	}
	if !got.Redaction.Enabled {
		t.Error("redaction is off on a new app; credentials would be stored in the clear")
	}
	if !got.WAF.Enabled || got.WAF.ParanoiaLevel != 1 || got.WAF.Threshold != 5 {
		t.Errorf("waf defaults wrong: %+v", got.WAF)
	}
}

// TestUpdateDoesNotResetOmittedFields checks the upsert merges rather than
// replaces, so a partial update cannot silently disable an app.
func TestUpdateDoesNotResetOmittedFields(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	c.decode(c.do(http.MethodPost, "/api/apps", map[string]any{
		"id": "merge", "hostnames": []string{"merge.example"},
		"upstream_url": "http://127.0.0.1:9",
		"waf":          map[string]any{"enabled": true, "paranoia_level": 3, "threshold": 9},
	}), http.StatusOK, nil)

	// Rename only; every other field must survive.
	c.decode(c.do(http.MethodPut, "/api/apps/merge", map[string]any{"name": "Renamed"}), http.StatusOK, nil)

	var got struct {
		Name    string   `json:"name"`
		Enabled bool     `json:"enabled"`
		Hosts   []string `json:"hostnames"`
		WAF     struct {
			ParanoiaLevel int `json:"paranoia_level"`
			Threshold     int `json:"threshold"`
		} `json:"waf"`
	}
	c.decode(c.get("/api/apps/merge"), http.StatusOK, &got)

	if got.Name != "Renamed" {
		t.Errorf("name = %q", got.Name)
	}
	if !got.Enabled {
		t.Error("a partial update disabled the app")
	}
	if len(got.Hosts) != 1 || got.Hosts[0] != "merge.example" {
		t.Errorf("hostnames lost: %v", got.Hosts)
	}
	if got.WAF.ParanoiaLevel != 3 || got.WAF.Threshold != 9 {
		t.Errorf("waf policy reset by a partial update: %+v", got.WAF)
	}
}

// TestReplayAcceptsRawRequest checks the repeater path: a hand-edited request
// is parsed and sent, rather than only the recorded one being replayed.
func TestReplayAcceptsRawRequest(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	seen := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		r.Header.Set("X-Captured-Body", string(body))
		seen <- r
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	// Point the event's app at the stub so replay has somewhere to send.
	app, err := h.store.GetApp(context.Background(), "api")
	if err != nil {
		t.Fatal(err)
	}
	app.UpstreamURL = upstream.URL
	if err := h.store.SaveApp(context.Background(), app); err != nil {
		t.Fatal(err)
	}

	raw := "PUT /edited/path?changed=yes HTTP/1.1\r\n" +
		"Host: api.example\r\n" +
		"X-Custom: from-the-editor\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"a body typed by hand"

	var out map[string]any
	c.decode(c.do(http.MethodPost, "/api/traffic/"+h.events[0].ID+"/replay",
		map[string]any{"raw": raw}), http.StatusOK, &out)

	select {
	case got := <-seen:
		if got.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", got.Method)
		}
		if got.URL.Path != "/edited/path" || got.URL.RawQuery != "changed=yes" {
			t.Errorf("target = %s?%s", got.URL.Path, got.URL.RawQuery)
		}
		if got.Header.Get("X-Custom") != "from-the-editor" {
			t.Errorf("edited header not sent: %v", got.Header)
		}
		if got.Header.Get("X-Captured-Body") != "a body typed by hand" {
			t.Errorf("edited body not sent: %q", got.Header.Get("X-Captured-Body"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream never received the replayed request")
	}

	if int(out["status"].(float64)) != http.StatusAccepted {
		t.Errorf("reported status = %v", out["status"])
	}
}

func TestReplayRejectsUnparseableRaw(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "admin", store.RoleAdmin, nil)

	resp := c.do(http.MethodPost, "/api/traffic/"+h.events[0].ID+"/replay",
		map[string]any{"raw": "this is not an HTTP request"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRuleCatalogueEndpoints(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "reader", store.RoleAnalyst, nil)

	var facets struct {
		Total      int      `json:"total"`
		Tags       []string `json:"tags"`
		Categories []string `json:"categories"`
	}
	c.decode(c.get("/api/rules/facets"), http.StatusOK, &facets)
	if facets.Total < 300 || len(facets.Tags) == 0 || len(facets.Categories) == 0 {
		t.Fatalf("facets look wrong: %+v", facets)
	}

	var page struct {
		Rules []struct {
			ID      int    `json:"id"`
			Message string `json:"message"`
		} `json:"rules"`
		Total int `json:"total"`
	}
	c.decode(c.get("/api/rules?q=sql&limit=5"), http.StatusOK, &page)
	if page.Total == 0 || len(page.Rules) == 0 {
		t.Fatalf("search returned nothing: %+v", page)
	}
	if len(page.Rules) > 5 {
		t.Errorf("limit ignored: got %d rules", len(page.Rules))
	}

	var rule struct {
		ID     int    `json:"id"`
		Source string `json:"source"`
	}
	c.decode(c.get("/api/rules/942100"), http.StatusOK, &rule)
	if rule.ID != 942100 || rule.Source == "" {
		t.Errorf("rule detail wrong: %+v", rule)
	}

	resp := c.get("/api/rules/1")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown rule = %d, want 404", resp.StatusCode)
	}
}
