// Package api assembles the HTTP routes for the query and administration API.
package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/amzteodor/heron/internal/api/auth"
	"github.com/amzteodor/heron/internal/api/handlers"
	"github.com/amzteodor/heron/internal/store"
)

// Options configures the router.
type Options struct {
	Handler        *handlers.Handler
	Auth           *auth.Middleware
	AllowedOrigins []string
}

// NewRouter builds the API routes.
//
// Every route below /api requires a session. Reads need the viewer role,
// analysis actions need analyst, and configuration needs admin.
func NewRouter(o Options) http.Handler {
	h := o.Handler
	// The websocket route authorizes by Origin, so it needs the same list the
	// CORS middleware uses. Keeping them in step here stops them drifting.
	if h.AllowedOrigins == nil {
		h.AllowedOrigins = o.AllowedOrigins
	}
	mux := http.NewServeMux()

	// Unauthenticated.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("POST /api/auth/login", http.HandlerFunc(h.Login))

	// Everyone signed in is at least an analyst, so reading and analysing share
	// one gate; admin is the only step up.
	analyst := chain(o.Auth.Authenticate, o.Auth.CSRF, auth.RequireRole(store.RoleAnalyst))
	admin := chain(o.Auth.Authenticate, o.Auth.CSRF, auth.RequireRole(store.RoleAdmin))

	// Session.
	mux.Handle("POST /api/auth/logout", analyst(http.HandlerFunc(h.Logout)))
	mux.Handle("GET /api/me", analyst(http.HandlerFunc(h.Me)))
	mux.Handle("POST /api/me/password", analyst(http.HandlerFunc(h.ChangeOwnPassword)))

	// Traffic.
	mux.Handle("GET /api/traffic", analyst(http.HandlerFunc(h.ListTraffic)))
	mux.Handle("POST /api/traffic/search", analyst(http.HandlerFunc(h.ListTraffic)))
	mux.Handle("GET /api/traffic/count", analyst(http.HandlerFunc(h.CountTraffic)))
	mux.Handle("POST /api/traffic/count", analyst(http.HandlerFunc(h.CountTraffic)))
	mux.Handle("GET /api/traffic/bookmarks", analyst(http.HandlerFunc(h.Bookmarks)))
	mux.Handle("GET /api/traffic/{id}", analyst(http.HandlerFunc(h.GetTraffic)))
	mux.Handle("GET /api/traffic/{id}/export", analyst(http.HandlerFunc(h.ExportTraffic)))
	mux.Handle("POST /api/traffic/{id}/annotate", analyst(http.HandlerFunc(h.Annotate)))
	mux.Handle("POST /api/traffic/{id}/verdict", analyst(http.HandlerFunc(h.MarkFP)))
	mux.Handle("POST /api/traffic/{id}/replay", analyst(http.HandlerFunc(h.Replay)))

	// Live tail. The websocket handshake is a GET, so CSRF does not apply.
	stream := chain(o.Auth.Authenticate, auth.RequireRole(store.RoleAnalyst))
	mux.Handle("GET /api/stream", stream(http.HandlerFunc(h.Stream)))
	mux.Handle("GET /api/stream/status", analyst(http.HandlerFunc(h.StreamStatus)))

	// Statistics.
	mux.Handle("GET /api/stats/summary", analyst(http.HandlerFunc(h.Summary)))
	mux.Handle("POST /api/stats/summary", analyst(http.HandlerFunc(h.Summary)))
	mux.Handle("GET /api/stats/series", analyst(http.HandlerFunc(h.TimeSeries)))
	mux.Handle("POST /api/stats/series", analyst(http.HandlerFunc(h.TimeSeries)))
	mux.Handle("GET /api/stats/rules", analyst(http.HandlerFunc(h.TopRules)))
	mux.Handle("POST /api/stats/rules", analyst(http.HandlerFunc(h.TopRules)))
	mux.Handle("GET /api/stats/ips", analyst(http.HandlerFunc(h.TopIPs)))
	mux.Handle("POST /api/stats/ips", analyst(http.HandlerFunc(h.TopIPs)))
	mux.Handle("GET /api/stats/top/{field}", analyst(http.HandlerFunc(h.TopBy)))
	mux.Handle("POST /api/stats/top/{field}", analyst(http.HandlerFunc(h.TopBy)))
	mux.Handle("GET /api/simulate", analyst(http.HandlerFunc(h.Simulate)))
	mux.Handle("POST /api/simulate", analyst(http.HandlerFunc(h.Simulate)))
	mux.Handle("GET /api/ip/{ip}", analyst(http.HandlerFunc(h.IPProfile)))

	// Saved filters.
	mux.Handle("GET /api/filters", analyst(http.HandlerFunc(h.ListFilters)))
	mux.Handle("GET /api/filters/schema", analyst(http.HandlerFunc(h.FilterSchema)))
	mux.Handle("POST /api/filters", analyst(http.HandlerFunc(h.SaveFilter)))
	mux.Handle("DELETE /api/filters/{id}", analyst(http.HandlerFunc(h.DeleteFilter)))

	// The rule catalogue is reference material, readable by anyone signed in.
	mux.Handle("GET /api/rules", analyst(http.HandlerFunc(h.ListRules)))
	mux.Handle("GET /api/rules/facets", analyst(http.HandlerFunc(h.RuleFacets)))
	mux.Handle("GET /api/rules/{id}", analyst(http.HandlerFunc(h.GetRule)))

	// Rule tuning.
	mux.Handle("GET /api/exclusions", analyst(http.HandlerFunc(h.ListExclusions)))
	mux.Handle("GET /api/exclusions/verdicts", analyst(http.HandlerFunc(h.FPSummaries)))
	mux.Handle("POST /api/exclusions/preview", analyst(http.HandlerFunc(h.PreviewExclusion)))
	mux.Handle("POST /api/exclusions", analyst(http.HandlerFunc(h.CreateExclusion)))
	mux.Handle("PATCH /api/exclusions/{id}", analyst(http.HandlerFunc(h.SetExclusionEnabled)))
	mux.Handle("DELETE /api/exclusions/{id}", analyst(http.HandlerFunc(h.DeleteExclusion)))

	// Applications and certificates.
	mux.Handle("GET /api/apps", analyst(http.HandlerFunc(h.ListApps)))
	mux.Handle("GET /api/apps/{id}", analyst(http.HandlerFunc(h.GetApp)))
	mux.Handle("POST /api/apps", admin(http.HandlerFunc(h.SaveApp)))
	mux.Handle("PUT /api/apps/{id}", admin(http.HandlerFunc(h.SaveApp)))
	mux.Handle("DELETE /api/apps/{id}", admin(http.HandlerFunc(h.DeleteApp)))
	// The authority certificate is public by nature: it is meant to be
	// installed as trusted, and holds no secret.
	mux.Handle("GET /api/ca", analyst(http.HandlerFunc(h.CertificateAuthority)))
	mux.Handle("GET /api/ca.crt", analyst(http.HandlerFunc(h.DownloadCertificateAuthority)))
	mux.Handle("POST /api/ca/regenerate", admin(http.HandlerFunc(h.RegenerateCertificateAuthority)))

	mux.Handle("GET /api/certificates", admin(http.HandlerFunc(h.ListCertificates)))
	mux.Handle("POST /api/certificates", admin(http.HandlerFunc(h.SaveCertificate)))
	mux.Handle("DELETE /api/certificates/{id}", admin(http.HandlerFunc(h.DeleteCertificate)))

	// Users, alerts and audit.
	mux.Handle("GET /api/users", admin(http.HandlerFunc(h.ListUsers)))
	mux.Handle("POST /api/users", admin(http.HandlerFunc(h.CreateUser)))
	mux.Handle("PATCH /api/users/{id}", admin(http.HandlerFunc(h.UpdateUser)))
	mux.Handle("DELETE /api/users/{id}", admin(http.HandlerFunc(h.DeleteUser)))
	mux.Handle("GET /api/alerts", admin(http.HandlerFunc(h.ListAlerts)))
	mux.Handle("POST /api/alerts", admin(http.HandlerFunc(h.SaveAlert)))
	mux.Handle("POST /api/alerts/preview", admin(http.HandlerFunc(h.PreviewAlert)))
	mux.Handle("PUT /api/alerts/{id}", admin(http.HandlerFunc(h.SaveAlert)))
	mux.Handle("DELETE /api/alerts/{id}", admin(http.HandlerFunc(h.DeleteAlert)))
	mux.Handle("GET /api/audit", admin(http.HandlerFunc(h.ListAudit)))

	return cors(o.AllowedOrigins)(mux)
}

// chain applies middleware in the order given.
func chain(mw ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			next = mw[i](next)
		}
		return next
	}
}

// cors permits credentialed requests from configured origins only. With no
// origins configured the API is same-origin, which is how the compose stack
// serves it.
func cors(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && slices.Contains(origins, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers",
					strings.Join([]string{"Content-Type", auth.CSRFHeader}, ", "))
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
