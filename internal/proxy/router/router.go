// Package router maps request hostnames to configured applications and decides
// which source address a request is attributed to.
package router

import (
	"net"
	"strings"
	"sync/atomic"

	"github.com/amzteodor/proxy-waf/internal/config"
)

type routes struct {
	exact    map[string]*config.App
	wildcard map[string]*config.App
	byID     map[string]*config.App
	all      []*config.App
}

// Router resolves a Host header to an app. Replace swaps the whole table
// atomically, so configuration changes never block in-flight requests.
type Router struct {
	r atomic.Pointer[routes]
}

// New returns an empty router.
func New() *Router {
	r := &Router{}
	r.Replace(nil)
	return r
}

// Replace installs a new app set.
func (r *Router) Replace(apps []config.App) {
	next := &routes{
		exact:    make(map[string]*config.App, len(apps)),
		wildcard: make(map[string]*config.App),
		byID:     make(map[string]*config.App, len(apps)),
		all:      make([]*config.App, 0, len(apps)),
	}
	for i := range apps {
		app := apps[i]
		app.ApplyDefaults()
		stored := &app
		stored.SetTrusted(ParseCIDRs(app.TrustedCIDRs))
		next.byID[app.ID] = stored
		next.all = append(next.all, stored)
		if !app.Enabled {
			continue
		}
		for _, h := range app.Hostnames {
			h = normalizeHost(h)
			if h == "" {
				continue
			}
			if suffix, ok := strings.CutPrefix(h, "*."); ok {
				next.wildcard[suffix] = stored
			} else {
				next.exact[h] = stored
			}
		}
	}
	r.r.Store(next)
}

// Match resolves a Host header. An exact hostname wins over a wildcard.
func (r *Router) Match(host string) (*config.App, bool) {
	rt := r.r.Load()
	h := normalizeHost(host)
	if app, ok := rt.exact[h]; ok {
		return app, true
	}
	if _, parent, found := strings.Cut(h, "."); found {
		if app, ok := rt.wildcard[parent]; ok {
			return app, true
		}
	}
	return nil, false
}

// ByID returns an app by identifier.
func (r *Router) ByID(id string) (*config.App, bool) {
	app, ok := r.r.Load().byID[id]
	return app, ok
}

// Apps returns every configured app, enabled or not.
func (r *Router) Apps() []*config.App { return r.r.Load().all }

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}
