package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/amzteodor/proxy-waf/internal/config"
	"github.com/amzteodor/proxy-waf/internal/store"
)

// ListApps returns the apps the caller may see.
func (h *Handler) ListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.Store.ListApps(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s := session(r)
	visible := make([]config.App, 0, len(apps))
	for _, a := range apps {
		if s.CanSeeApp(a.ID) {
			visible = append(visible, a)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": visible})
}

// GetApp returns one app.
func (h *Handler) GetApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !session(r).CanSeeApp(id) {
		writeError(w, http.StatusForbidden, "no access to this app")
		return
	}
	app, err := h.Store.GetApp(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, app)
}

// SaveApp creates or updates an app.
func (h *Handler) SaveApp(w http.ResponseWriter, r *http.Request) {
	var app config.App
	if err := decodeBody(r, &app); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if id := r.PathValue("id"); id != "" {
		app.ID = id
	}
	if err := validateApp(&app); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.Store.SaveApp(r.Context(), app); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "app.save", map[string]any{"app_id": app.ID})
	writeJSON(w, http.StatusOK, app)
}

// validateApp rejects an app the proxy could not serve.
func validateApp(app *config.App) error {
	app.ID = strings.TrimSpace(app.ID)
	if app.ID == "" {
		return errors.New("id is required")
	}
	if strings.TrimSpace(app.Name) == "" {
		app.Name = app.ID
	}
	if len(app.Hostnames) == 0 {
		return errors.New("at least one hostname is required")
	}
	u, err := url.Parse(app.UpstreamURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("upstream_url must be an absolute http or https URL")
	}
	if app.WAF.ParanoiaLevel < 0 || app.WAF.ParanoiaLevel > 4 {
		return errors.New("waf.paranoia_level must be between 1 and 4")
	}
	if app.RetentionDays < 0 || app.RetentionDays > 3650 {
		return errors.New("retention_days must be between 1 and 3650")
	}
	app.ApplyDefaults()
	return nil
}

// DeleteApp removes an app.
func (h *Handler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Store.DeleteApp(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "app not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "app.delete", map[string]any{"app_id": id})
	w.WriteHeader(http.StatusNoContent)
}

// ListCertificates returns certificate metadata, never private keys.
func (h *Handler) ListCertificates(w http.ResponseWriter, r *http.Request) {
	certs, err := h.Store.ListCertificates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type row struct {
		store.Certificate
		ExpiresInDays int `json:"expires_in_days"`
	}
	out := make([]row, 0, len(certs))
	for _, c := range certs {
		out = append(out, row{Certificate: c, ExpiresInDays: int(c.ExpiresIn().Hours() / 24)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

// SaveCertificate stores a key pair, encrypting the private key.
func (h *Handler) SaveCertificate(w http.ResponseWriter, r *http.Request) {
	var c store.Certificate
	if err := decodeBody(r, &c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if c.CertPEM == "" || c.PrivateKeyPEM == "" {
		writeError(w, http.StatusBadRequest, "cert_pem and private_key_pem are required")
		return
	}
	saved, err := h.Store.SaveCertificate(r.Context(), c)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "certificate.save", map[string]any{"fingerprint": saved.Fingerprint, "app_id": saved.AppID})
	writeJSON(w, http.StatusCreated, saved)
}

// DeleteCertificate removes a certificate.
func (h *Handler) DeleteCertificate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Store.DeleteCertificate(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "certificate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "certificate.delete", map[string]any{"id": id})
	w.WriteHeader(http.StatusNoContent)
}
