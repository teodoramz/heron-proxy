package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amzteodor/heron/internal/config"
	"github.com/amzteodor/heron/internal/store"
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
//
// The request body is decoded over a base rather than a zero value: an existing
// app when updating, the defaults when creating. Without this, any field the
// caller omits would be silently set to Go's zero value, so a new app would
// arrive with capture and the WAF switched off.
func (h *Handler) SaveApp(w http.ResponseWriter, r *http.Request) {
	app := config.App{
		Enabled:           true,
		UpstreamTLSVerify: true,
		Capture:           config.DefaultCapture(),
		Redaction:         config.DefaultRedaction(),
		WAF:               config.DefaultWAF(),
	}
	if id := r.PathValue("id"); id != "" {
		if existing, err := h.Store.GetApp(r.Context(), id); err == nil {
			app = existing
		}
	}
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
	if app.WAF.Mode != "" && !config.ValidMode(app.WAF.Mode) {
		return errors.New("waf.mode must be detect or block")
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

// CertificateAuthority returns the authority that signs for hosts with no
// uploaded certificate, so it can be installed as trusted.
func (h *Handler) CertificateAuthority(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Store.EnsureCA(r.Context(), "proxy-waf"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	info, err := h.Store.CAInfo(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type response struct {
		store.CAInfo
		ExpiresInDays int `json:"expires_in_days"`
	}
	writeJSON(w, http.StatusOK, response{
		CAInfo:        info,
		ExpiresInDays: int(time.Until(info.NotAfter).Hours() / 24),
	})
}

// DownloadCertificateAuthority serves the authority certificate as a file, for
// installing in a browser or system trust store.
func (h *Handler) DownloadCertificateAuthority(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Store.EnsureCA(r.Context(), "proxy-waf"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	info, err := h.Store.CAInfo(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="heron-ca.crt"`)
	_, _ = w.Write([]byte(info.CertPEM))
}

// RegenerateCertificateAuthority replaces the authority. Everything that
// trusted the old one stops trusting what the proxy serves, so it is a
// deliberate, separate action.
func (h *Handler) RegenerateCertificateAuthority(w http.ResponseWriter, r *http.Request) {
	ca, err := h.Store.RegenerateCA(r.Context(), "heron")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "certificate_authority.regenerate", map[string]any{"fingerprint": ca.Fingerprint()})
	writeJSON(w, http.StatusOK, map[string]any{
		"fingerprint": ca.Fingerprint(),
		"cert_pem":    ca.CertPEM(),
	})
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
