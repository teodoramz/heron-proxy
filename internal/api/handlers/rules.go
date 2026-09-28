package handlers

import (
	"net/http"

	"github.com/amzteodor/heron/internal/store"
)

// ListExclusions returns tuning exclusions, optionally for one app.
func (h *Handler) ListExclusions(w http.ResponseWriter, r *http.Request) {
	apps, err := appScope(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	list, err := h.Store.ListExclusions(r.Context(), apps)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exclusions": list})
}

// PreviewExclusion renders the directive an exclusion would produce, without
// storing it.
func (h *Handler) PreviewExclusion(w http.ResponseWriter, r *http.Request) {
	var e store.Exclusion
	if err := decodeBody(r, &e); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !requireAppAccess(w, r, e.AppID) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"seclang": store.BuildSecLang(e, 10000000)})
}

// CreateExclusion stores a tuning exclusion. The proxy picks it up on its next
// configuration poll.
func (h *Handler) CreateExclusion(w http.ResponseWriter, r *http.Request) {
	var e store.Exclusion
	if err := decodeBody(r, &e); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if e.RuleID <= 0 {
		writeError(w, http.StatusBadRequest, "rule_id is required")
		return
	}
	if !requireAppAccess(w, r, e.AppID) {
		return
	}
	e.CreatedBy = session(r).User.ID
	saved, err := h.Store.SaveExclusion(r.Context(), e)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "exclusion.create", map[string]any{"app_id": e.AppID, "rule_id": e.RuleID, "seclang": saved.SecLang})
	writeJSON(w, http.StatusCreated, saved)
}

// SetExclusionEnabled toggles an exclusion.
func (h *Handler) SetExclusionEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	if !h.mayChangeExclusion(w, r, id) {
		return
	}
	if err := h.Store.SetExclusionEnabled(r.Context(), id, req.Enabled); err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	h.audit(r, "exclusion.toggle", map[string]any{"id": id, "enabled": req.Enabled})
	w.WriteHeader(http.StatusNoContent)
}

// DeleteExclusion removes an exclusion.
func (h *Handler) DeleteExclusion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !h.mayChangeExclusion(w, r, id) {
		return
	}
	if err := h.Store.DeleteExclusion(r.Context(), id); err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	h.audit(r, "exclusion.delete", map[string]any{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

// MarkFP records an analyst's verdict on a rule match.
func (h *Handler) MarkFP(w http.ResponseWriter, r *http.Request) {
	var m store.FPMark
	if err := decodeBody(r, &m); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	m.EventID = r.PathValue("id")
	m.UserID = session(r).User.ID
	// The app comes from the event, not the request: otherwise a caller could
	// name an app they can see while marking an event belonging to one they
	// cannot.
	appID, err := h.eventApp(r, m.EventID)
	if err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	if !requireAppAccess(w, r, appID) {
		return
	}
	m.AppID = appID
	saved, err := h.Store.SaveFPMark(r.Context(), m)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "rule.verdict", map[string]any{"event_id": m.EventID, "rule_id": m.RuleID, "verdict": m.Verdict})
	writeJSON(w, http.StatusOK, saved)
}

// FPSummaries aggregates verdicts per rule for the tuning queue.
func (h *Handler) FPSummaries(w http.ResponseWriter, r *http.Request) {
	apps, err := appScope(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	sums, err := h.Store.FPSummaries(r.Context(), apps)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summaries": sums})
}

// mayChangeExclusion reports whether the caller may alter the exclusion, which
// depends on the app it belongs to rather than on anything they sent.
func (h *Handler) mayChangeExclusion(w http.ResponseWriter, r *http.Request, id string) bool {
	appID, err := h.Store.ExclusionApp(r.Context(), id)
	if err != nil {
		writeError(w, statusFor(err), err.Error())
		return false
	}
	return requireAppAccess(w, r, appID)
}
