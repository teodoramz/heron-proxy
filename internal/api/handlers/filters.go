package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/amzteodor/heron/internal/api/alerts"
	"github.com/amzteodor/heron/internal/api/query"
	"github.com/amzteodor/heron/internal/store"
)

// ListFilters returns the caller's saved filters plus shared ones.
func (h *Handler) ListFilters(w http.ResponseWriter, r *http.Request) {
	list, err := h.Store.ListFilters(r.Context(), session(r).User.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"filters": list})
}

// SaveFilter stores a named filter after validating that it parses.
func (h *Handler) SaveFilter(w http.ResponseWriter, r *http.Request) {
	var f store.SavedFilter
	if err := decodeBody(r, &f); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if f.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if _, err := query.ParseFilter(f.Query); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.UserID = session(r).User.ID
	saved, err := h.Store.SaveFilter(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

// DeleteFilter removes a filter the caller owns.
func (h *Handler) DeleteFilter(w http.ResponseWriter, r *http.Request) {
	if err := h.Store.DeleteFilter(r.Context(), r.PathValue("id"), session(r).User.ID); err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// FilterSchema describes the fields and operators the UI can offer.
func (h *Handler) FilterSchema(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"fields":    query.Schema(),
		"max_limit": query.MaxLimit,
	})
}

// ListAlerts returns every alert rule.
func (h *Handler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	rules, err := h.Store.ListAlertRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": rules})
}

// SaveAlert creates or updates an alert rule.
func (h *Handler) SaveAlert(w http.ResponseWriter, r *http.Request) {
	var rule store.AlertRule
	if err := decodeBody(r, &rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if id := r.PathValue("id"); id != "" {
		rule.ID = id
	}
	if rule.Name == "" || rule.TargetURL == "" {
		writeError(w, http.StatusBadRequest, "name and target_url are required")
		return
	}
	if rule.ThrottleSeconds <= 0 {
		rule.ThrottleSeconds = 300
	}
	// A broken template would otherwise only show up the first time the rule
	// fires, which is the worst moment to find out.
	if err := alerts.ValidTemplate(rule.Template); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, err := h.Store.SaveAlertRule(r.Context(), rule)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "alert.save", map[string]any{"id": saved.ID, "name": saved.Name})
	writeJSON(w, http.StatusOK, saved)
}

// DeleteAlert removes an alert rule.
func (h *Handler) DeleteAlert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Store.DeleteAlertRule(r.Context(), id); err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	h.audit(r, "alert.delete", map[string]any{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

var _ = json.Marshal
