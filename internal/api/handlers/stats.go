package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/amzteodor/proxy-waf/internal/api/reader"
)

// Summary returns the headline numbers for a filtered range.
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	s, err := h.Reader.Summary(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// TimeSeries returns bucketed traffic counts and latency quantiles.
func (h *Handler) TimeSeries(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	bucket := time.Minute
	if v := r.URL.Query().Get("bucket"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			bucket = d
		}
	}
	points, err := h.Reader.TimeSeries(r.Context(), f, bucket)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bucket": bucket.String(), "points": points})
}

// TopRules ranks the CRS rules that fired most.
func (h *Handler) TopRules(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	rules, err := h.Reader.TopRules(r.Context(), f, intParam(r, "limit", 20))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// TopIPs ranks source addresses by anomaly and volume.
func (h *Handler) TopIPs(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	ips, err := h.Reader.TopIPs(r.Context(), f, intParam(r, "limit", 20))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ips": ips})
}

// TopBy ranks by a groupable column named in the path.
func (h *Handler) TopBy(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	rows, err := h.Reader.TopBy(r.Context(), f, r.PathValue("field"), intParam(r, "limit", 20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"field":     r.PathValue("field"),
		"rows":      rows,
		"groupable": reader.GroupableFields(),
	})
}

// Simulate reports how many recorded requests a blocking threshold would stop.
func (h *Handler) Simulate(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	threshold := uint16(5)
	if v := r.URL.Query().Get("threshold"); v != "" {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			writeError(w, http.StatusBadRequest, "threshold must be a number")
			return
		}
		threshold = uint16(n)
	}
	sim, err := h.Reader.Simulate(r.Context(), f, threshold)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sim)
}

// IPProfile returns everything recorded about one source address.
func (h *Handler) IPProfile(w http.ResponseWriter, r *http.Request) {
	f, err := h.filterFromRequest(r)
	if err != nil {
		h.writeFilterError(w, err)
		return
	}
	profile, err := h.Reader.IPProfile(r.Context(), f, r.PathValue("ip"), intParam(r, "limit", 20))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, profile)
}
