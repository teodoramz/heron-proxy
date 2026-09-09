package handlers

import (
	"net/http"
	"strconv"

	"github.com/amzteodor/proxy-waf/internal/api/rules"
)

// ListRules searches the Core Rule Set catalogue, so an analyst can look up what
// a rule ID means without opening the rule files.
func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	catalogue, err := rules.Load()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	q := r.URL.Query()
	paranoia, _ := strconv.Atoi(q.Get("paranoia"))

	result := catalogue.Search(rules.Query{
		Text:     q.Get("q"),
		Tag:      q.Get("tag"),
		Severity: q.Get("severity"),
		Category: q.Get("category"),
		Paranoia: paranoia,
		Limit:    intParam(r, "limit", 100),
		Offset:   intParam(r, "offset", 0),
	})
	writeJSON(w, http.StatusOK, result)
}

// GetRule returns one rule, including the directive it is defined by.
func (h *Handler) GetRule(w http.ResponseWriter, r *http.Request) {
	catalogue, err := rules.Load()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the rule id must be a number")
		return
	}
	rule, ok := catalogue.Get(uint32(id))
	if !ok {
		writeError(w, http.StatusNotFound, "no such rule in the loaded rule set")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// RuleFacets lists the values available for filtering the catalogue.
func (h *Handler) RuleFacets(w http.ResponseWriter, r *http.Request) {
	catalogue, err := rules.Load()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	facets := catalogue.Facets()
	writeJSON(w, http.StatusOK, map[string]any{
		"total":      catalogue.Len(),
		"tags":       facets["tags"],
		"categories": facets["categories"],
		"severities": facets["severities"],
	})
}
