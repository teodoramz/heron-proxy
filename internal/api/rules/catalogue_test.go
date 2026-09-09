package rules

import (
	"strings"
	"testing"
)

func catalogue(t *testing.T) *Catalogue {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestCataloguePopulated(t *testing.T) {
	c := catalogue(t)
	if c.Len() < 300 {
		t.Fatalf("parsed only %d rules; the Core Rule Set has far more", c.Len())
	}
}

func TestKnownRulesParsed(t *testing.T) {
	c := catalogue(t)
	// One well-known rule from each of the main attack families.
	for _, id := range []uint32{942100, 941100, 930120, 932160, 913100} {
		r, ok := c.Get(id)
		if !ok {
			t.Errorf("rule %d not found", id)
			continue
		}
		if r.Message == "" {
			t.Errorf("rule %d has no message", id)
		}
		if r.File == "" || r.Category == "" {
			t.Errorf("rule %d missing provenance: %+v", id, r)
		}
	}
}

func TestRuleCarriesTagsAndSeverity(t *testing.T) {
	c := catalogue(t)
	r, ok := c.Get(942100)
	if !ok {
		t.Fatal("rule 942100 not found")
	}
	if len(r.Tags) == 0 {
		t.Error("no tags parsed")
	}
	var sqli bool
	for _, tag := range r.Tags {
		if tag == "attack-sqli" {
			sqli = true
		}
	}
	if !sqli {
		t.Errorf("expected an attack-sqli tag, got %v", r.Tags)
	}
	if r.Severity == "" {
		t.Error("no severity parsed")
	}
	if r.Paranoia < 1 {
		t.Errorf("paranoia = %d, want at least 1", r.Paranoia)
	}
}

func TestSearchByID(t *testing.T) {
	c := catalogue(t)
	res := c.Search(Query{Text: "942100"})
	if res.Total == 0 {
		t.Fatal("searching by ID found nothing")
	}
	if res.Rules[0].ID != 942100 {
		t.Errorf("first result = %d", res.Rules[0].ID)
	}
}

func TestSearchByIDPrefix(t *testing.T) {
	c := catalogue(t)
	res := c.Search(Query{Text: "9421", Limit: 500})
	if res.Total < 2 {
		t.Fatalf("prefix search returned %d rules", res.Total)
	}
	for _, r := range res.Rules {
		if r.ID < 942100 || r.ID > 942199 {
			t.Errorf("rule %d does not match the prefix 9421", r.ID)
		}
	}
}

func TestSearchByText(t *testing.T) {
	c := catalogue(t)
	res := c.Search(Query{Text: "sql injection", Limit: 500})
	if res.Total == 0 {
		t.Fatal("text search found nothing")
	}
}

func TestSearchByTag(t *testing.T) {
	c := catalogue(t)
	res := c.Search(Query{Tag: "attack-xss", Limit: 500})
	if res.Total == 0 {
		t.Fatal("tag search found nothing")
	}
	for _, r := range res.Rules {
		if !hasTag(r.Tags, "attack-xss") {
			t.Errorf("rule %d lacks the tag", r.ID)
		}
	}
}

func TestSearchByParanoia(t *testing.T) {
	c := catalogue(t)
	res := c.Search(Query{Paranoia: 2, Limit: 500})
	if res.Total == 0 {
		t.Fatal("paranoia search found nothing")
	}
	for _, r := range res.Rules {
		if r.Paranoia != 2 {
			t.Errorf("rule %d has paranoia %d", r.ID, r.Paranoia)
		}
	}
}

func TestSearchPaginates(t *testing.T) {
	c := catalogue(t)
	first := c.Search(Query{Limit: 10})
	second := c.Search(Query{Limit: 10, Offset: 10})

	if len(first.Rules) != 10 || len(second.Rules) != 10 {
		t.Fatalf("page sizes: %d and %d", len(first.Rules), len(second.Rules))
	}
	if first.Rules[0].ID == second.Rules[0].ID {
		t.Error("the second page repeats the first")
	}
	if first.Total != second.Total {
		t.Error("total changed between pages")
	}
}

func TestSearchOffsetBeyondEnd(t *testing.T) {
	c := catalogue(t)
	res := c.Search(Query{Offset: 1 << 20})
	if len(res.Rules) != 0 {
		t.Errorf("got %d rules past the end", len(res.Rules))
	}
}

func TestFacets(t *testing.T) {
	c := catalogue(t)
	f := c.Facets()
	if len(f["tags"]) == 0 || len(f["categories"]) == 0 || len(f["severities"]) == 0 {
		t.Errorf("facets incomplete: %v", f)
	}
	for _, tag := range f["tags"] {
		if !strings.HasPrefix(tag, "attack-") {
			t.Errorf("facet tag %q is not an attack category", tag)
		}
	}
}

func TestDirectivesJoinContinuations(t *testing.T) {
	body := "# a comment\n" +
		`SecRule ARGS "@rx foo" \` + "\n" +
		`    "id:1234,\` + "\n" +
		`    phase:2,\` + "\n" +
		`    msg:'spread over lines'"` + "\n"
	got := directives(body)
	if len(got) != 1 {
		t.Fatalf("got %d directives, want 1: %q", len(got), got)
	}
	rule, ok := parseDirective(got[0], "TEST.conf")
	if !ok || rule.ID != 1234 || rule.Message != "spread over lines" {
		t.Errorf("parsed %+v", rule)
	}
}

func TestCategoryFromFilename(t *testing.T) {
	if got := category("REQUEST-942-APPLICATION-ATTACK-SQLI.conf"); got != "Application attack sqli" {
		t.Errorf("category = %q", got)
	}
}
