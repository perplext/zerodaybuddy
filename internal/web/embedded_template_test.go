package web

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// Smoke tests for the production templates shipped under
// internal/web/embedded/templates/. Handler tests use minimal stand-in
// templates for isolation; these verify the real templates parse and that
// the HTMX-driven triage row renders the contract zdb.js relies on.

func TestEmbeddedTemplates_ParseClean(t *testing.T) {
	tmpl, err := parseTemplates(EmbeddedFS)
	require.NoError(t, err)
	require.NotNil(t, tmpl)

	// Lookup is page-keyed in the new pageSet — partials are visible inside
	// each page's template instance, not as top-level pageSet entries.
	for _, name := range []string{
		"login.tmpl",
		"dashboard.tmpl",
		"project_detail.tmpl",
	} {
		assert.NotNil(t, tmpl.Lookup(name), "page %s must be present", name)
	}

	// Verify partials are accessible from inside a page (smoke that the
	// clone-from-base machinery actually wired the partials).
	loginPage := tmpl.Lookup("login.tmpl")
	require.NotNil(t, loginPage)
	for _, partial := range []string{"_layout.tmpl", "_header.tmpl"} {
		assert.NotNil(t, loginPage.Lookup(partial),
			"partial %s must be visible from a page-template clone", partial)
	}
}

func TestEmbeddedTemplates_FindingRowEmitsHTMXTriageContract(t *testing.T) {
	// Render a single _finding_row partial and assert the attributes the
	// frontend (zdb.js + HTMX) depends on. This guards U6's wiring against
	// silent template regressions. We render through project_detail.tmpl's
	// clone since the partial is only visible inside per-page instances.
	tmpl, err := parseTemplates(EmbeddedFS)
	require.NoError(t, err)
	page := tmpl.Lookup("project_detail.tmpl")
	require.NotNil(t, page, "project_detail page must be parsed")

	finding := &models.Finding{
		ID:       "abc-123",
		Title:    "Reflected XSS",
		Severity: models.SeverityHigh,
		Status:   models.FindingStatusConfirmed,
		FoundAt:  time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
	}

	var buf bytes.Buffer
	require.NoError(t, page.ExecuteTemplate(&buf, "_finding_row.tmpl", finding))
	body := buf.String()

	// Triage <select> must point at the right endpoint and use json-enc.
	assert.Contains(t, body, `hx-patch="/api/findings/abc-123"`,
		"triage select must PATCH the per-finding endpoint")
	assert.Contains(t, body, `hx-ext="json-enc"`,
		"json-enc converts form value to {\"status\": \"...\"} JSON body")
	assert.Contains(t, body, `hx-trigger="change"`,
		"triage fires on select change, not on every keypress")
	assert.Contains(t, body, `hx-swap="none"`,
		"server is authoritative; user reloads to confirm — no DOM swap")
	assert.Contains(t, body, `name="status"`,
		"json-enc keys off the form-field name")

	// Currently-selected option must be marked. Template has whitespace
	// between value and selected for column alignment — assert on substring.
	assert.Regexp(t, `value="confirmed"\s*selected`, body,
		"current status must be the selected option")

	// Flash sentinel zdb.js looks for.
	assert.Contains(t, body, `data-triage-flash`,
		"flash sentinel must be present so zdb.js can find it on htmx:afterRequest")

	// All six valid status values present so users can transition to any of them.
	for _, opt := range []string{"new", "confirmed", "duplicate", "false_positive", "reported", "resolved"} {
		assert.True(t, strings.Contains(body, `value="`+opt+`"`),
			"option %q must be selectable", opt)
	}
}
