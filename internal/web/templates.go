package web

import (
	"fmt"
	"html/template"
	"io/fs"
	"strings"
	"time"
)

// templateFuncs returns the function map available inside every template
// rendered by the dashboard. Adding a function here makes it callable from
// any .tmpl file — keep the set small to avoid templates becoming logic
// containers.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		// cliCommand formats a "$ zerodaybuddy <cmd> [args...]" line for
		// the copy-CLI-command panels (T2-3 D5). Args are space-joined.
		"cliCommand": func(cmd string, args ...string) string {
			parts := append([]string{"$ zerodaybuddy", cmd}, args...)
			return strings.Join(parts, " ")
		},
		// severityClass maps a finding severity to a CSS class for styling.
		"severityClass": func(s string) string {
			switch strings.ToLower(s) {
			case "critical":
				return "sev-critical"
			case "high":
				return "sev-high"
			case "medium":
				return "sev-medium"
			case "low":
				return "sev-low"
			case "info", "informational":
				return "sev-info"
			}
			return ""
		},
		// formatTime renders a time.Time as a short human-friendly string.
		// Empty/zero times render as "—" so templates don't show "0001-01-01".
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Format("2006-01-02 15:04")
		},
	}
}

// parseTemplates walks fsys for *.tmpl files at the root and parses them
// into a single *template.Template tree with the standard funcMap attached.
//
// Returns nil + nil if no .tmpl files are present (acceptable for tests
// that don't need rendering and for the bootstrap state where templates
// haven't been added yet). Returns an error only on a parse failure.
//
// Templates are parsed once at server construction time per T2-3 D4. The
// resulting tree should be stored on the Server and looked up by name from
// handler methods via .Lookup("name.tmpl").
func parseTemplates(fsys fs.FS) (*template.Template, error) {
	t := template.New("").Funcs(templateFuncs())

	// Glob first to detect "no templates yet" before ParseFS errors on it.
	matches, err := fs.Glob(fsys, "embedded/templates/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("globbing templates: %w", err)
	}
	if len(matches) == 0 {
		return nil, nil
	}

	t, err = t.ParseFS(fsys, "embedded/templates/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}
	return t, nil
}
