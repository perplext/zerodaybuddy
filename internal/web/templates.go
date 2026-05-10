package web

import (
	"fmt"
	"html/template"
	"io/fs"
	"path"
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
		// the copy-CLI-command panels (T2-3 D5). Each arg is shell-quoted so
		// values containing spaces or shell metacharacters can't break or
		// inject into the copied command. The fixed prefix and cmd are not
		// quoted (cmd is always a literal subcommand name from a template).
		"cliCommand": func(cmd string, args ...string) string {
			parts := []string{"$ zerodaybuddy", cmd}
			for _, a := range args {
				parts = append(parts, shellQuote(a))
			}
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

// shellQuote wraps an argument in single quotes when (and only when) the
// argument contains characters that aren't safe to copy verbatim into a
// POSIX shell. Plain flag names ("--project") and tame identifiers
// ("acme-demo") pass through unchanged so the rendered CLI command stays
// readable. Values containing spaces, quotes, or shell metacharacters get
// the standard '\'' quoting treatment so the copied command is still
// syntactically one argument.
func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if shellSafe(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
}

// shellSafe reports whether s contains only characters POSIX shells treat
// literally — alphanumeric plus a small set of safe punctuation. The
// allowed set is intentionally conservative: anything else falls into
// shellQuote's escaping path.
func shellSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
			continue
		}
		switch r {
		case '-', '_', '.', '/', ':', '=', ',', '@', '+':
			continue
		}
		return false
	}
	return true
}

// pageSet is a name → *template.Template map. Each page-template instance
// has its own private parse tree containing the shared partials plus that
// page's content/title blocks. This isolates `{{define "title"}}` (and
// `{{define "content"}}`) blocks so the last-parsed page doesn't shadow
// earlier ones — which would happen with a single shared tree.
//
// Lookup is by page filename (e.g. "login.tmpl", "dashboard.tmpl"). The
// boolean returned by Lookup signals whether the page is wired (used by
// server.go to gate route registration). A nil pageSet from parseTemplates
// (no templates present) is acceptable — Lookup returns nil + false.
type pageSet map[string]*template.Template

// Lookup returns the page template for the given name, or nil if absent.
// Mirrors *template.Template.Lookup so handlers can swap a pageSet in for
// a *template.Template with minimal churn.
func (p pageSet) Lookup(name string) *template.Template {
	if p == nil {
		return nil
	}
	return p[name]
}

// parseTemplates builds a pageSet by:
//
//  1. Parsing every partial (filename starts with "_") into a base template.
//  2. For each non-partial page template, cloning the base and parsing
//     the page on top — yielding a per-page template instance.
//
// Per-page clones are required because Go's html/template tree treats
// `{{define "X"}}` as global within a single template — last parse wins.
// Without cloning, "title" and "content" blocks defined in the last-parsed
// page silently shadow every other page's blocks at render time, producing
// "can't evaluate field X in type Y" errors when the wrong page's data shape
// reaches the wrong block.
//
// Returns nil + nil if no .tmpl files are present (acceptable for tests
// that don't exercise rendering and for the bootstrap state where templates
// haven't been added yet). Returns an error only on a parse failure.
//
// Templates are parsed once at server construction time per T2-3 D4.
func parseTemplates(fsys fs.FS) (pageSet, error) {
	allTemplates, err := fs.Glob(fsys, "embedded/templates/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("globbing templates: %w", err)
	}
	if len(allTemplates) == 0 {
		return nil, nil
	}

	var partials, pages []string
	for _, t := range allTemplates {
		if strings.HasPrefix(path.Base(t), "_") {
			partials = append(partials, t)
		} else {
			pages = append(pages, t)
		}
	}

	// Base = funcMap + every partial. Pages clone from this and add their
	// own content. If no partials exist, base is just an empty tree with the
	// funcs attached.
	base := template.New("").Funcs(templateFuncs())
	if len(partials) > 0 {
		if base, err = base.ParseFS(fsys, partials...); err != nil {
			return nil, fmt.Errorf("parsing partials: %w", err)
		}
	}

	out := make(pageSet, len(pages))
	for _, p := range pages {
		clone, err := base.Clone()
		if err != nil {
			return nil, fmt.Errorf("cloning base for %s: %w", p, err)
		}
		clone, err = clone.ParseFS(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("parsing page %s: %w", p, err)
		}
		out[path.Base(p)] = clone
	}
	return out, nil
}
