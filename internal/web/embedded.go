package web

import "embed"

// EmbeddedFS bundles HTML templates and static assets into the binary so the
// web server is location-independent — no cwd dependence at request time, no
// loose files alongside the binary in deployment.
//
// The "all:" prefix forces inclusion of dotfiles (specifically the .gitkeep
// files that preserve empty subdirs in version control before assets land).
//
//go:embed all:embedded/templates all:embedded/static
var EmbeddedFS embed.FS
