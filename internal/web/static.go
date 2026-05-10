package web

import (
	"net/http"
	"os"
)

// indexHTML is the minimal CSP-clean stub served at "/". Lists the available
// API endpoints so a browser visit isn't a dead end. No inline styles or
// scripts — the strict default-src 'self' CSP set by SecurityHeaders would
// block them. T2-3 will replace this with a real templated dashboard.
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ZeroDayBuddy</title>
</head>
<body>
<h1>ZeroDayBuddy</h1>
<p>Bug bounty assistant — API server is running.</p>

<h2>Health</h2>
<ul>
<li><code>GET /health</code> — service liveness check</li>
</ul>

<h2>Authentication</h2>
<ul>
<li><code>POST /api/auth/login</code> — exchange username + password for a bearer token</li>
<li><code>POST /api/auth/register</code> — create a new user account</li>
<li><code>POST /api/auth/refresh</code> — exchange a refresh token for a new access token</li>
<li><code>POST /api/auth/logout</code> — revoke the current session (auth required)</li>
<li><code>GET /api/auth/profile</code> — return the current user (auth required)</li>
<li><code>POST /api/auth/change-password</code> — update password (auth required)</li>
</ul>

<p><small>Authenticated endpoints expect <code>Authorization: Bearer &lt;token&gt;</code>. A templated dashboard UI is forthcoming.</small></p>
</body>
</html>
`

// noListFS wraps an http.FileSystem to suppress directory indexes. Requests
// that resolve to a directory return os.ErrNotExist (which http.FileServer
// translates to 404), unless the directory has an index.html — in which case
// http.FileServer serves the index file as it normally would.
type noListFS struct {
	fs http.FileSystem
}

func (n noListFS) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if stat.IsDir() {
		// Allow if the directory contains an index.html
		if idx, err := n.fs.Open(name + "/index.html"); err == nil {
			_ = idx.Close()
			return f, nil
		}
		_ = f.Close()
		return nil, os.ErrNotExist
	}
	return f, nil
}
