---
title: "feat: Dashboard v1 — server-rendered HTMX UI with cookie auth"
date: 2026-05-10
type: feat
depth: deep
status: active
origin: docs/brainstorms/t2-3-dashboard-v1-requirements.md
related_units: U1, U2, U3, U4, U5, U6, U7
---

# Dashboard v1 (T2-3)

## Summary

Ship the v1 web dashboard described in `docs/brainstorms/t2-3-dashboard-v1-requirements.md`: 4 pages (login, dashboard project list, project detail, logout) using server-rendered Go `html/template` plus HTMX. Browser auth uses the existing JWT, served as an `HttpOnly+Secure+SameSite=Strict` cookie. Static assets (HTMX, Pico CSS) are vendored and served via `//go:embed`. Triage (status + severity changes on findings) goes through the existing `/api/findings/{id}` PATCH from T2-2 — no API forking, no new mutation endpoints.

7 implementation units, all feature-bearing, single PR. The architectural pivot is moving template + static assets to `//go:embed` so the binary is location-independent and the runtime cwd no longer matters.

This unblocks T4-2 (real-time scan progress) which can layer SSE/WebSocket over the dashboard's project pages, and T3-1 (manual project mode) which gets a UI surface for free.

---

## Problem Frame

After PR #20:
- `/health`, `/static/*`, `/`, six `/api/auth/*`, and 13 `/api/*` data endpoints are wired and tested.
- A browser visit to `/` shows a static API-documentation HTML stub with no interactivity.
- All mutations require an `Authorization: Bearer` header — no browser-friendly login form.
- `web/templates/` is empty. `web/static/{css,js,img}/` contain only `.gitkeep`.
- The CLI is the only first-class interface to the data.

T2-3 makes the browser a real client of the same data and auth surface, with the smallest viable scope: login, browse projects, drill into a project's findings/hosts/endpoints/tasks, triage findings inline, copy CLI commands for mutations the dashboard intentionally doesn't trigger directly.

---

## Requirements Trace

From `docs/brainstorms/t2-3-dashboard-v1-requirements.md`:

| Origin | Plan unit |
|---|---|
| D1 (server-rendered + HTMX) | U2, U3, U4, U5, U6 |
| D2 (cookie-issued JWT auth) | U1, U3 |
| D3 (classless CSS framework) | U2 |
| D4 (4 pages: login, dashboard, project detail, logout) | U3, U4, U5 |
| D5 (CLI commands for actions) | U5 |
| D6 (triage via existing PATCH endpoint) | U6 |
| Page set in §4 | U3, U4, U5, U6 |
| Verification gate in §5 | U7 |

The 8 open questions from origin §7 are resolved in this plan's Key Technical Decisions (D-OQ-1 through D-OQ-8 below).

---

## Key Technical Decisions

### Resolutions for origin's Open Questions

**D-OQ-1. Classless framework: Pico CSS v2.x.**
Pico has the most production-grade default styling, supports both light and dark modes via CSS prefers-color-scheme, and ships in ~30KB minified. Vendor `pico.min.css` directly into `web/static/css/`. Project-specific overrides live in a sibling `web/static/css/zdb.css` (~50 lines max).

**D-OQ-2. HTMX version: 2.x latest stable.**
HTMX 2.x is the current major version (1.x is in long-term maintenance only). Vendor `htmx.min.js` from the official 2.x release. Also vendor `htmx-ext-json-enc.js` for the JSON encoding extension needed by D6.

**D-OQ-3. Logout redirect: `/login?logged-out=1`.**
Tells users the logout was intentional vs "your session expired." Login template reads the query param and shows a confirmation banner.

**D-OQ-4. Two vendored JS files: `htmx.min.js` + `htmx-ext-json-enc.js`.**
No separate clipboard-copy script needed — modern browsers (the brainstorm scoped to evergreen-only) ship `navigator.clipboard.writeText`. The copy button uses HTMX's `hx-on:click` with a one-line inline call.

**D-OQ-5. Cookie name: `zdb_session`.**
Short, namespaced, distinguishable from any other cookie a user might have.

**D-OQ-6. Cookie expiration matches JWT `exp`.**
The JWT `exp` claim is the authoritative expiration; the cookie's `Max-Age` mirrors it. A `Remember Me` checkbox is deferred to a future PR.

**D-OQ-7. Logged-in user display: username only.**
Header shows `Logged in as <username>` plus a logout button. Role indication is deferred — most users won't need to know their role, and admins can see it via `/api/auth/profile`.

**D-OQ-8. Layout: single-column main + persistent header.**
Header is rendered by a `_header.tmpl` partial that the layout includes. Main content is one column, max-width Pico default. No sidebar in v1.

### New plan-time architectural decisions

**D1. Use `//go:embed` for both templates AND static assets.**
The brainstorm recommended embed for templates and left static-asset embedding open. The plan picks "embed both" for consistency:
- One source of truth for asset locations (`internal/web/embedded.go`).
- Single binary, fully cwd-independent — removes the `filepath.Abs("web/static")` dance from `App.Initialize` (the bridge T2-1 added).
- `Dependencies.StaticDir` field becomes obsolete; remove it. Tests that need an alternate static layout can pass an `embed.FS` substitute.

Trade-off: rebuilding the binary is required to update CSS/templates during dev. Acceptable for a Go-only project; live-reload is a developer-experience polish, not v1 scope.

**D2. Extract a `tokenFromRequest(r)` helper used by `AuthMiddleware`, `OptionalAuth`, and the new browser-auth handler.**
The cookie-OR-header logic must be implemented identically in three places. Putting it in one helper is the only way to guarantee they stay in sync.

**D3. Browser-friendly login is its own handler family in `internal/web/handlers/browser_auth.go`.**
Distinct from the JSON `AuthHandler` (T2-1). The two share `auth.Service` but their request/response shapes differ:
- JSON `AuthHandler`: JSON body in, JSON body out, returns token in response body.
- Browser `BrowserAuthHandler`: form-encoded body in, 303 redirect out, sets cookie.

Forking by content negotiation on a single endpoint (the alternative) would have made the API client behavior depend on `Accept` headers — fragile and surprising.

**D4. Templates parsed once at startup with a `template.FuncMap`.**
`internal/web/templates.go` parses every template under `web/templates/*.tmpl` into a single `*template.Template` at server construction time. `funcMap` includes:
- `cliCommand(cmd, args...)` — formats a CLI invocation like `$ zerodaybuddy recon --project foo` for the copy-command panels.
- Standard helpers: `severityClass(s)` for CSS classes by severity, `formatTime(t)` for human-readable timestamps.

Templates are unique by base filename: `dashboard.tmpl`, `project_detail.tmpl`, `login.tmpl`, plus `_layout.tmpl` and `_header.tmpl` partials.

**D5. Browser routes use `OptionalAuth` middleware (cookie-extended), not `AuthMiddleware`.**
`AuthMiddleware` returns 401 JSON on auth failure — wrong response for browser routes that should 303 to `/login`. `OptionalAuth` populates user-context if the token is valid and silently passes through otherwise. The browser handlers themselves check `middleware.GetUserFromContext` and either render or redirect.

API routes continue to use `AuthMiddleware` (401 on failure, JSON-shaped error). Two middleware → two response shapes; correct.

**D6. Project detail page does N synchronous storage queries.**
Per the brainstorm note, the page fetches: 1× project, 1× hosts, 1× endpoints, 1× findings, 1× tasks. That's 5 storage round-trips per page render. Acceptable for v1 because:
- The data layer is in-process (SQLite, no network round-trip).
- Lists are small for a single project.
- Concurrent calls via `errgroup.Group` would micro-optimize but add concurrency complexity for marginal speedup at this scale.

Document the design choice; a "single denormalized projection" optimization is a Tier 4 polish item if it ever becomes pain.

**D7. Triage UX: HTMX PATCH with `json-enc` extension; success feedback via `hx-on::after-request`; user manually refreshes for authoritative state.**
Per origin D6 recommendation. The triage form on each finding row uses `hx-patch="/api/findings/{id}"` + `hx-ext="json-enc"`. After a successful PATCH:
- HTMX fires `htmx:afterRequest` event.
- A small client-side handler (vanilla JS, ~10 lines, in `web/static/js/zdb.js`) shows a `✓ saved` badge for 2 seconds.
- The form values stay (last-submitted value); user reloads page for full state from server.

This is intentionally not "swap the whole row with the server's authoritative response." That would require server-side partial rendering, which forks the API. The brainstorm explicitly chose simplicity here.

### Plan-internal naming

| Concept | Name |
|---|---|
| Cookie | `zdb_session` |
| Cookie attributes | `HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=<jwt-exp-seconds>` |
| Token-extraction helper | `middleware.tokenFromRequest(r) (token string, ok bool)` |
| Browser handler | `handlers.BrowserAuthHandler` |
| Dashboard handler | `handlers.DashboardHandler` |
| Embedded FS package var | `web.EmbeddedFS` (or unexported `embeddedFS` if no external use) |

---

## High-Level Technical Design

This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.

### Browser auth flow (sequence)

```mermaid
sequenceDiagram
    participant B as Browser
    participant M as OptionalAuth
    participant H as Browser handlers
    participant S as auth.Service
    participant DB as SQLite

    Note over B: User visits /
    B->>M: GET /
    M->>M: tokenFromRequest(r) — no cookie, no header
    M->>H: pass through, ctx user=nil
    H->>H: GetUserFromContext == nil
    H-->>B: 303 Location: /login

    B->>H: GET /login
    H-->>B: 200 + login.tmpl rendered

    B->>H: POST /login (form: username, password)
    H->>S: Login(ctx, req, ip, ua)
    S->>DB: validate user + create session
    DB-->>S: AuthResponse{Token, ...}
    S-->>H: AuthResponse
    H-->>B: 303 Location: / + Set-Cookie: zdb_session=<jwt>; HttpOnly; Secure; SameSite=Strict; Max-Age=3600

    B->>M: GET / (Cookie: zdb_session=...)
    M->>M: tokenFromRequest(r) — found in cookie
    M->>S: ValidateToken(ctx, token)
    S-->>M: User
    M->>H: pass through, ctx user=alice
    H-->>B: 200 + dashboard.tmpl rendered with project list

    Note over B: User clicks Logout
    B->>H: POST /logout
    H->>S: Logout(ctx, token)
    S->>DB: revoke session
    H-->>B: 303 Location: /login?logged-out=1 + Set-Cookie: zdb_session=; Max-Age=0
```

### Page → handler → template + API mapping

```text
GET /                    → DashboardHandler.list      → dashboard.tmpl  +  store.ListProjects()
GET /login               → BrowserAuthHandler.loginForm → login.tmpl
POST /login              → BrowserAuthHandler.login    → 303 / Set-Cookie | login.tmpl with error
POST /logout             → BrowserAuthHandler.logout   → 303 + Set-Cookie clear
GET /projects/{id}       → DashboardHandler.projectDetail → project_detail.tmpl  +  GetProject + ListHosts + ListEndpointsByProject + ListFindings + ListTasks (5 storage calls)

(triage on the project detail page)
PATCH /api/findings/{id} → existing FindingsHandler.patch  (T2-2, unchanged)
                           ↑ HTMX hx-patch with json-enc extension
```

### Middleware composition for browser routes

```text
publicChain               (T2-1: RecoverPanic → SecurityHeaders → MaxBodySize → RateLimit)
  ↓
OptionalAuth (cookie+header)        ← NEW: extended to read cookie
  ↓
Browser handler — checks user context, renders or redirects
```

Compare to the existing API authedChain:

```text
publicChain
  ↓
AuthMiddleware (cookie+header)      ← NEW: extended to read cookie
  ↓
Data handler — assumes user is present (returns 401 if not, but middleware ensures it is)
```

Same `tokenFromRequest` helper backs both middleware variants.

---

## Output Structure

```text
internal/web/
├── server.go                   (modify — register browser routes)
├── templates.go                (NEW — parse-once template loader + funcMap)
├── embedded.go                 (NEW — //go:embed declarations for templates + static)
├── handlers/
│   ├── browser_auth.go         (NEW — login form, login POST, logout)
│   ├── browser_auth_test.go    (NEW)
│   ├── dashboard.go            (NEW — DashboardHandler with list + projectDetail)
│   ├── dashboard_test.go       (NEW)
│   └── (existing files unchanged: auth.go, projects.go, hosts.go, etc.)
├── middleware/
│   ├── auth.go                 (modify — extract tokenFromRequest helper; cookie support in AuthMiddleware + OptionalAuth)
│   └── auth_test.go            (modify — add cookie scenarios)
└── router_test.go              (modify — add e2e browser-flow test)

web/templates/                  (was empty; add 5 .tmpl files)
├── _layout.tmpl
├── _header.tmpl
├── login.tmpl
├── dashboard.tmpl
└── project_detail.tmpl

web/static/
├── css/
│   ├── pico.min.css            (NEW — vendored from picocss.com)
│   └── zdb.css                 (NEW — project overrides, ~50 lines)
└── js/
    ├── htmx.min.js             (NEW — vendored from htmx.org 2.x)
    ├── htmx-ext-json-enc.js    (NEW — vendored from htmx.org)
    └── zdb.js                  (NEW — ~10 lines for after-PATCH ✓ flash + clipboard copy)
```

`internal/core/app.go` is modified once: remove the `filepath.Abs("web/static")` dance per D1, replace `Dependencies.StaticDir` with no field (or repurpose for tests).

The plan creates ~14 new files and modifies ~5 existing files. Net diff likely +1500-2000 lines including templates, vendored assets (HTMX is ~14KB; Pico is ~30KB; both are minified single files committed verbatim).

---

## Implementation Units

### U1. Cookie-OR-header support in `AuthMiddleware` and `OptionalAuth`

**Goal:** Extend the existing two auth middleware functions to read the JWT from a cookie (`zdb_session`) when no `Authorization: Bearer` header is present. Header takes precedence when both are sent.

**Requirements:** D-OQ-5 (cookie name), D2 (token-extraction helper), D5 (browser routes use OptionalAuth).

**Dependencies:** None. Can land independently; existing API tests and behavior must stay green.

**Files:**
- `internal/web/middleware/auth.go` (modify): add `tokenFromRequest(r) (string, bool)` helper; update `AuthMiddleware` and `OptionalAuth` to use it
- `internal/web/middleware/auth_test.go` (modify): add cookie-extraction scenarios; verify header-precedence; verify expired-cookie behavior

**Approach:**
- New private helper: `tokenFromRequest(r *http.Request) (string, bool)`. Tries `Authorization: Bearer <token>` first. If absent or malformed, tries `Cookie: zdb_session=<token>`. Returns the token + ok flag.
- `AuthMiddleware` — replace the inline `Authorization` header parsing with `tokenFromRequest(r)`. If `!ok`, return 401 (existing behavior preserved). If `ok`, validate and populate context (existing).
- `OptionalAuth` — same swap. If `!ok`, pass through silently (existing). If `ok` but validation fails, pass through silently (existing).
- Cookie name lives as a package-level constant: `const SessionCookieName = "zdb_session"`. Exported for browser handlers to set.
- Edge case: cookie value is URL-encoded by `http.Cookie` automatically — but JWT base64 has `=` and `_` chars that are URL-safe. Verify roundtrip works with a test.

**Patterns to follow:**
- The existing `AuthMiddleware` shape (`internal/web/middleware/auth.go:23`).
- T2-2's "narrow interface for testability" pattern — `tokenFromRequest` works on `*http.Request` directly, no fancy abstraction.

**Test scenarios:**
- **Happy path — header only:** `Authorization: Bearer <valid>` → user populated. (existing test)
- **Happy path — cookie only:** `Cookie: zdb_session=<valid>` → user populated. (NEW)
- **Edge — header takes precedence:** both header and cookie set with different valid tokens → header's user wins. (NEW)
- **Edge — header malformed, cookie valid:** `Authorization: Basic xxx` + valid cookie → fall through to cookie, user populated. (NEW)
- **Error — no header, no cookie:** 401 from AuthMiddleware; pass-through from OptionalAuth. (existing)
- **Error — invalid cookie:** AuthMiddleware → 401; OptionalAuth → pass-through. (NEW)
- **Error — expired cookie:** same as invalid. (NEW)
- **JWT roundtrip via cookie:** set a real auth.Service-issued token in a cookie, request hits middleware, validates successfully. Catches subtle base64/URL-encoding issues. (NEW)

**Verification:**
- All existing AuthMiddleware/OptionalAuth tests pass unchanged (header-only flow preserved).
- New cookie scenarios pass.
- `grep -n "Authorization" internal/web/middleware/auth.go` finds it referenced in only one place (the `tokenFromRequest` helper) — no inline duplication.

---

### U2. Embedded templates and vendored static assets via `//go:embed`

**Goal:** Move `web/templates/*` and `web/static/**` into the binary via `//go:embed`. Add a parse-once template loader. Vendor HTMX (2.x), HTMX json-enc extension, and Pico CSS into the static tree. Remove the cwd-dependent `filepath.Abs("web/static")` dance.

**Requirements:** D1 (embed both), D-OQ-1 (Pico v2), D-OQ-2 (HTMX 2.x), D-OQ-4 (json-enc extension), D4 (parse-once + funcMap).

**Dependencies:** None. Can land before any handler/template work since the loader is infrastructure.

**Files:**
- `internal/web/embedded.go` (NEW): `//go:embed all:templates_root` and `//go:embed all:static_root` directives + exported `TemplatesFS embed.FS` and `StaticFS embed.FS`. Or: a single `//go:embed all:web` that embeds the parent directory if directory layout permits.
- `internal/web/templates.go` (NEW): `parseTemplates(fs embed.FS) (*template.Template, error)` — walks `web/templates/*.tmpl`, parses with the funcMap, returns a single `*template.Template` keyed by filename
- `internal/web/server.go` (modify): replace `http.FileServer(http.Dir(s.deps.StaticDir))` with `http.FileServer(http.FS(staticSubFS))`; parse templates at `NewServer` construction; store on Server
- `internal/core/app.go` (modify): remove the `filepath.Abs("web/static")` block; remove `StaticDir` from `web.Dependencies` literal
- `internal/web/server.go` Dependencies struct (modify): remove `StaticDir` field
- `web/static/js/htmx.min.js` (NEW vendored): HTMX 2.x latest stable
- `web/static/js/htmx-ext-json-enc.js` (NEW vendored): HTMX json-enc extension
- `web/static/css/pico.min.css` (NEW vendored): Pico CSS v2.x latest stable
- `web/static/css/zdb.css` (NEW): project overrides — ~50 lines max for v1
- `web/static/js/zdb.js` (NEW): ~10 lines for HTMX ✓-flash + clipboard.writeText helper
- `web/static/VENDORED.md` (NEW): document each vendored file's source URL, version, license, and update procedure
- `internal/web/embedded_test.go` (NEW): smoke tests verifying expected files are present in EmbeddedFS

**Approach:**
- `//go:embed` directives use repo-relative paths from the file's package; since `internal/web/embedded.go` is at `internal/web/`, paths are `../../web/static` and `../../web/templates`. **`//go:embed` does NOT support `..` paths.** Workaround: move embedded.go to the repo root (one file at root, embeds `web/...`) OR move `web/static` and `web/templates` under `internal/web/` (e.g., `internal/web/embedded/static`, `internal/web/embedded/templates`).
- Recommend: relocate to `internal/web/embedded/static` and `internal/web/embedded/templates`. Cleaner package boundaries; the `web/` directory at repo root becomes obsolete and gets removed in this unit.
- Template loader uses `template.New("").Funcs(funcMap).ParseFS(fs, "templates/*.tmpl")`. Returns the `*template.Template`; handlers look up by base name.
- `funcMap` includes: `cliCommand`, `severityClass`, `formatTime`. Add more as templates demand.
- Static handler: `http.FileServer(http.FS(staticSubFS))` where `staticSubFS, _ := fs.Sub(EmbeddedFS, "static")`. Apply the existing `noListFS` wrapper (from T2-1) for directory-listing suppression.
- The `Dependencies.StaticDir` field goes away entirely. App.Initialize stops passing it. Tests that need an alternate static layout substitute their own `embed.FS` via a new `Dependencies.StaticOverride embed.FS` field if real need surfaces (defer until needed).

**Patterns to follow:**
- Standard Go embed pattern: `//go:embed all:dirname` for everything including dotfiles (catches `.gitkeep`).
- T2-1's `noListFS` wrapper in `internal/web/static.go` applies to embedded FS the same way it applies to `http.Dir`.
- `internal/web/static.go` already has the `indexHTML` constant — that becomes the dashboard template instead, but that swap is U4's concern.

**Test scenarios:**
- **Happy path — embedded files present:** `EmbeddedFS` contains `templates/login.tmpl`, `static/css/pico.min.css`, `static/js/htmx.min.js`. (Smoke check; protects against accidental deletion or path-name drift.)
- **Happy path — templates parse:** `parseTemplates` returns no error and the result has all expected template names defined.
- **Edge — template syntax error:** if any template has bad syntax, `parseTemplates` returns an error including the file name.
- **Edge — funcMap helper called:** template using `{{cliCommand "recon" "--project" "foo"}}` renders `$ zerodaybuddy recon --project foo`.
- **Integration — static asset served via embed:** `GET /static/css/pico.min.css` against the running server returns 200 with the actual file content (verified via byte length sanity).

**Verification:**
- `go build ./...` clean.
- `find web -type f` returns nothing (the directory is gone); embedded files live under `internal/web/embedded/`.
- The binary, copied to `/tmp` and run from `/tmp`, still serves `/static/css/pico.min.css` correctly (proves cwd-independence).
- Template parsing is verified by `internal/web/embedded_test.go`.

---

### U3. Browser-friendly login/logout handlers + login template

**Goal:** Add `GET /login`, `POST /login`, and `POST /logout` handlers that work with form-encoded bodies and cookies. Include the login template that renders the form (with optional error and "logged out" notice).

**Requirements:** D2 (cookie auth), D3 (browser auth handler is its own family), D-OQ-3 (logout redirect with `?logged-out=1`), D-OQ-5 (cookie name).

**Dependencies:** U1 (`SessionCookieName` constant + cookie middleware support), U2 (template loader, login.tmpl).

**Files:**
- `internal/web/handlers/browser_auth.go` (NEW): `BrowserAuthHandler` struct with `auth.Service`, template, logger; `RegisterRoutes(mux, publicChain)`; `loginForm`, `login`, `logout` methods
- `internal/web/handlers/browser_auth_test.go` (NEW)
- `internal/web/embedded/templates/login.tmpl` (NEW): form with username + password fields; conditional error banner; conditional "you've been logged out" banner from `?logged-out=1`
- `internal/web/embedded/templates/_layout.tmpl` (NEW — also used by U4/U5): page skeleton with `<head>` (title, CSP-friendly meta, link to pico.min.css and zdb.css), `<body>` with `<header>` partial inclusion, `<main>{{block "content" .}}{{end}}</main>`, footer with HTMX scripts loaded
- `internal/web/embedded/templates/_header.tmpl` (NEW — also used by U4/U5): conditional "Logged in as <username> [Logout]" or empty if not authed
- `internal/web/server.go` (modify): construct `BrowserAuthHandler` and call `RegisterRoutes`

**Approach:**
- `BrowserAuthHandler` constructor: `NewBrowserAuthHandler(authSvc *auth.Service, tmpl *template.Template, logger *utils.Logger)`.
- `loginForm` (GET /login): if user already authenticated (via OptionalAuth-populated context), 303 → `/`. Otherwise render `login.tmpl` with data `{ Error: "", LoggedOut: r.URL.Query().Get("logged-out") == "1" }`.
- `login` (POST /login): parse form (`r.ParseForm()`); sanitize username via `validation.SanitizeString`; build `auth.LoginRequest`; call `s.authSvc.Login(ctx, req, ipAddress, userAgent)`. On error: re-render `login.tmpl` with `Error: "Invalid username or password"` (don't leak which); set status 401. On success: extract `Token` from `AuthResponse`; compute `Max-Age` from JWT `exp` claim (or use a sensible constant matching the JWT TTL); set cookie via `http.SetCookie`; 303 → `/`.
- `logout` (POST /logout): read cookie; if missing, just clear and redirect (idempotent). If present, call `authSvc.Logout(ctx, token)` to revoke (best-effort — log error but proceed). Set `Set-Cookie: zdb_session=; Max-Age=0; Path=/`. 303 → `/login?logged-out=1`.
- All three routes use the public chain only (no AuthMiddleware — login is public; logout works whether or not the cookie is valid).
- Cookie attributes: `HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, Path: "/", MaxAge: <derived>`. **Note**: setting `Secure` on localhost over HTTP requires the test server to use TLS or the cookie won't actually persist. For local dev, `Secure` should reflect `cfg.EnableTLS`. Make this configurable: `Secure: s.config.EnableTLS` so localhost dev works without TLS.
- IP and user-agent extraction: `r.RemoteAddr` and `r.Header.Get("User-Agent")`. The `cfg.ProxyEnabled` flag (already in WebServerConfig from T2-1) means we should respect `X-Forwarded-For` when set — defer the proxy-aware version to a small helper or use what exists.

**Patterns to follow:**
- T2-2's `ProjectsHandler` for the constructor + RegisterRoutes shape.
- The existing `AuthHandler.Login` method (`internal/web/handlers/auth.go:34`) for the auth.Service.Login wiring.

**Test scenarios:**
- **Happy path — GET /login renders form:** 200, body contains `<form action="/login" method="post">`, no error banner.
- **Happy path — GET /login when already authed:** 303 → `/`.
- **Happy path — GET /login?logged-out=1:** 200, body contains a "you have been logged out" banner.
- **Happy path — POST /login with valid creds:** 303 → `/`, `Set-Cookie: zdb_session=...; HttpOnly; SameSite=Strict; Max-Age=...`. (Verify `Secure` flag is set when TLS is on, omitted when off.)
- **Happy path — POST /logout with valid cookie:** 303 → `/login?logged-out=1`, `Set-Cookie: zdb_session=; Max-Age=0`. Session is revoked in DB (verified by trying to use the same token afterward).
- **Edge — POST /login form parse error (no body):** 400 with structured error message.
- **Edge — POST /login with empty username:** 401, re-renders form with generic error.
- **Edge — POST /login with valid username but wrong password:** 401, re-renders form with the same generic "Invalid username or password" (no leak about which was wrong).
- **Edge — POST /logout without cookie:** 303 → `/login?logged-out=1` anyway (idempotent).
- **Error — POST /login when authSvc.Login returns "user inactive":** 401 with generic error (don't leak the specific reason).
- **Integration — login → use cookie → logout flow:** POST /login, capture cookie; GET /api/auth/profile with cookie → 200 + user; POST /logout with cookie → 303 + cleared cookie; GET /api/auth/profile with the same (now-revoked) token → 401 (the `ValidateToken` "session still exists" check should fire).
- **Integration — Secure flag respects TLS config:** with `cfg.EnableTLS = false`, cookie omits Secure; with `EnableTLS = true`, cookie includes Secure. (One test of each.)

**Verification:**
- All test scenarios pass.
- `curl -i -X POST -d 'username=admin&password=AdminPass123!' http://localhost:8080/login` returns 303 + Set-Cookie zdb_session.
- A second `curl -i -b "zdb_session=<token>" http://localhost:8080/api/auth/profile` returns 200 with the admin user.

---

### U4. Layout, header, and dashboard page

**Goal:** Implement the "/" dashboard handler, the dashboard template that lists projects, and the shared `_layout.tmpl` and `_header.tmpl` partials that all three pages use.

**Requirements:** D4 (templates parsed once with funcMap), D5 (browser routes use OptionalAuth), D-OQ-7 (header shows logged-in user), D-OQ-8 (single-column layout).

**Dependencies:** U1 (cookie-aware OptionalAuth), U2 (template infrastructure), U3 (login template + layout/header partials). U3 introduces `_layout.tmpl` and `_header.tmpl`; U4 consumes them.

**Files:**
- `internal/web/handlers/dashboard.go` (NEW): `DashboardHandler` with `store storage.Store`, template, logger; `RegisterRoutes(mux, publicChainWithOptionalAuth)`; `index` method (the "/" handler) and `projectDetail` method (used in U5)
- `internal/web/handlers/dashboard_test.go` (NEW)
- `internal/web/embedded/templates/dashboard.tmpl` (NEW): extends layout; renders "Projects" heading, a table of project name + handle + platform + status, link per row to `/projects/{id}`. Bottom panel: "Create a new project" with copy-CLI-command (`$ zerodaybuddy project create --platform <p> --program <h>`)
- `internal/web/server.go` (modify): construct `DashboardHandler` and call `RegisterRoutes` for the `/` route only (project-detail registration also happens here but its handler method comes in U5)

**Approach:**
- `DashboardHandler.index` (GET /): pull user from context. If nil → 303 → `/login`. Otherwise: `projects, err := h.store.ListProjects(ctx)`. On error: log + render an error template (or a small HTML error response). On success: execute `dashboard.tmpl` with data `{ User: user, Projects: projects }`.
- The route lives on a chain that includes `OptionalAuth` (cookie-aware). The handler does the redirect-when-nil check; the middleware doesn't.
- The "/" registration in `buildRouter` also has to remove the existing `GET /{$}` index handler that serves the static API-doc HTML (replaced by the dashboard).
- Header partial: `_header.tmpl` receives the layout's data context. It expects `.User` to be either `*auth.User` or nil. Renders "Logged in as {{.User.Username}} | [Logout]" (logout is a `<form method="POST" action="/logout">` button) when User != nil, otherwise renders "Login" link.
- Layout: standard HTML5 skeleton. `<head>` includes `<title>{{block "title" .}}ZeroDayBuddy{{end}}</title>`, `<link rel="stylesheet" href="/static/css/pico.min.css">`, `<link rel="stylesheet" href="/static/css/zdb.css">`. `<body>` has `{{template "_header.tmpl" .}}`, `<main>{{block "content" .}}{{end}}</main>`. Footer loads `htmx.min.js`, `htmx-ext-json-enc.js`, and `zdb.js`.

**Patterns to follow:**
- T2-2's `ProjectsHandler.list` as the model for "fetch from store, render data" — same shape, just rendering a template instead of writing JSON.
- Template inheritance: dashboard.tmpl uses `{{template "_layout.tmpl" .}}` then defines a `{{define "content"}}...{{end}}` block.

**Test scenarios:**
- **Happy path — GET / authed user:** cookie set, valid; response 200 + HTML containing a `<table>` element and a row per project. The header shows "Logged in as <username>".
- **Happy path — GET / unauthed:** no cookie; response 303 → `/login`.
- **Happy path — empty project list:** authed user, no projects in store → 200 + HTML containing "No projects yet" message (or similar empty-state). No `<tr>` rows.
- **Edge — invalid cookie:** authed-looking cookie with bad token → OptionalAuth doesn't populate user → 303 → `/login` (treated same as no cookie).
- **Integration — header partial rendered consistently:** the header on the dashboard page contains the same "Logged in as ..." text as the project-detail page (verified by U5).
- **Integration — CSP-clean:** rendered HTML contains no inline `<script>` tags or `style=` attributes (proves CSP-cleanliness).

**Verification:**
- `curl -i -b "zdb_session=<valid>" http://localhost:8080/` returns 200 + HTML containing the project list and the header.
- `curl -i http://localhost:8080/` (no cookie) returns 303 + Location: /login.

---

### U5. Project detail page (`/projects/{id}`) with sections + CLI command panels

**Goal:** Implement the project detail page handler. The page shows project metadata, sections for Findings (with inline triage forms), Hosts, Endpoints, Tasks, and bottom panels with copy-CLI-command snippets for recon/scan/report.

**Requirements:** D4 (single page with sections), D5 (CLI command UX), D6 (storage N+1 acceptable for v1).

**Dependencies:** U2 (template loader + funcMap with `cliCommand`), U4 (layout/header, dashboard handler scaffold).

**Files:**
- `internal/web/handlers/dashboard.go` (modify, started in U4): add `projectDetail` method
- `internal/web/embedded/templates/project_detail.tmpl` (NEW): extends layout; renders project metadata, four sections, three CLI command panels
- `internal/web/embedded/templates/_finding_row.tmpl` (NEW): partial for one finding row, used by both the full project detail render AND U6's HTMX swap target
- `internal/web/server.go` (modify, started in U4): register `GET /projects/{id}` route

**Approach:**
- `DashboardHandler.projectDetail` (GET /projects/{id}): pull user; if nil → 303 → `/login`. Pull `id := r.PathValue("id")`. Fetch in sequence:
  1. `project, err := h.store.GetProject(ctx, id)` — if not found → 404 page (HTML, friendly)
  2. `hosts, _ := h.store.ListHosts(ctx, id)` — log error, render section as empty
  3. `endpoints, _ := h.store.ListEndpointsByProject(ctx, id)`
  4. `findings, _ := h.store.ListFindings(ctx, id)`
  5. `tasks, _ := h.store.ListTasks(ctx, id)`
- Template data: `{ User, Project, Hosts, Endpoints, Findings, Tasks }`.
- Template structure (per origin §4 D4 page set):
  - `<h1>{{ .Project.Name }}</h1>` + project metadata (handle, platform, status, dates)
  - `<section><h2>Findings ({{len .Findings}})</h2><table>...{{range .Findings}}{{template "_finding_row.tmpl" .}}{{end}}</table></section>`
  - `<section><h2>Hosts ({{len .Hosts}})</h2><table>...</table></section>`
  - `<section><h2>Endpoints ({{len .Endpoints}})</h2><table>...</table></section>`
  - `<section><h2>Tasks ({{len .Tasks}})</h2><table>...</table></section>`
  - `<section class="cli-panels"><h2>Run actions</h2>` followed by 3 sub-panels:
    - "Run reconnaissance: `$ zerodaybuddy recon --project {{ .Project.Name }} --concurrent 10` [Copy]"
    - "Run vulnerability scanning: `$ zerodaybuddy scan --project {{ .Project.Name }} --target all` [Copy]"
    - "Generate report: `$ zerodaybuddy report --project {{ .Project.Name }} --format markdown` [Copy]"
- Each Copy button has a `data-copy="<command>"` attribute; `web/static/js/zdb.js` (added in U2) wires `click → navigator.clipboard.writeText(this.dataset.copy)`.
- `_finding_row.tmpl` renders the row's static content plus the inline triage form (no functionality yet — U6 wires HTMX). Keep it self-contained so U6 can return it as the HTMX swap target.

**Patterns to follow:**
- T2-2's flat data handler structure (one method per route) but with template rendering instead of JSON encoding.
- The `funcMap.cliCommand` helper from U2 produces the formatted CLI string.

**Test scenarios:**
- **Happy path — GET /projects/{id} authed:** valid cookie + valid id → 200 + HTML containing project name, all 4 sections, all 3 CLI panels. The CLI panels include the project's name in the command string.
- **Happy path — sections show entity counts:** `<h2>Findings (3)</h2>` when 3 findings exist.
- **Happy path — empty sections render gracefully:** project with no hosts → "No hosts discovered yet" message in that section.
- **Edge — project doesn't exist:** 404 + friendly HTML 404 page (not the JSON `{"error": ...}`).
- **Edge — unauthed:** 303 → `/login`.
- **Edge — storage error on a child entity (e.g., ListHosts fails):** project still renders; that section shows an error banner; other sections render normally.
- **Integration — `_finding_row.tmpl` is consumable as a partial:** U6 will reuse it, but a smoke test here confirms it renders standalone with finding-only data.

**Verification:**
- `curl -i -b "zdb_session=<valid>" http://localhost:8080/projects/<id>` returns 200 + HTML with all sections.
- The `data-copy` attribute is present on each CLI button.
- A nonexistent id returns 404 with HTML, not JSON.

---

### U6. HTMX-driven inline finding triage

**Goal:** Wire the inline triage forms on each finding row to the existing `/api/findings/{id}` PATCH endpoint via HTMX with the `json-enc` extension. Show ✓ feedback after a successful PATCH; show error banner on failure. The existing API handler from T2-2 is **not** modified.

**Requirements:** D6 (use existing PATCH; UX feedback via after-request hook), D7 (no row-swap; user manually refreshes).

**Dependencies:** U2 (HTMX vendored, json-enc extension vendored), U5 (`_finding_row.tmpl` exists with the form HTML).

**Files:**
- `internal/web/embedded/templates/_finding_row.tmpl` (modify, started in U5): add HTMX attributes to the triage form
- `web/static/js/zdb.js` (modify, started in U2): add `htmx:afterRequest` event handler for the ✓-flash logic
- `internal/web/embedded/templates/_layout.tmpl` (modify if needed): ensure HTMX scripts load in correct order (htmx.min.js → htmx-ext-json-enc.js → zdb.js)

**Approach:**
- Each finding row has a `<form>` per editable field OR a single `<form>` with both `<select name="status">` and `<select name="severity">`. Recommend single form per row for atomicity (matches D2 of brainstorm).
- The form attributes:
  - `hx-patch="/api/findings/{{.ID}}"` — sends PATCH
  - `hx-ext="json-enc"` — encodes form fields as JSON instead of url-form-encoded
  - `hx-swap="none"` — server returns JSON, HTMX doesn't try to swap into DOM
  - `hx-include="this"` — sends both selects' current values
  - `hx-headers='{"Authorization": ""}'` — explicitly omit Authorization since we're using cookies (HTMX shouldn't add a default empty one; this is just to be explicit; verify behavior in test)
- Auth via cookie: HTMX inherits browser cookie behavior automatically, so the cookie will be sent. No special handling needed.
- After-request behavior in `zdb.js`:
  - Listen for `htmx:afterRequest` events on `document.body`.
  - If `evt.detail.successful` (status 200-299) → find the form's `<button>` element, replace text with `✓ saved`, schedule restoration after 2 seconds.
  - If not successful → show inline error message (read `evt.detail.xhr.responseText`, parse JSON if possible, show in a `<span class="error">` near the button).
- The form's `<select>` elements have an `onchange` hook (HTMX `hx-trigger="change"`) so changing a value automatically triggers the PATCH — no submit button needed. Or keep an explicit "Save" button for clarity. Recommend: explicit button — less surprising.

**Patterns to follow:**
- HTMX standard pattern: `<form hx-patch="..." hx-ext="json-enc">` is the json-enc extension's canonical use.
- The existing `FindingsHandler.patch` in `internal/web/handlers/findings.go` (T2-2) handles the request unchanged. The PATCH allow-list (status, severity) is what the form fields are.

**Test scenarios:**
- **Happy path — PATCH succeeds:** simulated HTMX request with valid cookie + form data → /api/findings/{id} returns 200 + updated finding; `htmx:afterRequest` fires; ✓-flash visible. (Browser-side test; for backend verification, tests just confirm the PATCH endpoint accepts the JSON body shape produced by json-enc.)
- **Edge — Cookie-only auth (no Authorization header) reaches the PATCH endpoint successfully:** integration test that submits a triage form via cookie and observes the PATCH call succeeding. This ties U1's middleware change into the triage flow.
- **Error — invalid value:** PATCH /api/findings/{id} with body `{"status": "nonsense"}` → 400 invalid_field; `zdb.js` shows the error message inline.
- **Error — readonly user attempts triage:** PATCH returns 403; error banner shown.
- **Integration — json-enc encodes form correctly:** verify that an HTMX form with `<input name="status" value="resolved">` and `<input name="severity" value="low">` produces a JSON body `{"status": "resolved", "severity": "low"}` in the request to /api/findings/{id}. (Headless browser test OR a careful unit test of the JSON-encoder shape.)

**Verification:**
- Live in a browser: change a finding's status dropdown, click Save, see ✓ flash, hard-refresh the page, status is persisted.
- Network tab shows the PATCH with `Content-Type: application/json` and body `{"status": "..."}`.
- No CSP violations in devtools console.

---

### U7. End-to-end browser-flow integration test

**Goal:** Add an integration test that exercises the complete browser flow: visit `/` → 303 to `/login` → POST login → 303 to `/` → render dashboard → visit `/projects/{id}` → render detail → POST `/logout` → 303 back to `/login`.

**Requirements:** Brainstorm §5 verification gate.

**Dependencies:** U1, U2, U3, U4, U5, U6 (all of the above).

**Files:**
- `internal/web/router_test.go` (modify): add `TestRouter_BrowserFlow_FullLifecycle` and a few supporting tests

**Approach:**
- Build on the existing `setupCombinedBackend(t)` and `loginAs(t, ...)` helpers from T2-2.
- The test uses `srv.buildRouter().ServeHTTP(w, req)` (no real network); manually manages a `http.CookieJar`-style `Cookie` header propagation between requests.
- Test sequence:
  1. `GET /` with no cookie → 303 + Location: `/login`
  2. `GET /login` → 200 + HTML form
  3. `POST /login` form-encoded `username=admin&password=AdminPass123!` → 303 + Location: `/` + `Set-Cookie: zdb_session=...`
  4. Capture the cookie value; reuse on subsequent requests
  5. `GET /` with cookie → 200 + HTML containing project list
  6. Create a project via the existing helper → get an id
  7. `GET /projects/{id}` with cookie → 200 + HTML with sections
  8. `POST /logout` with cookie → 303 + Location: `/login?logged-out=1` + cookie cleared
  9. `GET /api/auth/profile` with the same (now-revoked) cookie → 401 (proves session was revoked)
- Additional tests:
  - `TestRouter_BrowserFlow_LoginErrorRendersForm`: bad password → 401 + login form re-rendered with error
  - `TestRouter_BrowserFlow_CookieAndHeaderBoth`: send both → header wins, behavior matches header value (this is U1's middleware test but at integration scope)
  - `TestRouter_BrowserFlow_LoggedOutQueryShowsBanner`: GET `/login?logged-out=1` → 200 with banner text

**Patterns to follow:**
- T2-2's `TestRouter_FullProjectLifecycle` (in `internal/web/router_test.go`) — the same sequence but for the API endpoints. T2-3's e2e test mirrors that style with browser-flow specifics.

**Test scenarios:** (above is exhaustive for this unit; everything is integration-shaped)

**Verification:**
- All scenarios pass with `-race`.
- Clearing the cookie after logout AND verifying the previously-valid token now 401s on a separate API call confirms session revocation works end-to-end.

---

## System-Wide Impact

| Surface | Before | After |
|---|---|---|
| Web UI | Static API-doc HTML stub at `/`; no login | 4 pages: login, dashboard, project detail, logout. HTMX-driven triage. |
| Auth transport | `Authorization: Bearer` header only | Header (existing) OR `zdb_session` cookie (new). Same JWT, two transports. |
| `web/templates/` | Empty directory at repo root | Migrated to `internal/web/embedded/templates/`, populated with 5 .tmpl files. Old directory removed. |
| `web/static/` | Empty subdirs at repo root | Migrated to `internal/web/embedded/static/`, populated with 5 vendored + project files. Old directory removed. |
| `web.Dependencies` | `{AuthService, StaticDir, Store}` | `{AuthService, Store}` (StaticDir removed; embedded FS replaces it) |
| `App.Initialize` cwd dependence | `filepath.Abs("web/static")` resolves at startup | No path resolution; `//go:embed` baked into binary |
| Browser routes | None | 4 new routes on the public chain with OptionalAuth |
| Total routes | 19 (3 static/health/index + 6 auth + 13 data) | 23 (replaced welcome stub with dashboard; added /login, /logout, /projects/{id}) |
| Binary size | ~25MB | ~25.05MB (pico+htmx+templates is ~50KB compressed) |

**Affected parties:**
- **CLI users**: unchanged. The CLI doesn't touch the web layer.
- **Existing API clients**: unchanged. Bearer-token auth still works identically.
- **New browser users**: gain the 4-page UI.
- **Operators**: deploy the same binary; no new files to ship alongside; no cwd configuration concerns.

---

## Scope Boundaries

**In scope:**
- All work described in U1-U7.

### Deferred to Follow-Up Work

- **Per-host, per-endpoint, per-finding individual detail pages** (origin §6 deferred): the project detail page's row-level data is enough for v1 triage.
- **Project create/delete UI forms** (origin §6): show CLI commands instead.
- **Real action-trigger endpoints** (POST `/api/projects/{id}/recon`, etc.): out of T2-3 scope; needs its own design pass for async-job patterns.
- **Real-time scan progress** (T4-2): polling, SSE, or WebSocket; layered on the dashboard later.
- **Per-finding evidence rendering** (markdown, syntax highlight): triage row shows raw text in v1; rich rendering is polish.
- **Profile page / password change UI**: JSON endpoints exist; UI deferred.
- **Pagination UI**: API doesn't paginate either.
- **Multi-user account creation flow**: CLI-managed only.
- **`Remember Me` checkbox** for longer cookie expiration.
- **CSRF tokens beyond `SameSite=Strict`**: relying on the cookie attribute alone for v1.
- **Live-reload of templates during dev**: rebuild required.
- **Markdown / syntax highlighting in evidence**.
- **Custom 404/500 error pages** for the browser routes (HTML-friendly): a small follow-up; v1 can use the framework default 404 text since most failures come through the API in JSON shape.

### Not chasing

- **Mobile responsiveness** beyond what Pico provides for free.
- **Dark mode** beyond Pico's `prefers-color-scheme` default.
- **Accessibility audit** beyond shipping semantic HTML.
- **i18n**.
- **SPA frameworks**, **Tailwind**, **build steps**, **Node tooling**.
- **localStorage-based auth**.
- **OAuth/OIDC integration**.

---

## Open Questions (defer to implementation)

1. **HTMX 2.x exact patch version**: pick latest stable at execution time; document in `web/static/VENDORED.md` (added by U2).
2. **Pico CSS exact version**: same.
3. **`zdb.css` actual contents**: discover during U2 — likely `<table>` density tweaks, button consistency, error-banner styling. Cap at ~50 lines.
4. **Login form's "remember me" checkbox**: explicitly deferred above. If U3 implementation discovers it's trivial to add (Max-Age=720h instead of matching JWT exp), reconsider; otherwise leave out.
5. **404 page when project missing on detail page**: U5 falls back to a small inline "Not found" message in the layout; if it feels too sparse, add a dedicated `404.tmpl` as a small follow-up.
6. **JSON encoding shape via HTMX json-enc with empty fields**: verify at U6 implementation that an empty value submits as `""` (string) vs omitted; the API treats null vs missing differently.
7. **`secure` cookie attribute when `cfg.EnableTLS = false`**: U3 plans to mirror the TLS flag — verify on first run that browsers accept this on localhost without `Secure`.

---

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `//go:embed` directive doesn't accept the relocated paths and U2 has to be re-architected | Low | Medium | Plan calls for moving paths under `internal/web/embedded/`, which Go's embed supports cleanly. Verify in U2 by writing the directive first and running `go build` before any other U2 work. |
| Cookie roundtrip breaks JWT format (URL-encoding issue) | Medium | High (auth wouldn't work) | U1 has an explicit roundtrip test using a real JWT through `http.Cookie` setting and reading. Catches it before downstream units depend on it. |
| HTMX `json-enc` extension produces unexpected JSON shape (e.g., wraps single-field forms differently) | Medium | Medium | U6 has an explicit json-shape test. If json-enc proves wrong-shaped, fallback is a 5-line `hx-on::config-request` handler that JSON-encodes the form manually. |
| `Secure` cookie flag prevents local-dev login (cookie isn't set when accessing via plain HTTP) | High if not handled | High (browser couldn't log in) | U3 explicitly mirrors `cfg.EnableTLS` for the Secure flag. Tested with both true/false. |
| `SameSite=Strict` blocks legit cross-tab opening of project URLs | Medium | Low (annoyance) | Document the trade-off; consider `SameSite=Lax` as a config knob for v1.5 if users complain. |
| Removing the `web/` directory at repo root breaks references in docs/CLAUDE.md | Low | Low | Grep for `web/static` and `web/templates` in `*.md` files during U2 and update the references. |
| Template parse error at startup crashes the server | Low | High (server won't start) | Templates are parsed in `NewServer` constructor; on parse error, the constructor returns the error, surfaced in `App.Initialize`, surfaced in the CLI startup with a clear message. Tested in U2. |
| Existing `Dependencies.StaticDir` removal breaks tests that reference it | Medium | Low | U2 covers the test updates; the field's only producer is `App.Initialize` and only consumer is `buildRouter`. |
| Cookie-OR-header precedence test fails (reverse precedence accidentally implemented) | Medium | Medium | U1 has a dedicated test; the helper documentation comment specifies precedence explicitly. |
| Rendering 5 storage queries serially makes the project detail page slow under load | Low for v1 | Medium under load | Document the design choice (D6); revisit with `errgroup.Group` if load becomes an issue. |

---

## Verification Gate

The plan is complete when **all** of the following pass:

```text
1. go build ./...                                                      # clean
2. go test ./... -count=1 -race                                        # all packages green
3. golangci-lint run --timeout=3m                                      # zero issues at v1.64.8
4. curl -i http://localhost:8080/                                      # 303 → /login (no cookie)
5. curl -i http://localhost:8080/login                                 # 200 + HTML form
6. curl -i -X POST -d 'username=admin&password=AdminPass123!' http://localhost:8080/login
                                                                        # 303 → / + Set-Cookie: zdb_session=...; HttpOnly; SameSite=Strict
7. curl -i -b "zdb_session=<token>" http://localhost:8080/             # 200 + dashboard HTML
8. curl -i -b "zdb_session=<token>" http://localhost:8080/projects/<id> # 200 + project detail HTML with sections
9. curl -i -X POST -b "zdb_session=<token>" http://localhost:8080/logout # 303 + cleared cookie
10. browser smoke test: visit / → login → see dashboard → click project →
    triage a finding via dropdown + Save → see ✓ flash → reload → status persisted
11. devtools console: zero CSP violations on every page
12. binary copied to /tmp and run from /tmp still serves /static/css/pico.min.css
    (proves cwd-independence from D1)
```

Steps 4-9 require `./zerodaybuddy serve` from a fresh `init`. Step 10 requires a browser; can be skipped in CI but should be run locally before merging.

---

## Suggested Commit Boundary

Seven commits in one PR, one per implementation unit. The order respects dependencies:

1. `feat(middleware): cookie-OR-header support in AuthMiddleware and OptionalAuth (T2-3 U1)`
2. `feat(web): embed templates and static assets via go:embed (T2-3 U2)`
3. `feat(web): browser-friendly login/logout handlers (T2-3 U3)`
4. `feat(web): dashboard handler and project list page (T2-3 U4)`
5. `feat(web): project detail page with sections and CLI command panels (T2-3 U5)`
6. `feat(web): HTMX-driven inline finding triage (T2-3 U6)`
7. `test(web): end-to-end browser-flow integration tests (T2-3 U7)`

U1 + U2 are independent of each other and could land in either order. U3 depends on U1 (cookie support) and U2 (login.tmpl). U4 depends on U3 (header partial). U5 depends on U4. U6 depends on U5. U7 depends on all.

If the implementer prefers, U1 + U2 can land in a single commit since they're both "infrastructure with no user-visible change." Either is fine.
