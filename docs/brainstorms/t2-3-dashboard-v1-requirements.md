# T2-3: Dashboard v1 — Server-Rendered + HTMX

**Date:** 2026-05-10
**Origin:** `docs/brainstorms/codebase-punch-list-requirements.md` T2-3 (templates and static-asset pipeline)
**Tier:** 2 (web UI)
**Depends on:** T2-1 (router wired, PR #19), T2-2 (data API, PR #20)
**Successor:** suitable for `/ce-plan`

---

## 1. Goal

Ship a v1 web dashboard that gives a logged-in user browser access to the four observable behaviors enabled by T2-2's API: list projects, browse a project's discovered hosts/endpoints/findings/tasks, triage findings (status/severity changes via the existing PATCH endpoint), and copy CLI commands for the actions the dashboard intentionally doesn't trigger directly.

The dashboard is **additive** to the CLI, not a replacement. It exists for tasks the CLI is awkward at — keyboard-clicking through findings, sharing a project URL with a teammate, and visually navigating discovered data — while leaving long-running operations (recon/scan/init) to the CLI invocation pattern users already know.

---

## 2. Why now / counterfactual

Today, with PRs #16-#20 merged:
- The router serves auth, static, and 13 data endpoints. All of it is reachable from `curl` with a bearer token.
- A user can `zerodaybuddy project list`, `recon`, `scan`, `report` — the CLI does everything.
- A user **cannot** open a browser to `http://localhost:8080/` and see anything beyond a static welcome stub.

Without T2-3 a user has only two paths to inspect findings: scrolling CLI output (pre-formatted, fixed-width, lossy for nested structures) or opening the SQLite DB directly (raw, no auth). Both lose context. Both are unshareable.

T2-3 closes that gap with the smallest UI surface that the data API already supports.

---

## 3. Users and use cases

The dashboard's user is the same person who runs the CLI: a security researcher logged into the box where ZeroDayBuddy is running (or accessing it via SSH-tunneled localhost). All four use cases are in scope for v1:

| # | Use case | How v1 addresses it |
|---|---|---|
| 1 | Triage findings interactively | Inline status/severity controls on each finding row; HTMX PATCH to `/api/findings/{id}` |
| 2 | Browse discovered data structurally | Project detail page lists hosts, endpoints, findings, tasks |
| 3 | Show read-only views to others | Sharable URLs (`/projects/{id}`); the recipient logs in then follows the link |
| 4 | Run actions (recon/scan/etc.) | "Show CLI command + copy button" panels — **no** new server endpoints triggered from the UI |

Use case 4's CLI-command-display approach is the central scope decision. It honors the CLI-first identity of the tool, prevents an O(scope-explosion) of async-job endpoints, and keeps T2-3 shippable in one PR. Real action-triggering becomes its own future plan when there's clear demand.

---

## 4. Key Decisions

### D1. Render model: server-rendered Go `html/template` + HTMX

Standard library `html/template` parses and renders pages on each request. HTMX (vendored as `web/static/js/htmx.min.js`, ~14KB minified) handles partial-page updates: clicking "mark as resolved" issues a PATCH and HTMX swaps in the new finding row.

Why HTMX over alternatives:
- **CSP-friendly.** No inline scripts or styles. Loaded from `/static/js/`, satisfies `default-src 'self'`.
- **No build step.** Fits a Go-only repo with no Node tooling.
- **Progressive enhancement.** Pages render and links work even with JS disabled (basic browse-only); HTMX layers triage on top.
- **Tiny ongoing maintenance.** HTMX is one vendored file; updates are a `curl` of the new release.

Rejected: vanilla-JS-fetching-API (more client complexity, still needs JS for every authed request), no-JS-only (would need a parallel form-encoded triage endpoint), SPA framework (Node toolchain, ongoing dep churn).

### D2. Browser auth flow: cookie-issued JWT

The existing `auth.Service` issues JWTs. The browser flow:

1. `GET /login` — login form (HTML, no auth required).
2. `POST /login` — form-encoded `username` + `password`. Server delegates to `auth.Service.Login`, retrieves the JWT, sets it as `HttpOnly + Secure + SameSite=Strict` cookie named e.g. `zdb_session`, returns 303 → `/`.
3. `AuthMiddleware` is extended to read the JWT from the cookie OR the `Authorization: Bearer` header (existing behavior). Both produce the same `auth.User` in request context.
4. `POST /logout` — server clears the cookie via `Set-Cookie: zdb_session=; Max-Age=0`, calls `auth.Service.Logout` to revoke the session, redirects to `/login`.

Why cookie-issued JWT over alternatives:
- **One auth system, two transports.** API clients keep using `Authorization: Bearer`; browser uses cookies. The token is the same JWT, validated by the same code.
- **CSRF protection comes free with `SameSite=Strict`.** Modern browsers refuse to send the cookie on cross-site requests, which eliminates the CSRF token machinery server-side sessions would require.
- **No new session model.** The JWT's existing claims (`exp`, `user_id`, `role`) flow through. Logout still revokes via the existing session table that backs `ValidateToken`'s "session still exists" check.

Rejected: server-side sessions (would create a parallel auth system), localStorage tokens (every HTMX request needs JS to attach the header, fights HTMX's JS-light strength).

### D3. CSS: classless framework (Pico CSS or similar)

Vendor a single ~10-15KB classless CSS file at `web/static/css/`. Write semantic HTML — `<header>`, `<main>`, `<table>`, `<form>` — and the framework styles it automatically based on tag names. Add a small `web/static/css/zdb.css` with project-specific overrides (~50 lines max).

Why classless over alternatives:
- **Zero markup pollution.** Templates stay readable; no `class="text-sm font-medium text-gray-700 dark:text-gray-300"` noise.
- **CSP-clean.** Single file from `/static/`, no inline styles, no external CDN.
- **Aesthetic by default.** Pico in particular looks production-grade out of the box without design effort.
- **Solo-maintainable.** Updating the framework is one file replacement.

Pico CSS is recommended; Simple.css or Water.css are equivalent fallbacks if Pico's stylistic choices don't fit. Final choice in the plan.

Rejected: vanilla CSS hand-written (more upfront effort with no clear payoff for a security tool), Tailwind (Node toolchain), no CSS (looks crude).

### D4. Page set: tight v1 (4 pages)

| URL | Method | Auth | Renders |
|---|---|---|---|
| `/login` | GET | public | login form |
| `/login` | POST | public (form-encoded) | sets cookie, 303 → `/` on success; re-renders form with error on fail |
| `/` | GET | required | dashboard = project list, plus a "create project" panel showing CLI commands |
| `/projects/{id}` | GET | required | project detail: header with project metadata, then sections for Findings (with inline triage), Hosts, Endpoints, Tasks; bottom panel with copy-CLI-command snippets for recon/scan/delete |
| `/logout` | POST | required | clears cookie, revokes session, 303 → `/login` |

Plus the existing `/health`, `/static/*`, and JSON `/api/*` endpoints, all unchanged.

Per-host, per-endpoint, per-finding individual detail pages are **deferred**. The project detail page can show enough for triage (finding row inline expands to evidence; host/endpoint rows are summaries with values + status). When users hit a wall — needing markdown evidence rendering, syntax highlighting, multi-step triage workflows — that drives v2.

### D5. CLI commands as the action-trigger UX

Where the dashboard would otherwise have a "Run recon" button, instead show:

```text
Run reconnaissance on this project:
$ zerodaybuddy recon --project foo --concurrent 10
[ Copy command ]
```

The copy button is wired by an external script (`/static/js/zdb.js`) that listens for clicks on `[data-clipboard-target]` and copies the adjacent `<code data-clipboard>` content via `navigator.clipboard.writeText`. No inline event handlers — those would violate the strict `default-src 'self'` CSP. No backend involved.

This applies to:
- Project create (`zerodaybuddy project create --platform hackerone --program ...`)
- Project delete (`zerodaybuddy project delete --project ...` — though admin-only; CLI may not have this command yet, defer to plan)
- Recon (`zerodaybuddy recon --project ... --concurrent ...`)
- Scan (`zerodaybuddy scan --project ... --target all|host:X|endpoint:Y|<url>`)
- Report generation (`zerodaybuddy report --project ... --format markdown`)

### D6. Triage works through the existing JSON PATCH endpoint

HTMX's vendored `json-enc` extension lets the triage form `hx-patch="/api/findings/{id}"` with a JSON body containing the changed fields. The existing handler from T2-2 is unchanged. The response can return a re-rendered HTML fragment (handler reads `Accept: text/html`) OR HTMX uses `hx-swap="none"` and an external script listens for `htmx:afterRequest` to flash a "saved ✓" indicator.

Recommend the latter (server returns JSON; the external script in `/static/js/zdb.js` handles UX feedback via the `htmx:afterRequest` event listener) to avoid forking the API by content negotiation. No inline handlers — the strict CSP forbids them.

---

## 5. What "done" looks like

A logged-in user with the seeded `admin` (or any user-tier) account can:

1. Visit `http://localhost:8080/` in a browser.
2. Be redirected to `/login` if not authenticated.
3. Submit username + password.
4. See a list of projects on `/`.
5. Click a project → land on `/projects/{id}`.
6. See sections for Findings, Hosts, Endpoints, Tasks populated from the API.
7. Click status/severity controls on a finding → see the value update without a full page reload.
8. Copy CLI commands for recon/scan/report from the bottom panel.
9. Click logout → return to `/login`.

Verification commands (executable from a fresh `init` and `serve`):

```text
1. curl -i http://localhost:8080/        → 303 → /login (when no cookie)
2. curl -i http://localhost:8080/login   → 200 + HTML form
3. curl -i -X POST -d 'username=admin&password=AdminPass123!' http://localhost:8080/login
                                         → 303 → / + Set-Cookie: zdb_session=...; HttpOnly; Secure; SameSite=Strict
4. curl -i -b "zdb_session=<token>" http://localhost:8080/      → 200 + HTML dashboard
5. curl -i -b "zdb_session=<token>" http://localhost:8080/projects/some-id  → 200 + HTML with sections
```

A browser visiting localhost should also get zero CSP violations in the devtools console.

---

## 6. Scope Boundaries

### In scope (v1)

- All work described in D1-D6 above.
- The 4 pages in D4.
- Cookie-issued-JWT auth flow including AuthMiddleware extension.
- Vendored HTMX + classless CSS + project-specific CSS overrides.
- Inline triage on the project detail page.
- Copy-CLI-command panels.
- Header partial showing logged-in username + logout button.
- Tests: server-side HTML rendering tests (template parses, expected content present, auth gate enforced), middleware tests (cookie-or-header acceptance), an end-to-end browser-flow test using the real auth backend.

### Deferred to Follow-Up Work

- **Per-host, per-endpoint, per-finding individual detail pages** — when users hit limits browsing within a project, this becomes a future PR. The data is already in the JSON API; the templates just don't exist yet.
- **Project create/delete UI forms** — currently shown as CLI commands. Real forms come when the friction of "switch to terminal" is documented as actually painful.
- **Real action-trigger endpoints** (POST `/api/projects/{id}/recon`, etc.) — separate scope. Async-job design, status polling, cancellation are real but not in T2-3.
- **Real-time scan-progress visualizations** — T4-2.
- **Per-finding evidence rendering** — markdown, syntax highlighting, screenshots. The triage row can show plain-text evidence; rich rendering is future polish.
- **Profile page / password change UI** — JSON endpoints exist; UI is deferred.
- **Pagination UI** — the API doesn't paginate either.
- **Multi-user account creation flow** — admin-managed only via CLI for now.

### Not chasing

- **Mobile responsiveness.** Security tool, desktop-primary. Pico's defaults will work passably on mobile for free; explicit mobile design is out.
- **Dark mode** beyond what the classless framework gives by default.
- **Accessibility audit** beyond shipping semantic HTML (no positive a11y commitment in v1).
- **i18n.** English only.
- **SPA frameworks** (React, Vue, Svelte). See D1.
- **localStorage-based auth.** See D2.
- **Tailwind, build steps, Node tooling.** See D3.
- **OAuth/OIDC integration.** Out of scope per parent brainstorm.

---

## 7. Open Questions (resolve at planning time)

1. **Choice of classless framework**: Pico vs Simple.css vs Water.css. All work; Pico is recommended for production-feel; the plan picks one.
2. **HTMX version pin**: vendor a specific release tag (e.g., 1.x or 2.x). The plan picks the version current at execution time.
3. **Logout redirect target**: `/login` or `/login?logged-out=1` (showing a confirmation message). Minor UX choice.
4. **HTMX `json-enc` extension vs a separate `clipboard-copy.js`**: do we vendor more than one tiny JS file? Up to the plan.
5. **Cookie name**: `zdb_session` is recommended, but the plan picks the literal string.
6. **Cookie expiration**: matches the JWT's `exp` claim (default ~1 hour) or a longer "remember me" mode? Recommend matching JWT's exp for simplicity in v1.
7. **Logged-in user display**: header shows just username, or username+role? Trivial polish.
8. **Layout/styling overrides**: what's the visual hierarchy of the project page? Plan-time design within Pico's defaults.

---

## 8. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| HTMX's PATCH-JSON encoding has a subtle gotcha and triage doesn't work end-to-end | Medium | Medium | Implementation includes an early end-to-end test of one HTMX-driven PATCH; falls back to a small wrapper handler if json-enc proves brittle |
| `AuthMiddleware` cookie-OR-header logic gets the precedence wrong (e.g., honors a stale cookie when a fresh Authorization header is also sent) | Low | Medium | Explicit middleware test for all four header/cookie combinations |
| `SameSite=Strict` breaks legitimate workflows (e.g., user clicks a link from a chat app to `/projects/{id}` and gets redirected to login) | Medium | Low | Document the behavior; offer `SameSite=Lax` as a config knob if needed |
| Pico CSS's defaults clash with security-tool aesthetics (too "consumer-y") | Medium | Low | Project-specific CSS overrides; or swap framework if visceral mismatch |
| The shared `header.tmpl` partial gets too clever (e.g., conditional sections, deep template nesting) | Low | Low | Keep partials flat; one section, one partial |
| CSP violations slip through during template authoring (e.g., an inline `style=` attribute) | Medium | Low | Browser devtools console check during local verification; CSP report-uri is overkill for v1 |
| Creating a "browser-friendly" `/login` POST handler means duplicating validation that the JSON `/api/auth/login` handler does | Medium | Low | New handler delegates to the same `auth.Service.Login` method internally; no duplicated validation logic |

---

## 9. Success Criteria

- The 5 verification commands in §5 produce the expected outcomes.
- An interactive browser session demonstrates: login, project navigation, finding triage with HTMX-driven update, CLI-command copy, logout.
- All existing tests still pass; new tests cover the cookie auth path, the dashboard handler set, and one end-to-end browser flow.
- `golangci-lint` clean; CSP devtools check shows no violations.
- The PR is reviewable in one sitting (~6-8 implementation units; tight scope held).

---

## 10. Suggested Next Step

This brainstorm is ready for `/ce-plan`. The plan should be **Deep** depth, ~6-8 units:

1. Cookie-OR-header support in `AuthMiddleware` + tests.
2. Browser-friendly login/logout handlers (`/login` GET/POST, `/logout` POST) + cookie management.
3. `html/template` parsing infrastructure in `internal/web/server.go` (parse-once at startup; embed via `//go:embed` so the binary doesn't depend on cwd).
4. Vendored static assets (HTMX, Pico CSS, project CSS) + asset references.
5. Layout partial (`base.tmpl`, `header.tmpl`) + dashboard page (`/`).
6. Project detail page (`/projects/{id}`) with sections + CLI command panels.
7. Inline finding triage via HTMX PATCH integration.
8. End-to-end browser flow test.

Estimated PR size: ~25-30 new files, ~1500-2000 lines including templates and tests.
