# Vendored Static Assets

Third-party files in this directory are checked in verbatim from upstream
releases. They're served via `//go:embed` so the binary doesn't depend on
any external CDN at runtime — required by the strict `default-src 'self'`
Content-Security-Policy.

## Inventory

| File | Source | Version | License | Notes |
|---|---|---|---|---|
| `js/htmx.min.js` | https://unpkg.com/htmx.org@2.0.9/dist/htmx.min.js | 2.0.9 | BSD-2-Clause | Stay on 2.x — v4 is in beta, v1.x is in maintenance only |
| `js/json-enc.js` | https://unpkg.com/htmx-ext-json-enc@2.0.2/json-enc.js | 2.0.2 | BSD-2-Clause | HTMX extension that encodes form fields as JSON for hx-patch/post |
| `css/pico.min.css` | https://unpkg.com/@picocss/pico@2.1.1/css/pico.min.css | 2.1.1 | MIT | Classless CSS framework |

## Update procedure

1. Check the upstream release for breaking changes (especially HTMX 2.x → 3.x → ...).
2. Download the new version into `/tmp` first to verify checksums if upstream provides them.
3. `mv /tmp/<file> internal/web/embedded/static/<path>/<file>`.
4. Update the version + URL in this table.
5. Run `go test ./internal/web/...` and start the server locally to confirm pages render.
6. Eyeball the rendered dashboard for visual regressions before committing.

## Project-authored files (not vendored, just listed for completeness)

| File | Purpose |
|---|---|
| `css/zdb.css` | Project-specific overrides on top of Pico (~80 lines max) |
| `js/zdb.js` | HTMX after-request flash + copy-to-clipboard handlers |
