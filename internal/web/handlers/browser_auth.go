package handlers

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/perplext/zerodaybuddy/pkg/validation"
)

// sessionCookieMaxAge is the lifetime of the browser session cookie in
// seconds. Matches the auth.Service access-token TTL (15 minutes — see
// internal/auth/tokens.go). Server-side validation is authoritative; the
// cookie expiring at the same time as the JWT means the user is redirected
// to /login at most every 15min either way. A "remember me" longer-lived
// cookie is deferred per T2-3 plan.
const sessionCookieMaxAge = 15 * 60 // 900 seconds

// BrowserAuthHandler serves the cookie-driven browser auth flow:
//
//   - GET  /login   — render the login form
//   - POST /login   — set cookie, 303 → /
//   - POST /logout  — clear cookie, revoke session, 303 → /login?logged-out=1
//
// Distinct from the JSON AuthHandler family (auth.go); the JSON endpoints
// remain unchanged for API clients. Both share auth.Service.
type BrowserAuthHandler struct {
	authSvc      *auth.Service
	tmpl         *template.Template
	logger       *utils.Logger
	enableTLS    bool // server's own TLS config — direct-TLS deployments
	proxyEnabled bool // when true, X-Forwarded-Proto is trusted as a TLS signal
}

// NewBrowserAuthHandler constructs a BrowserAuthHandler. tmpl must include
// "login.tmpl".
//
// Note: Cookies are now always issued with Secure=true to enforce HTTPS-only
// transport. The enableTLS and proxyEnabled parameters are retained for
// backward compatibility but no longer affect the Secure flag.
func NewBrowserAuthHandler(authSvc *auth.Service, tmpl *template.Template, logger *utils.Logger, enableTLS, proxyEnabled bool) *BrowserAuthHandler {
	return &BrowserAuthHandler{
		authSvc:      authSvc,
		tmpl:         tmpl,
		logger:       logger,
		enableTLS:    enableTLS,
		proxyEnabled: proxyEnabled,
	}
}

// RegisterRoutes wires the three browser-auth routes onto mux. publicChain
// is the standard public middleware stack; the handlers themselves manage
// auth-state checks (they don't sit behind AuthMiddleware because login is
// public and logout works with-or-without a valid cookie).
func (h *BrowserAuthHandler) RegisterRoutes(mux *http.ServeMux, publicChain []func(http.Handler) http.Handler) {
	mux.Handle("GET /login", middleware.Chain(http.HandlerFunc(h.loginForm), publicChain...))
	mux.Handle("POST /login", middleware.Chain(http.HandlerFunc(h.login), publicChain...))
	mux.Handle("POST /logout", middleware.Chain(http.HandlerFunc(h.logout), publicChain...))
}

// loginPageData is the shape passed to login.tmpl.
type loginPageData struct {
	User      *auth.User
	LoggedOut bool
	Error     string
}

func (h *BrowserAuthHandler) loginForm(w http.ResponseWriter, r *http.Request) {
	// If the user is already authenticated (OptionalAuth populated context),
	// skip the form and bounce to the dashboard. /login is for unauthed only.
	if user := middleware.GetUserFromContext(r.Context()); user != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := loginPageData{
		LoggedOut: r.URL.Query().Get("logged-out") == "1",
	}
	h.renderLogin(w, http.StatusOK, data)
}

func (h *BrowserAuthHandler) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderLogin(w, http.StatusBadRequest, loginPageData{Error: "Could not parse form data"})
		return
	}

	username := validation.SanitizeString(r.PostForm.Get("username"))
	password := r.PostForm.Get("password") // never sanitize a password — reduces entropy
	if username == "" || password == "" {
		h.renderLogin(w, http.StatusUnauthorized, loginPageData{Error: "Invalid username or password"})
		return
	}

	resp, err := h.authSvc.Login(r.Context(), &auth.LoginRequest{
		Username: username,
		Password: password,
	}, clientIP(r), r.Header.Get("User-Agent"))
	if err != nil {
		// Don't leak which credential was wrong (matches the JSON handler).
		h.logger.Debug("Browser login failed for %q: %v", username, err)
		h.renderLogin(w, http.StatusUnauthorized, loginPageData{Error: "Invalid username or password"})
		return
	}

	http.SetCookie(w, h.makeSessionCookie(resp.Token))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *BrowserAuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	// Best-effort revoke: if a cookie is present and contains a valid-looking
	// token, ask auth.Service to invalidate the session. Errors are logged
	// but don't block the cookie clearing — logout should always succeed
	// from the client's perspective.
	if cookie, err := r.Cookie(middleware.SessionCookieName); err == nil && cookie.Value != "" {
		if logoutErr := h.authSvc.Logout(r.Context(), cookie.Value); logoutErr != nil {
			h.logger.Debug("auth.Service.Logout failed for browser session: %v", logoutErr)
		}
	}

	http.SetCookie(w, h.makeClearedCookie())
	http.Redirect(w, r, "/login?logged-out=1", http.StatusSeeOther)
}

// makeSessionCookie builds the Set-Cookie value carrying the JWT.
// Session cookies are always marked Secure to enforce HTTPS-only transport.
func (h *BrowserAuthHandler) makeSessionCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     middleware.SessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   sessionCookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// makeClearedCookie builds a Set-Cookie that immediately expires the session.
// Browsers honor MaxAge=-1 (or 0 with Expires=epoch) by deleting the cookie.
// The Secure flag must match the original cookie's flag — browsers won't
// overwrite a Secure cookie with a non-Secure clearing cookie.
// makeClearedCookie builds a Set-Cookie that immediately expires the session.
// Cleared cookies are always marked Secure to enforce HTTPS-only transport.
func (h *BrowserAuthHandler) makeClearedCookie() *http.Cookie {
	return &http.Cookie{
		Name:     middleware.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// renderLogin writes the login template with the given data. Errors during
// render are logged and surface as plain-text 500 — fall back rather than
// leave a half-written response.
func (h *BrowserAuthHandler) renderLogin(w http.ResponseWriter, status int, data loginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Render to a buffer first so we don't write a partial response if the
	// template execution fails.
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, "login.tmpl", data); err != nil {
		h.logger.Error("Failed to render login template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	if _, err := w.Write(buf.Bytes()); err != nil {
		h.logger.Error("Failed to write login response: %v", err)
	}
}

// clientIP extracts the client IP from the request. Honors X-Forwarded-For
// only when the request originated from a proxy we trust — this handler
// doesn't have access to that config, so for now use RemoteAddr as the
// authoritative source. T2-3 plan defers proxy-aware IP extraction; revisit
// when ProxyEnabled config wiring matters.
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

