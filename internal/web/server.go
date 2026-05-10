package web

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/handlers"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// Default request-handling limits. WebServerConfig doesn't currently expose
// these as tunables; centralised here so the operating posture is greppable.
const (
	defaultMaxBodyBytes int64   = 1 << 20 // 1 MiB — enough for auth payloads, generous headroom
	defaultRateLimitRPS float64 = 10      // tokens per second per IP
	defaultRateLimitBurst int   = 30      // burst capacity per IP
)

// Dependencies bundles the application services and resources the web server
// needs to wire HTTP routes.
//
// AuthService may be nil — when nil, NewServer skips auth-route registration
// and logs a warning at startup. This makes it possible to construct minimal
// servers in tests without spinning up the full auth stack.
//
// Store is the application's data layer. When nil, the data-model routes
// (/api/projects, /api/hosts, etc.) are not registered. Tests construct
// minimal servers with Dependencies{} to exercise auth-only or static-only
// scenarios.
//
// Static assets and templates are bundled into the binary via //go:embed
// (see embedded.go) — there is no StaticDir field. The binary is location-
// independent and serves /static/* from the embedded FS regardless of cwd.
type Dependencies struct {
	AuthService *auth.Service
	Store       storage.Store
}

// Server represents the web server for the ZeroDayBuddy UI
type Server struct {
	config      config.WebServerConfig
	deps        Dependencies
	logger      *utils.Logger
	rateLimiter *middleware.RateLimiter
	tmpl        *template.Template // parsed once at construction; nil if no templates exist (acceptable for tests)
	server      *http.Server
}

// NewServer creates a new web server with the given dependencies. Parses
// templates from EmbeddedFS once at construction. Panics if templates exist
// but fail to parse — startup failure is the right outcome for templates
// that ship with the binary, and surfaces clearly in `zerodaybuddy serve`.
func NewServer(cfg config.WebServerConfig, deps Dependencies, logger *utils.Logger) *Server {
	rl := middleware.NewRateLimiter(middleware.RateLimitConfig{
		RequestsPerSecond: defaultRateLimitRPS,
		Burst:             defaultRateLimitBurst,
	}, logger)

	tmpl, err := parseTemplates(EmbeddedFS)
	if err != nil {
		// Templates ship with the binary — a parse error is a programmer
		// error caught at startup, not a runtime condition to recover from.
		panic("web: failed to parse embedded templates: " + err.Error())
	}

	return &Server{
		config:      cfg,
		deps:        deps,
		logger:      logger,
		rateLimiter: rl,
		tmpl:        tmpl,
	}
}

// publicChain returns the per-route middleware stack.
// Order: RecoverPanic (outermost) -> SecurityHeaders -> MaxBodySize -> RateLimit.
// CORS is intentionally NOT in this chain — it's applied at the mux level in
// buildRouter so OPTIONS preflight requests are handled before method-pattern
// dispatch. See the CORS wrapping in buildRouter for details.
func (s *Server) publicChain() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		middleware.RecoverPanic(s.logger),
		middleware.SecurityHeaders(s.logger),
		middleware.MaxBodySize(defaultMaxBodyBytes, s.logger),
		s.rateLimiter.Middleware(),
	}
}

// authedChain extends publicChain with AuthMiddleware. Caller must ensure
// s.deps.AuthService is non-nil before invoking this.
func (s *Server) authedChain() []func(http.Handler) http.Handler {
	return append(s.publicChain(),
		middleware.AuthMiddleware(s.deps.AuthService, s.logger),
	)
}

// buildRouter assembles the http.Handler that routes all server requests.
// Routes registered:
//   - GET  /health                      (public)
//   - GET  /                            (public, welcome stub; replaced in U4)
//   - POST /api/auth/login              (public, only when AuthService set)
//   - POST /api/auth/register           (public, only when AuthService set)
//   - POST /api/auth/refresh            (public, only when AuthService set)
//   - POST /api/auth/logout             (authed, only when AuthService set)
//   - GET  /api/auth/profile            (authed, only when AuthService set)
//   - POST /api/auth/change-password    (authed, only when AuthService set)
func (s *Server) buildRouter() http.Handler {
	mux := http.NewServeMux()

	// Health endpoint — public, lightweight. Routed through the public chain
	// so the rate limiter sees probe traffic and security headers apply.
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			s.logger.Error("Failed to write health check response: %v", err)
		}
	})
	mux.Handle("GET /health", middleware.Chain(healthHandler, s.publicChain()...))

	// Index — registered later by DashboardHandler when Store + AuthService +
	// dashboard template are all available. Falls back to a minimal API-doc
	// stub when any prerequisite is missing (test servers, no-storage mode).
	// Registered with the {$} wildcard so it matches exactly "/" only;
	// without {$}, "/" would be a catch-all that masks ServeMux's 405 and
	// 404 semantics for /api/* and /static/* routes.
	dashboardWired := false
	if s.deps.Store != nil && s.deps.AuthService != nil && s.tmpl != nil && s.tmpl.Lookup("dashboard.tmpl") != nil {
		// Dashboard + project-detail browser pages go through OptionalAuth
		// (cookie-aware). The handlers themselves 303 unauth'd visitors to
		// /login — AuthMiddleware would 401 with JSON, which is awful UX
		// for a browser navigating to a bookmarked page.
		dashboardChain := append(s.publicChain(), middleware.OptionalAuth(s.deps.AuthService, s.logger))
		handlers.NewDashboardHandler(s.deps.Store, s.tmpl, s.logger).RegisterRoutes(mux, dashboardChain)
		if s.tmpl.Lookup("project_detail.tmpl") != nil {
			handlers.NewProjectDetailHandler(s.deps.Store, s.tmpl, s.logger).RegisterRoutes(mux, dashboardChain)
		}
		dashboardWired = true
	}
	if !dashboardWired {
		indexHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(indexHTML)); err != nil {
				s.logger.Error("Failed to write index response: %v", err)
			}
		})
		mux.Handle("GET /{$}", middleware.Chain(indexHandler, s.publicChain()...))
	}

	// Static file server — backed by the embedded FS. Always registered (the
	// embedded FS is part of the binary, not a configurable filesystem path).
	// noListFS suppresses directory indexes; http.FileServer's built-in path
	// cleaning handles traversal.
	staticSubFS, err := fs.Sub(EmbeddedFS, "embedded/static")
	if err != nil {
		// EmbeddedFS structure is checked at compile time via //go:embed;
		// a Sub error here would indicate a code bug, not runtime input.
		s.logger.Error("Failed to derive embedded static sub-FS: %v", err)
	} else {
		staticServer := http.FileServer(noListFS{fs: http.FS(staticSubFS)})
		// Static gets a thinner middleware chain — no rate limit, no body size.
		// Reads are cheap and bodyless. (CORS is applied at the mux level below.)
		staticChain := []func(http.Handler) http.Handler{
			middleware.RecoverPanic(s.logger),
			middleware.SecurityHeaders(s.logger),
		}
		mux.Handle("GET /static/", middleware.Chain(http.StripPrefix("/static/", staticServer), staticChain...))
	}

	// Browser auth routes (T2-3) — register when both AuthService and the
	// login template are available. Public chain only; the handlers check
	// auth state internally via OptionalAuth-populated context (U4 wires
	// the optional-auth chain on the dashboard routes).
	if s.deps.AuthService != nil && s.tmpl != nil && s.tmpl.Lookup("login.tmpl") != nil {
		browserAuth := handlers.NewBrowserAuthHandler(s.deps.AuthService, s.tmpl, s.logger, s.config.EnableTLS)
		// Browser routes need OptionalAuth so the GET /login handler can
		// detect "already logged in" and 303 to /. Wrap the handler chain
		// with OptionalAuth in addition to publicChain.
		browserChain := append(s.publicChain(), middleware.OptionalAuth(s.deps.AuthService, s.logger))
		browserAuth.RegisterRoutes(mux, browserChain)
	}

	// Auth routes — registered only when AuthService is wired. Tests construct
	// minimal servers with Dependencies{} for non-auth scenarios.
	if s.deps.AuthService != nil {
		authHandler := handlers.NewAuthHandler(s.deps.AuthService, s.logger)
		authHandler.SetProxyEnabled(s.config.ProxyEnabled)

		publicAuth := s.publicChain()
		authedAuth := s.authedChain()

		mux.Handle("POST /api/auth/login", middleware.Chain(http.HandlerFunc(authHandler.Login), publicAuth...))
		mux.Handle("POST /api/auth/register", middleware.Chain(http.HandlerFunc(authHandler.Register), publicAuth...))
		mux.Handle("POST /api/auth/refresh", middleware.Chain(http.HandlerFunc(authHandler.RefreshToken), publicAuth...))

		mux.Handle("POST /api/auth/logout", middleware.Chain(http.HandlerFunc(authHandler.Logout), authedAuth...))
		mux.Handle("GET /api/auth/profile", middleware.Chain(http.HandlerFunc(authHandler.Profile), authedAuth...))
		mux.Handle("POST /api/auth/change-password", middleware.Chain(http.HandlerFunc(authHandler.ChangePassword), authedAuth...))
	} else {
		s.logger.Warn("AuthService is nil; skipping /api/auth/* route registration")
	}

	// Data-model routes — registered only when both Store and AuthService
	// are wired. The handlers themselves don't gate on auth; the authedChain
	// does. Without an AuthService, AuthMiddleware would 401 every request,
	// so the routes would be reachable but useless — skip them too.
	if s.deps.Store != nil && s.deps.AuthService != nil {
		authedChain := s.authedChain()

		handlers.NewProjectsHandler(s.deps.Store, s.logger).RegisterRoutes(mux, authedChain)
		handlers.NewHostsHandler(s.deps.Store, s.logger).RegisterRoutes(mux, authedChain)
		handlers.NewEndpointsHandler(s.deps.Store, s.logger).RegisterRoutes(mux, authedChain)
		handlers.NewFindingsHandler(s.deps.Store, s.logger).RegisterRoutes(mux, authedChain)
		handlers.NewTasksHandler(s.deps.Store, s.logger).RegisterRoutes(mux, authedChain)
	} else if s.deps.Store == nil {
		s.logger.Warn("Store is nil; skipping data-model route registration")
	}

	return s.applyCORS(mux)
}

// applyCORS wraps the entire mux with CORS middleware when AllowedOrigins is
// non-empty. This must be applied at the mux level (not in per-route chains)
// because Go 1.22 ServeMux's method-prefixed patterns ("POST /api/auth/login",
// etc.) do not match OPTIONS preflight requests — those would 405 at the
// routing layer before any per-route middleware ran. Wrapping the mux makes
// CORS run for every request, including OPTIONS preflight, regardless of
// whether the path+method combination has a registered handler.
//
// The CORS middleware itself short-circuits OPTIONS with 204 + headers when
// the Origin is in the allow-list, and otherwise delegates to the wrapped
// handler unchanged.
func (s *Server) applyCORS(handler http.Handler) http.Handler {
	if len(s.config.AllowedOrigins) == 0 {
		return handler
	}
	return middleware.CORS(s.config.AllowedOrigins, s.logger)(handler)
}

// Start starts the web server
func (s *Server) Start(ctx context.Context, host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	s.logger.Info("Starting web server on %s", addr)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.buildRouter(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Warn if binding to non-localhost without TLS
	if !s.config.EnableTLS && host != "localhost" && host != "127.0.0.1" && host != "::1" {
		s.logger.Warn("Web server binding to %s without TLS — traffic is unencrypted", host)
	}

	// Start server in a goroutine
	go func() {
		var err error
		if s.config.EnableTLS {
			s.logger.Info("TLS enabled with cert=%s key=%s", s.config.TLSCertFile, s.config.TLSKeyFile)
			err = s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			err = s.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("Failed to start web server: %v", err)
		}
	}()

	s.logger.Info("Web server started on %s", addr)
	return nil
}

// Shutdown gracefully shuts down the web server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down web server")
	return s.server.Shutdown(ctx)
}
