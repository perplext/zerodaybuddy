package web

import (
	"context"
	"fmt"
	"net/http"
	"time"
	
	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// Server represents the web server for the ZeroDayBuddy UI
type Server struct {
	config   config.WebServerConfig
	logger   *utils.Logger
	services map[string]interface{}
	server   *http.Server
}

// NewServer creates a new web server
func NewServer(cfg config.WebServerConfig, logger *utils.Logger) *Server {
	return &Server{
		config:   cfg,
		logger:   logger,
		services: make(map[string]interface{}),
	}
}

// RegisterService registers a service with the web server
func (s *Server) RegisterService(name string, service interface{}) {
	s.services[name] = service
}

// Start starts the web server
func (s *Server) Start(ctx context.Context, host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	s.logger.Info("Starting web server on %s", addr)
	
	// Basic server setup
	mux := http.NewServeMux()
	
	// Add a simple health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			// Log error but don't fail the handler
			s.logger.Error("Failed to write health check response: %v", err)
		}
	})
	
	// Add a basic welcome page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("<html><body><h1>ZeroDayBuddy</h1><p>Welcome to ZeroDayBuddy - the bug bounty management tool.</p></body></html>")); err != nil {
			// Log error but don't fail the handler
			s.logger.Error("Failed to write welcome page response: %v", err)
		}
	})
	
	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
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
