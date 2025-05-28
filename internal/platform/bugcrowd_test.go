package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/ratelimit"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBugcrowd(t *testing.T) {
	cfg := config.BugcrowdConfig{
		APIUrl:      "https://bugcrowd.com",
		CookieValue: "test-cookie",
	}
	logger := utils.NewLogger("", false)

	platform := NewBugcrowd(cfg, logger)

	assert.NotNil(t, platform)
	bc, ok := platform.(*Bugcrowd)
	require.True(t, ok)
	assert.Equal(t, &cfg, bc.config)
	assert.NotNil(t, bc.client)
	assert.Equal(t, logger, bc.logger)
}

func TestNewBugcrowdWithRateLimiter(t *testing.T) {
	cfg := config.BugcrowdConfig{
		APIUrl:      "https://bugcrowd.com",
		CookieValue: "test-cookie",
	}
	logger := utils.NewLogger("", false)
	rateLimiter := ratelimit.New(ratelimit.DefaultConfig())

	platform := NewBugcrowdWithRateLimiter(cfg, logger, rateLimiter)

	assert.NotNil(t, platform)
	bc, ok := platform.(*Bugcrowd)
	require.True(t, ok)
	assert.Equal(t, &cfg, bc.config)
	assert.NotNil(t, bc.client)
	assert.Equal(t, logger, bc.logger)
}

func TestBugcrowd_GetName(t *testing.T) {
	bc := &Bugcrowd{}
	assert.Equal(t, "bugcrowd", bc.GetName())
}

func TestBugcrowd_ListPrograms(t *testing.T) {
	tests := []struct {
		name           string
		config         config.BugcrowdConfig
		mockResponse   interface{}
		mockStatusCode int
		expectedError  string
		expectedCount  int
		checkPrograms  func(t *testing.T, programs []models.Program)
	}{
		{
			name: "successful list programs",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockResponse: map[string]interface{}{
				"programs": []map[string]interface{}{
					{
						"id":          "123",
						"name":        "Test Program",
						"code":        "test-program",
						"description": "Test program description",
						"url":         "/test-program",
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
						"logo_attachment": map[string]interface{}{
							"url": "/logos/test-program.png",
						},
					},
					{
						"id":          "456",
						"name":        "Another Program",
						"code":        "another-program",
						"description": "Another program description",
						"url":         "/another-program",
						"created_at":  "2023-02-01T00:00:00Z",
						"updated_at":  "2023-02-02T00:00:00Z",
						"logo_attachment": map[string]interface{}{
							"url": "/logos/another-program.png",
						},
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectedCount:  2,
			checkPrograms: func(t *testing.T, programs []models.Program) {
				assert.Equal(t, "123", programs[0].ID)
				assert.Equal(t, "Test Program", programs[0].Name)
				assert.Equal(t, "test-program", programs[0].Handle)
				assert.Equal(t, "Test program description", programs[0].Description)
				assert.Contains(t, programs[0].URL, "/test-program")
				assert.Equal(t, "bugcrowd", programs[0].Platform)

				assert.Equal(t, "456", programs[1].ID)
				assert.Equal(t, "Another Program", programs[1].Name)
				assert.Equal(t, "another-program", programs[1].Handle)
			},
		},
		{
			name: "missing cookie",
			config: config.BugcrowdConfig{
				CookieValue: "",
			},
			expectedError: "Bugcrowd cookie not configured",
		},
		{
			name: "unauthorized response",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockStatusCode: http.StatusUnauthorized,
			expectedError:  "unexpected status code: 401",
		},
		{
			name: "invalid response format",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockResponse:   "invalid json",
			mockStatusCode: http.StatusOK,
			expectedError:  "failed to parse response",
		},
		{
			name: "empty response",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockResponse: map[string]interface{}{
				"programs": []map[string]interface{}{},
			},
			mockStatusCode: http.StatusOK,
			expectedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request
				assert.Equal(t, "/programs.json", r.URL.Path)
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Accept"))
				assert.Equal(t, "ZeroDayBuddy/1.0", r.Header.Get("User-Agent"))

				// Check cookie
				if tt.config.CookieValue != "" {
					expectedCookie := fmt.Sprintf("_crowdcontrol_session=%s", tt.config.CookieValue)
					assert.Equal(t, expectedCookie, r.Header.Get("Cookie"))
				}

				// Send response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					if str, ok := tt.mockResponse.(string); ok {
						w.Write([]byte(str))
					} else {
						json.NewEncoder(w).Encode(tt.mockResponse)
					}
				}
			}))
			defer server.Close()

			// Configure client
			tt.config.APIUrl = server.URL
			logger := utils.NewLogger("", false)
			bc := NewBugcrowd(tt.config, logger)

			// Execute
			ctx := context.Background()
			programs, err := bc.ListPrograms(ctx)

			// Assert
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Len(t, programs, tt.expectedCount)
				if tt.checkPrograms != nil {
					tt.checkPrograms(t, programs)
				}
			}
		})
	}
}

func TestBugcrowd_GetProgram(t *testing.T) {
	tests := []struct {
		name               string
		handle             string
		config             config.BugcrowdConfig
		mockProgramResp    interface{}
		mockProgramStatus  int
		mockTargetsResp    interface{}
		mockTargetsStatus  int
		expectedError      string
		checkProgram       func(t *testing.T, program *models.Program)
	}{
		{
			name:   "successful get program",
			handle: "test-program",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockProgramResp: map[string]interface{}{
				"program": map[string]interface{}{
					"id":          "123",
					"name":        "Test Program",
					"code":        "test-program",
					"description": "Test program description",
					"url":         "/test-program",
					"created_at":  "2023-01-01T00:00:00Z",
					"updated_at":  "2023-01-02T00:00:00Z",
					"briefing":    "Test briefing information",
				},
			},
			mockProgramStatus: http.StatusOK,
			mockTargetsResp: map[string]interface{}{
				"targets": []map[string]interface{}{
					{
						"id":          "t1",
						"name":        "Main Website",
						"category":    "website",
						"description": "Main website",
						"uri":         "*.example.com",
						"in_scope":    true,
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
					},
				},
			},
			mockTargetsStatus: http.StatusOK,
			checkProgram: func(t *testing.T, program *models.Program) {
				assert.Equal(t, "123", program.ID)
				assert.Equal(t, "Test Program", program.Name)
				assert.Equal(t, "test-program", program.Handle)
				assert.Equal(t, "Test program description", program.Description)
				assert.Contains(t, program.URL, "/test-program")
				assert.Equal(t, "bugcrowd", program.Platform)
				assert.Equal(t, "Test briefing information", program.Policy)
				assert.Len(t, program.Scope.InScope, 1)
				assert.Equal(t, "*.example.com", program.Scope.InScope[0].Value)
				assert.Equal(t, models.AssetTypeDomain, program.Scope.InScope[0].Type)
			},
		},
		{
			name:   "missing cookie",
			handle: "test-program",
			config: config.BugcrowdConfig{
				CookieValue: "",
			},
			expectedError: "Bugcrowd cookie not configured",
		},
		{
			name:   "program not found",
			handle: "nonexistent",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockProgramStatus: http.StatusNotFound,
			expectedError:     "unexpected status code: 404",
		},
		{
			name:   "scope fetch fails",
			handle: "test-program",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockProgramResp: map[string]interface{}{
				"program": map[string]interface{}{
					"id":          "123",
					"name":        "Test Program",
					"code":        "test-program",
					"description": "Test program description",
					"url":         "/test-program",
					"created_at":  "2023-01-01T00:00:00Z",
					"updated_at":  "2023-01-02T00:00:00Z",
				},
			},
			mockProgramStatus: http.StatusOK,
			mockTargetsStatus: http.StatusInternalServerError,
			expectedError:     "failed to fetch scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Route based on path
				switch r.URL.Path {
				case fmt.Sprintf("/%s.json", tt.handle):
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.mockProgramStatus)
					if tt.mockProgramResp != nil {
						json.NewEncoder(w).Encode(tt.mockProgramResp)
					}
				case fmt.Sprintf("/%s/targets.json", tt.handle):
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.mockTargetsStatus)
					if tt.mockTargetsResp != nil {
						json.NewEncoder(w).Encode(tt.mockTargetsResp)
					}
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Configure client
			tt.config.APIUrl = server.URL
			logger := utils.NewLogger("", false)
			bc := NewBugcrowd(tt.config, logger)

			// Execute
			ctx := context.Background()
			program, err := bc.GetProgram(ctx, tt.handle)

			// Assert
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, program)
				if tt.checkProgram != nil {
					tt.checkProgram(t, program)
				}
			}
		})
	}
}

func TestBugcrowd_FetchScope(t *testing.T) {
	tests := []struct {
		name           string
		handle         string
		config         config.BugcrowdConfig
		mockResponse   interface{}
		mockStatusCode int
		expectedError  string
		checkScope     func(t *testing.T, scope *models.Scope)
	}{
		{
			name:   "successful fetch scope with various asset types",
			handle: "test-program",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockResponse: map[string]interface{}{
				"targets": []map[string]interface{}{
					{
						"id":          "t1",
						"name":        "Main Website",
						"category":    "website",
						"description": "Main website and all subdomains",
						"uri":         "*.example.com",
						"in_scope":    true,
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
					},
					{
						"id":          "t2",
						"name":        "API Endpoint",
						"category":    "api",
						"description": "REST API",
						"uri":         "https://api.example.com",
						"in_scope":    true,
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
					},
					{
						"id":          "t3",
						"name":        "Mobile App",
						"category":    "mobile",
						"description": "Android application",
						"uri":         "com.example.app",
						"in_scope":    true,
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
					},
					{
						"id":          "t4",
						"name":        "Desktop App",
						"category":    "binary",
						"description": "Windows desktop application",
						"uri":         "example.exe",
						"in_scope":    true,
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
					},
					{
						"id":          "t5",
						"name":        "Internal Network",
						"category":    "ip_range",
						"description": "Internal IP range",
						"uri":         "192.168.0.0/16",
						"in_scope":    false,
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
					},
					{
						"id":          "t6",
						"name":        "Other Asset",
						"category":    "other",
						"description": "Miscellaneous asset",
						"uri":         "other-asset",
						"in_scope":    true,
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			checkScope: func(t *testing.T, scope *models.Scope) {
				assert.Len(t, scope.InScope, 5)
				assert.Len(t, scope.OutOfScope, 1)

				// Check in-scope assets
				assert.Equal(t, "*.example.com", scope.InScope[0].Value)
				assert.Equal(t, models.AssetTypeDomain, scope.InScope[0].Type)
				assert.Equal(t, "Main website and all subdomains", scope.InScope[0].Description)

				assert.Equal(t, "https://api.example.com", scope.InScope[1].Value)
				assert.Equal(t, models.AssetTypeURL, scope.InScope[1].Type)

				assert.Equal(t, "com.example.app", scope.InScope[2].Value)
				assert.Equal(t, models.AssetTypeMobile, scope.InScope[2].Type)

				assert.Equal(t, "example.exe", scope.InScope[3].Value)
				assert.Equal(t, models.AssetTypeBinary, scope.InScope[3].Type)

				assert.Equal(t, "other-asset", scope.InScope[4].Value)
				assert.Equal(t, models.AssetTypeOther, scope.InScope[4].Type)

				// Check out-of-scope assets
				assert.Equal(t, "192.168.0.0/16", scope.OutOfScope[0].Value)
				assert.Equal(t, models.AssetTypeIP, scope.OutOfScope[0].Type)
			},
		},
		{
			name:   "missing cookie",
			handle: "test-program",
			config: config.BugcrowdConfig{
				CookieValue: "",
			},
			expectedError: "Bugcrowd cookie not configured",
		},
		{
			name:   "unauthorized response",
			handle: "test-program",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockStatusCode: http.StatusUnauthorized,
			expectedError:  "unexpected status code: 401",
		},
		{
			name:   "empty scope",
			handle: "test-program",
			config: config.BugcrowdConfig{
				CookieValue: "test-cookie",
			},
			mockResponse: map[string]interface{}{
				"targets": []map[string]interface{}{},
			},
			mockStatusCode: http.StatusOK,
			checkScope: func(t *testing.T, scope *models.Scope) {
				assert.Empty(t, scope.InScope)
				assert.Empty(t, scope.OutOfScope)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request
				assert.Equal(t, fmt.Sprintf("/%s/targets.json", tt.handle), r.URL.Path)
				assert.Equal(t, "GET", r.Method)

				// Send response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			// Configure client
			tt.config.APIUrl = server.URL
			logger := utils.NewLogger("", false)
			bc := NewBugcrowd(tt.config, logger)

			// Execute
			ctx := context.Background()
			scope, err := bc.FetchScope(ctx, tt.handle)

			// Assert
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, scope)
				if tt.checkScope != nil {
					tt.checkScope(t, scope)
				}
			}
		})
	}
}

func TestBugcrowd_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.BugcrowdConfig{
		APIUrl:      server.URL,
		CookieValue: "test-cookie",
	}
	logger := utils.NewLogger("", false)
	bc := NewBugcrowd(cfg, logger)

	// Create a context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// All methods should fail with context cancelled
	_, err := bc.ListPrograms(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")

	_, err = bc.GetProgram(ctx, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")

	_, err = bc.FetchScope(ctx, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestBugcrowd_AssetTypeMapping(t *testing.T) {
	tests := []struct {
		category     string
		uri          string
		expectedType models.AssetType
	}{
		{"website", "example.com", models.AssetTypeDomain},
		{"website", "*.example.com", models.AssetTypeDomain},
		{"web", "sub.example.com", models.AssetTypeDomain},
		{"website", "https://example.com", models.AssetTypeURL},
		{"api", "https://api.example.com", models.AssetTypeURL},
		{"web", "http://app.example.com", models.AssetTypeURL},
		{"mobile", "com.example.app", models.AssetTypeMobile},
		{"binary", "example.exe", models.AssetTypeBinary},
		{"ip", "192.168.1.1", models.AssetTypeIP},
		{"ip_range", "192.168.0.0/24", models.AssetTypeIP},
		{"network", "10.0.0.0/8", models.AssetTypeIP},
		{"other", "something", models.AssetTypeOther},
		{"unknown", "test", models.AssetTypeOther},
		{"", "test", models.AssetTypeOther},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.category, tt.uri), func(t *testing.T) {
			// Create a minimal server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"targets": []map[string]interface{}{
						{
							"id":          "t1",
							"name":        "Test Target",
							"category":    tt.category,
							"description": "Test",
							"uri":         tt.uri,
							"in_scope":    true,
							"created_at":  "2023-01-01T00:00:00Z",
							"updated_at":  "2023-01-02T00:00:00Z",
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			cfg := config.BugcrowdConfig{
				APIUrl:      server.URL,
				CookieValue: "test-cookie",
			}
			logger := utils.NewLogger("", false)
			bc := NewBugcrowd(cfg, logger)

			ctx := context.Background()
			scope, err := bc.FetchScope(ctx, "test")
			require.NoError(t, err)
			require.Len(t, scope.InScope, 1)
			assert.Equal(t, tt.expectedType, scope.InScope[0].Type)
		})
	}
}

func TestBugcrowd_URLConstruction(t *testing.T) {
	tests := []struct {
		name        string
		apiUrl      string
		handle      string
		expectedURL string
	}{
		{
			name:        "standard URL",
			apiUrl:      "https://bugcrowd.com",
			handle:      "test-program",
			expectedURL: "https://bugcrowd.com/test-program",
		},
		{
			name:        "URL with trailing slash",
			apiUrl:      "https://bugcrowd.com/",
			handle:      "test-program",
			expectedURL: "https://bugcrowd.com//test-program",
		},
		{
			name:        "handle with special characters",
			apiUrl:      "https://bugcrowd.com",
			handle:      "test-program-123",
			expectedURL: "https://bugcrowd.com/test-program-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"program": map[string]interface{}{
						"id":         "123",
						"name":       "Test Program",
						"code":       tt.handle,
						"created_at": "2023-01-01T00:00:00Z",
						"updated_at": "2023-01-02T00:00:00Z",
					},
				}
				if r.URL.Path == fmt.Sprintf("/%s/targets.json", tt.handle) {
					response = map[string]interface{}{
						"targets": []map[string]interface{}{},
					}
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			cfg := config.BugcrowdConfig{
				APIUrl:      tt.apiUrl,
				CookieValue: "test-cookie",
			}

			// Override APIUrl for testing
			serverCfg := cfg
			serverCfg.APIUrl = server.URL
			logger := utils.NewLogger("", false)
			bc := NewBugcrowd(serverCfg, logger)

			ctx := context.Background()
			program, err := bc.GetProgram(ctx, tt.handle)
			require.NoError(t, err)
			
			// Check that the URL is constructed properly by replacing server URL with expected base
			actualURL := program.URL
			actualURL = strings.Replace(actualURL, server.URL, tt.apiUrl, 1)
			assert.Equal(t, tt.expectedURL, actualURL)
		})
	}
}