package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/ratelimit"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHackerOne(t *testing.T) {
	cfg := config.HackerOneConfig{
		APIUrl:   "https://api.hackerone.com",
		Username: "testuser",
		APIKey:   "testkey",
	}
	logger := utils.NewLogger("", false)

	platform := NewHackerOne(cfg, logger)

	assert.NotNil(t, platform)
	h1, ok := platform.(*HackerOne)
	require.True(t, ok)
	assert.Equal(t, &cfg, h1.config)
	assert.NotNil(t, h1.client)
	assert.Equal(t, logger, h1.logger)
}

func TestNewHackerOneWithRateLimiter(t *testing.T) {
	cfg := config.HackerOneConfig{
		APIUrl:   "https://api.hackerone.com",
		Username: "testuser",
		APIKey:   "testkey",
	}
	logger := utils.NewLogger("", false)
	rateLimiter := ratelimit.New(ratelimit.DefaultConfig())

	platform := NewHackerOneWithRateLimiter(cfg, logger, rateLimiter)

	assert.NotNil(t, platform)
	h1, ok := platform.(*HackerOne)
	require.True(t, ok)
	assert.Equal(t, &cfg, h1.config)
	assert.NotNil(t, h1.client)
	assert.Equal(t, logger, h1.logger)
}

func TestHackerOne_GetName(t *testing.T) {
	h1 := &HackerOne{}
	assert.Equal(t, "hackerone", h1.GetName())
}

func TestHackerOne_ListPrograms(t *testing.T) {
	tests := []struct {
		name           string
		config         config.HackerOneConfig
		mockResponse   interface{}
		mockStatusCode int
		expectedError  string
		expectedCount  int
		checkPrograms  func(t *testing.T, programs []models.Program)
	}{
		{
			name: "successful list programs",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockResponse: map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id":   "123",
						"type": "program",
						"attributes": map[string]interface{}{
							"handle":      "test-program",
							"name":        "Test Program",
							"description": "Test program description",
							"url":         "https://hackerone.com/test-program",
							"created_at":  "2023-01-01T00:00:00Z",
							"updated_at":  "2023-01-02T00:00:00Z",
						},
					},
					{
						"id":   "456",
						"type": "program",
						"attributes": map[string]interface{}{
							"handle":      "another-program",
							"name":        "Another Program",
							"description": "Another program description",
							"url":         "https://hackerone.com/another-program",
							"created_at":  "2023-02-01T00:00:00Z",
							"updated_at":  "2023-02-02T00:00:00Z",
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
				assert.Equal(t, "https://hackerone.com/test-program", programs[0].URL)
				assert.Equal(t, "hackerone", programs[0].Platform)

				assert.Equal(t, "456", programs[1].ID)
				assert.Equal(t, "Another Program", programs[1].Name)
				assert.Equal(t, "another-program", programs[1].Handle)
			},
		},
		{
			name: "missing credentials",
			config: config.HackerOneConfig{
				Username: "",
				APIKey:   "",
			},
			expectedError: "HackerOne API credentials not configured",
		},
		{
			name: "unauthorized response",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockStatusCode: http.StatusUnauthorized,
			expectedError:  "authentication failed (401)",
		},
		{
			name: "invalid response format",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockResponse:   "invalid json",
			mockStatusCode: http.StatusOK,
			expectedError:  "failed to parse response",
		},
		{
			name: "empty response",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockResponse: map[string]interface{}{
				"data": []map[string]interface{}{},
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
				assert.Equal(t, "/programs", r.URL.Path)
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Accept"))

				// Check authorization
				if tt.config.APIKey != "" {
					expectedAuth := fmt.Sprintf("Basic %s",
						base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", tt.config.APIKey, tt.config.APIKey))))
					assert.Equal(t, expectedAuth, r.Header.Get("Authorization"))
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
			h1 := NewHackerOne(tt.config, logger)

			// Execute
			ctx := context.Background()
			programs, err := h1.ListPrograms(ctx)

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

func TestHackerOne_GetProgram(t *testing.T) {
	tests := []struct {
		name               string
		handle             string
		config             config.HackerOneConfig
		mockProgramResp    interface{}
		mockProgramStatus  int
		mockScopeResp      interface{}
		mockScopeStatus    int
		expectedError      string
		checkProgram       func(t *testing.T, program *models.Program)
	}{
		{
			name:   "successful get program",
			handle: "test-program",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockProgramResp: map[string]interface{}{
				"data": map[string]interface{}{
					"id":   "123",
					"type": "program",
					"attributes": map[string]interface{}{
						"handle":      "test-program",
						"name":        "Test Program",
						"description": "Test program description",
						"url":         "https://hackerone.com/test-program",
						"policy":      "Test policy",
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
					},
				},
			},
			mockProgramStatus: http.StatusOK,
			mockScopeResp: map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"attributes": map[string]interface{}{
							"asset_identifier":        "*.example.com",
							"asset_type":              "domain",
							"instruction":             "All subdomains",
							"eligible_for_submission": []string{"bounty"},
							"attributes":              map[string]interface{}{},
						},
					},
				},
			},
			mockScopeStatus: http.StatusOK,
			checkProgram: func(t *testing.T, program *models.Program) {
				assert.Equal(t, "123", program.ID)
				assert.Equal(t, "Test Program", program.Name)
				assert.Equal(t, "test-program", program.Handle)
				assert.Equal(t, "Test program description", program.Description)
				assert.Equal(t, "https://hackerone.com/test-program", program.URL)
				assert.Equal(t, "hackerone", program.Platform)
				assert.Equal(t, "Test policy", program.Policy)
				assert.Len(t, program.Scope.InScope, 1)
				assert.Equal(t, "*.example.com", program.Scope.InScope[0].Value)
				assert.Equal(t, models.AssetTypeDomain, program.Scope.InScope[0].Type)
			},
		},
		{
			name:   "missing credentials",
			handle: "test-program",
			config: config.HackerOneConfig{
				Username: "",
				APIKey:   "",
			},
			expectedError: "HackerOne API credentials not configured",
		},
		{
			name:   "program not found",
			handle: "nonexistent",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockProgramStatus: http.StatusNotFound,
			expectedError:     "unexpected status code: 404",
		},
		{
			name:   "scope fetch fails",
			handle: "test-program",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockProgramResp: map[string]interface{}{
				"data": map[string]interface{}{
					"id":   "123",
					"type": "program",
					"attributes": map[string]interface{}{
						"handle":      "test-program",
						"name":        "Test Program",
						"description": "Test program description",
						"url":         "https://hackerone.com/test-program",
						"created_at":  "2023-01-01T00:00:00Z",
						"updated_at":  "2023-01-02T00:00:00Z",
					},
				},
			},
			mockProgramStatus: http.StatusOK,
			mockScopeStatus:   http.StatusInternalServerError,
			expectedError:     "failed to fetch scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Route based on path
				switch r.URL.Path {
				case fmt.Sprintf("/programs/%s", tt.handle):
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.mockProgramStatus)
					if tt.mockProgramResp != nil {
						json.NewEncoder(w).Encode(tt.mockProgramResp)
					}
				case fmt.Sprintf("/programs/%s/structured_scopes", tt.handle):
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.mockScopeStatus)
					if tt.mockScopeResp != nil {
						json.NewEncoder(w).Encode(tt.mockScopeResp)
					}
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Configure client
			tt.config.APIUrl = server.URL
			logger := utils.NewLogger("", false)
			h1 := NewHackerOne(tt.config, logger)

			// Execute
			ctx := context.Background()
			program, err := h1.GetProgram(ctx, tt.handle)

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

func TestHackerOne_FetchScope(t *testing.T) {
	tests := []struct {
		name           string
		handle         string
		config         config.HackerOneConfig
		mockResponse   interface{}
		mockStatusCode int
		expectedError  string
		checkScope     func(t *testing.T, scope *models.Scope)
	}{
		{
			name:   "successful fetch scope with various asset types",
			handle: "test-program",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockResponse: map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"attributes": map[string]interface{}{
							"asset_identifier":        "*.example.com",
							"asset_type":              "domain",
							"instruction":             "All subdomains",
							"eligible_for_submission": []string{"bounty"},
							"attributes":              map[string]interface{}{"critical": true},
						},
					},
					{
						"attributes": map[string]interface{}{
							"asset_identifier":        "https://api.example.com",
							"asset_type":              "url",
							"instruction":             "API endpoint",
							"eligible_for_submission": []string{"bounty"},
							"attributes":              map[string]interface{}{},
						},
					},
					{
						"attributes": map[string]interface{}{
							"asset_identifier":        "192.168.1.0/24",
							"asset_type":              "cidr",
							"instruction":             "Internal network",
							"eligible_for_submission": []string{},
							"attributes":              map[string]interface{}{},
						},
					},
					{
						"attributes": map[string]interface{}{
							"asset_identifier":        "com.example.app",
							"asset_type":              "android",
							"instruction":             "Android app",
							"eligible_for_submission": []string{"bounty"},
							"attributes":              map[string]interface{}{},
						},
					},
					{
						"attributes": map[string]interface{}{
							"asset_identifier":        "example.exe",
							"asset_type":              "executable",
							"instruction":             "Windows executable",
							"eligible_for_submission": []string{"bounty"},
							"attributes":              map[string]interface{}{},
						},
					},
				},
			},
			mockStatusCode: http.StatusOK,
			checkScope: func(t *testing.T, scope *models.Scope) {
				assert.Len(t, scope.InScope, 4)
				assert.Len(t, scope.OutOfScope, 1)

				// Check in-scope assets
				assert.Equal(t, "*.example.com", scope.InScope[0].Value)
				assert.Equal(t, models.AssetTypeDomain, scope.InScope[0].Type)
				assert.Equal(t, "All subdomains", scope.InScope[0].Description)
				assert.Equal(t, true, scope.InScope[0].Attributes["critical"])

				assert.Equal(t, "https://api.example.com", scope.InScope[1].Value)
				assert.Equal(t, models.AssetTypeURL, scope.InScope[1].Type)

				assert.Equal(t, "com.example.app", scope.InScope[2].Value)
				assert.Equal(t, models.AssetTypeMobile, scope.InScope[2].Type)

				assert.Equal(t, "example.exe", scope.InScope[3].Value)
				assert.Equal(t, models.AssetTypeBinary, scope.InScope[3].Type)

				// Check out-of-scope assets
				assert.Equal(t, "192.168.1.0/24", scope.OutOfScope[0].Value)
				assert.Equal(t, models.AssetTypeIP, scope.OutOfScope[0].Type)
			},
		},
		{
			name:   "missing credentials",
			handle: "test-program",
			config: config.HackerOneConfig{
				Username: "",
				APIKey:   "",
			},
			expectedError: "HackerOne API credentials not configured",
		},
		{
			name:   "unauthorized response",
			handle: "test-program",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockStatusCode: http.StatusUnauthorized,
			expectedError:  "authentication failed (401)",
		},
		{
			name:   "empty scope",
			handle: "test-program",
			config: config.HackerOneConfig{
				Username: "testuser",
				APIKey:   "testkey",
			},
			mockResponse: map[string]interface{}{
				"data": []map[string]interface{}{},
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
				assert.Equal(t, fmt.Sprintf("/programs/%s/structured_scopes", tt.handle), r.URL.Path)
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
			h1 := NewHackerOne(tt.config, logger)

			// Execute
			ctx := context.Background()
			scope, err := h1.FetchScope(ctx, tt.handle)

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

func TestHackerOne_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.HackerOneConfig{
		APIUrl:   server.URL,
		Username: "testuser",
		APIKey:   "testkey",
	}
	logger := utils.NewLogger("", false)
	h1 := NewHackerOne(cfg, logger)

	// Create a context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// All methods should fail with context cancelled
	_, err := h1.ListPrograms(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")

	_, err = h1.GetProgram(ctx, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")

	_, err = h1.FetchScope(ctx, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestHackerOne_AssetTypeMapping(t *testing.T) {
	tests := []struct {
		assetType    string
		expectedType models.AssetType
	}{
		{"url", models.AssetTypeURL},
		{"URL", models.AssetTypeURL},
		{"domain", models.AssetTypeDomain},
		{"wildcard", models.AssetTypeDomain},
		{"ip_address", models.AssetTypeIP},
		{"cidr", models.AssetTypeIP},
		{"ip_range", models.AssetTypeIP},
		{"android", models.AssetTypeMobile},
		{"ios", models.AssetTypeMobile},
		{"windows", models.AssetTypeMobile},
		{"macos", models.AssetTypeMobile},
		{"executable", models.AssetTypeBinary},
		{"source_code", models.AssetTypeBinary},
		{"other_asset", models.AssetTypeBinary},
		{"unknown", models.AssetTypeOther},
		{"", models.AssetTypeOther},
	}

	for _, tt := range tests {
		t.Run(tt.assetType, func(t *testing.T) {
			// Create a minimal server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": []map[string]interface{}{
						{
							"attributes": map[string]interface{}{
								"asset_identifier":        "test-asset",
								"asset_type":              tt.assetType,
								"instruction":             "Test",
								"eligible_for_submission": []string{"bounty"},
								"attributes":              map[string]interface{}{},
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			cfg := config.HackerOneConfig{
				APIUrl:   server.URL,
				Username: "testuser",
				APIKey:   "testkey",
			}
			logger := utils.NewLogger("", false)
			h1 := NewHackerOne(cfg, logger)

			ctx := context.Background()
			scope, err := h1.FetchScope(ctx, "test")
			require.NoError(t, err)
			require.Len(t, scope.InScope, 1)
			assert.Equal(t, tt.expectedType, scope.InScope[0].Type)
		})
	}
}