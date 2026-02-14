package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/ratelimit"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func newTestHackerOne(serverURL string) *HackerOne {
	logger := utils.NewLogger("", true)
	rlConfig := ratelimit.DefaultConfig()
	rateLimiter := ratelimit.New(rlConfig)
	httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
		Service: "hackerone",
		Timeout: 5 * time.Second,
		RetryConfig: ratelimit.RetryConfig{
			MaxAttempts:     1,
			InitialDelay:    100 * time.Millisecond,
			MaxDelay:        1 * time.Second,
			Multiplier:      2.0,
			JitterFactor:    0.0,
			RetryableErrors: ratelimit.DefaultRetryableErrors(),
		},
		Logger: logger,
	})

	return &HackerOne{
		config: &config.HackerOneConfig{
			APIUrl:    serverURL,
			Username:  "testuser",
			AuthToken: "testtoken",
			APIKey:    "testkey",
		},
		client: httpClient,
		logger: logger,
	}
}

func TestSubmitReport_FullFlow(t *testing.T) {
	step := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step++
		switch step {
		case 1:
			// Step 1: Create report intent
			assert.Equal(t, "POST", r.Method)
			assert.Contains(t, r.URL.Path, "/report_intents")
			assert.Contains(t, r.Header.Get("Authorization"), "Basic")

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(reportIntentResponse{
				Data: struct {
					ID         string `json:"id"`
					Type       string `json:"type"`
					Attributes struct {
						Token string `json:"token"`
					} `json:"attributes"`
				}{
					ID:   "intent-123",
					Type: "report-intent",
				},
			})

		case 2:
			// Step 2: Update report intent
			assert.Equal(t, "PUT", r.Method)
			assert.Contains(t, r.URL.Path, "/report_intents/intent-123")

			var payload reportIntentUpdateRequest
			json.NewDecoder(r.Body).Decode(&payload)
			assert.Equal(t, "SQL Injection in Login", payload.Data.Attributes.Title)
			assert.Equal(t, "critical", payload.Data.Attributes.Severity.Rating)

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))

		case 3:
			// Step 3: Submit report intent
			assert.Equal(t, "POST", r.Method)
			assert.Contains(t, r.URL.Path, "/report_intents/intent-123/submit")

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(reportSubmissionResponse{
				Data: struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				}{
					ID:   "report-456",
					Type: "report",
				},
			})
		}
	}))
	defer server.Close()

	h1 := newTestHackerOne(server.URL)
	finding := &models.Finding{
		Title:       "SQL Injection in Login",
		Description: "The login form is vulnerable to SQL injection",
		Severity:    models.SeverityCritical,
		Impact:      "Full database access",
		URL:         "https://example.com/login",
		CWE:         "CWE-89",
		Steps:       []string{"Go to /login", "Enter ' OR 1=1 --", "Submit"},
	}

	reportID, err := h1.SubmitReport(context.Background(), "test-program", finding)
	assert.NoError(t, err)
	assert.Equal(t, "report-456", reportID)
	assert.Equal(t, 3, step, "all 3 API steps should have been called")
}

func TestSubmitReport_MissingCredentials(t *testing.T) {
	tests := []struct {
		name   string
		config *config.HackerOneConfig
	}{
		{"missing username", &config.HackerOneConfig{AuthToken: "token"}},
		{"missing auth token", &config.HackerOneConfig{Username: "user"}},
		{"missing both", &config.HackerOneConfig{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := utils.NewLogger("", true)
			rlConfig := ratelimit.DefaultConfig()
			rateLimiter := ratelimit.New(rlConfig)
			httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
				Service: "hackerone",
				Timeout: 5 * time.Second,
				RetryConfig: ratelimit.RetryConfig{
					MaxAttempts: 1, InitialDelay: 100 * time.Millisecond, MaxDelay: 1 * time.Second,
					Multiplier: 2.0, RetryableErrors: ratelimit.DefaultRetryableErrors(),
				},
				Logger: logger,
			})

			h := &HackerOne{config: tt.config, client: httpClient, logger: logger}
			_, err := h.SubmitReport(context.Background(), "prog", &models.Finding{})
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "credentials not configured")
		})
	}
}

func TestCreateReportIntent_AuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	}))
	defer server.Close()

	h1 := newTestHackerOne(server.URL)
	_, err := h1.createReportIntent(context.Background(), "test-program")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 401")
}

func TestUpdateReportIntent_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "not found"}`))
	}))
	defer server.Close()

	h1 := newTestHackerOne(server.URL)
	err := h1.updateReportIntent(context.Background(), "bad-id", &models.Finding{
		Title:    "Test",
		Severity: models.SeverityMedium,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 404")
}

func TestSubmitReportIntent_Conflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error": "report already submitted"}`))
	}))
	defer server.Close()

	h1 := newTestHackerOne(server.URL)
	_, err := h1.submitReportIntent(context.Background(), "intent-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 409")
}

func TestFormatReportBody_AllFields(t *testing.T) {
	finding := &models.Finding{
		Description: "SQL injection vulnerability",
		Details:     "The login parameter is injectable",
		Steps:       []string{"Go to /login", "Enter payload", "Observe response"},
		URL:         "https://example.com/login",
		Remediation: "Use parameterized queries",
	}

	body := formatReportBody(finding)
	assert.Contains(t, body, "## Summary")
	assert.Contains(t, body, "SQL injection vulnerability")
	assert.Contains(t, body, "## Details")
	assert.Contains(t, body, "The login parameter is injectable")
	assert.Contains(t, body, "## Steps to Reproduce")
	assert.Contains(t, body, "1. Go to /login")
	assert.Contains(t, body, "2. Enter payload")
	assert.Contains(t, body, "3. Observe response")
	assert.Contains(t, body, "## Affected URL")
	assert.Contains(t, body, "https://example.com/login")
	assert.Contains(t, body, "## Recommended Fix")
	assert.Contains(t, body, "Use parameterized queries")
}

func TestFormatReportBody_MinimalFields(t *testing.T) {
	finding := &models.Finding{
		Description: "A vulnerability was found",
	}

	body := formatReportBody(finding)
	assert.Contains(t, body, "## Summary")
	assert.Contains(t, body, "A vulnerability was found")
	// Optional sections should not be present
	assert.NotContains(t, body, "## Details")
	assert.NotContains(t, body, "## Steps to Reproduce")
	assert.NotContains(t, body, "## Affected URL")
	assert.NotContains(t, body, "## Recommended Fix")
}

func TestMapSeverityToHackerOne(t *testing.T) {
	tests := []struct {
		severity models.FindingSeverity
		want     string
	}{
		{models.SeverityCritical, "critical"},
		{models.SeverityHigh, "high"},
		{models.SeverityMedium, "medium"},
		{models.SeverityLow, "low"},
		{models.SeverityInfo, "none"},
		{"unknown", "none"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := mapSeverityToHackerOne(tt.severity)
			assert.Equal(t, tt.want, got)
		})
	}
}
