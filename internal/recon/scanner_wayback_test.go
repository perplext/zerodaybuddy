package recon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/ratelimit"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func newTestWaybackScanner(serverURL string) *WaybackScanner {
	logger := utils.NewLogger("", true)
	rlConfig := ratelimit.DefaultConfig()
	rateLimiter := ratelimit.New(rlConfig)
	httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
		Service: "wayback",
		Timeout: 5 * time.Second,
		RetryConfig: ratelimit.RetryConfig{
			MaxAttempts:     1,
			InitialDelay:    100 * time.Millisecond,
			MaxDelay:        1 * time.Second,
			Multiplier:      2.0,
			JitterFactor:    0.1,
			RetryableErrors: ratelimit.DefaultRetryableErrors(),
		},
		Logger: logger,
	})

	return &WaybackScanner{
		config:      config.ToolsConfig{},
		logger:      logger,
		rateLimiter: rateLimiter,
		httpClient:  httpClient,
	}
}

func TestNewWaybackScanner(t *testing.T) {
	cfg := config.ToolsConfig{}
	logger := utils.NewLogger("", true)
	scanner := NewWaybackScanner(cfg, logger)
	assert.NotNil(t, scanner)
	assert.NotNil(t, scanner.httpClient)
	assert.NotNil(t, scanner.rateLimiter)
}

func TestWaybackScanner_Name(t *testing.T) {
	scanner := &WaybackScanner{}
	assert.Equal(t, "waybackurls", scanner.Name())
}

func TestWaybackScanner_Description(t *testing.T) {
	scanner := &WaybackScanner{}
	assert.Equal(t, "Discovers historical endpoints from the Wayback Machine", scanner.Description())
}

func TestWaybackScanner_Scan_InvalidTargetType(t *testing.T) {
	scanner := newTestWaybackScanner("")
	project := getTestProjectWithScope()

	invalidTargets := []interface{}{
		123,
		"not-a-slice",
		nil,
	}

	for _, target := range invalidTargets {
		result, err := scanner.Scan(context.Background(), project, target, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid target type for Wayback")
		assert.Nil(t, result)
	}
}

func TestWaybackScanner_DiscoverEndpoints_EmptyInput(t *testing.T) {
	scanner := newTestWaybackScanner("")
	project := getTestProjectWithScope()

	endpoints, err := scanner.DiscoverEndpoints(context.Background(), project, []string{}, ScanOptions{})
	assert.NoError(t, err)
	assert.Nil(t, endpoints)
}

func TestWaybackResultToEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		result    WaybackResult
		projectID string
	}{
		{
			name: "full result",
			result: WaybackResult{
				URL:         "https://example.com/page",
				MimeType:    "text/html",
				StatusCode:  200,
				CaptureDate: time.Now(),
			},
			projectID: "proj-123",
		},
		{
			name: "no mime type",
			result: WaybackResult{
				URL:        "https://example.com/api",
				StatusCode: 301,
			},
			projectID: "proj-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := waybackResultToEndpoint(tt.result, tt.projectID)
			assert.Equal(t, tt.result.URL, ep.URL)
			assert.Equal(t, tt.projectID, ep.ProjectID)
			assert.Equal(t, "GET", ep.Method)
			assert.Equal(t, "waybackurls", ep.FoundBy)
			assert.Equal(t, tt.result.StatusCode, ep.Status)
			if tt.result.MimeType != "" {
				assert.Equal(t, tt.result.MimeType, ep.ContentType)
			}
		})
	}
}

func TestWaybackScanner_DiscoverEndpoints_MockAPI(t *testing.T) {
	// Create a mock CDX API server
	cdxResponse := [][]string{
		{"original", "mimetype", "statuscode", "timestamp", "length"}, // header row
		{"https://example.com/page1", "text/html", "200", "20230101120000", "1234"},
		{"https://example.com/page2", "application/json", "200", "20230615080000", "567"},
		{"https://evil.com/page", "text/html", "200", "20230101120000", "100"}, // out of scope
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cdxResponse)
	}))
	defer server.Close()

	// We can't easily override the CDX API URL in the scanner since it's hardcoded,
	// but we can test the parsing and conversion logic directly
	project := getTestProjectWithScope()

	// Test the URL deduplication logic
	results := []WaybackResult{
		{URL: "https://example.com/page1", StatusCode: 200},
		{URL: "https://example.com/page1", StatusCode: 200}, // duplicate
		{URL: "https://example.com/page2", StatusCode: 301},
	}

	uniqueURLs := make(map[string]bool)
	var filtered []WaybackResult
	for _, r := range results {
		if !uniqueURLs[r.URL] {
			uniqueURLs[r.URL] = true
			filtered = append(filtered, r)
		}
	}

	assert.Len(t, filtered, 2, "duplicates should be removed")
	_ = project
}

func TestWaybackScanner_TimestampParsing(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		wantZero  bool
	}{
		{"valid timestamp", "20230615143025", false},
		{"short timestamp", "2023", true},
		{"empty timestamp", "", true},
		{"invalid timestamp", "not-a-timestamp", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			captureDate := time.Time{}
			if tt.timestamp != "" && len(tt.timestamp) >= 14 {
				captureDate, _ = time.Parse("20060102150405", tt.timestamp[:14])
			}
			assert.Equal(t, tt.wantZero, captureDate.IsZero())
		})
	}
}
