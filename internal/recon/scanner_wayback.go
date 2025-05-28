package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/ratelimit"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// WaybackScanner implements the Scanner interface for Wayback Machine
type WaybackScanner struct {
	config      config.ToolsConfig
	logger      *utils.Logger
	rateLimiter *ratelimit.RateLimiter
	httpClient  *ratelimit.HTTPClient
}

// NewWaybackScanner creates a new Wayback scanner
func NewWaybackScanner(config config.ToolsConfig, logger *utils.Logger) Scanner {
	// Create rate limiter with config
	rlConfig := ratelimit.DefaultConfig()
	rateLimiter := ratelimit.New(rlConfig)
	
	// Create HTTP client with rate limiting
	httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
		Service: "wayback",
		Timeout: 30 * time.Second,
		RetryConfig: ratelimit.RetryConfig{
			MaxAttempts:     3,
			InitialDelay:    1 * time.Second,
			MaxDelay:        30 * time.Second,
			Multiplier:      2.0,
			JitterFactor:    0.1,
			RetryableErrors: ratelimit.DefaultRetryableErrors(),
		},
		Logger: logger,
	})
	
	return &WaybackScanner{
		config:      config,
		logger:      logger,
		rateLimiter: rateLimiter,
		httpClient:  httpClient,
	}
}

// Name returns the name of the scanner
func (s *WaybackScanner) Name() string {
	return "wayback"
}

// Description returns a description of the scanner
func (s *WaybackScanner) Description() string {
	return "Discovers historical endpoints from the Wayback Machine"
}

// WaybackResult represents a URL found in the Wayback Machine
type WaybackResult struct {
	URL           string    `json:"url"`
	MimeType      string    `json:"mime_type"`
	StatusCode    int       `json:"status_code"`
	CaptureDate   time.Time `json:"capture_date"`
	OriginalURL   string    `json:"original_url"`
	ContentLength int       `json:"content_length"`
}

// Scan performs a search for historical endpoints in the Wayback Machine
func (s *WaybackScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	domains, ok := target.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Wayback: %T", target)
	}

	if len(domains) == 0 {
		return []WaybackResult{}, nil
	}

	s.logger.Debug("Starting Wayback scan for %d domains", len(domains))

	allResults := []WaybackResult{}

	// Process each domain separately
	for _, domain := range domains {
		// Skip if the domain is not in scope
		if !project.Scope.IsInScope(models.AssetTypeDomain, domain) {
			s.logger.Debug("Skipping out-of-scope domain: %s", domain)
			continue
		}

		s.logger.Debug("Querying Wayback Machine for domain: %s", domain)

		// Build the Wayback Machine API URL
		// This uses the CDX API which is more reliable than the regular API
		apiURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey&fl=original,mimetype,statuscode,timestamp,length", url.QueryEscape(domain))

		// Add limit if specified in options
		limit := 1000 // Default limit
		if options != nil {
			if l, ok := options["limit"].(int); ok && l > 0 {
				limit = l
			}
		}
		apiURL = fmt.Sprintf("%s&limit=%d", apiURL, limit)

		// Make the request using rate-limited client
		resp, err := s.httpClient.Get(ctx, apiURL)
		if err != nil {
			s.logger.Warn("Failed to query Wayback Machine for %s: %v", domain, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			s.logger.Warn("Failed to read response from Wayback Machine: %v", err)
			continue
		}

		// Parse the JSON response
		var results [][]string
		if err := json.Unmarshal(body, &results); err != nil {
			s.logger.Warn("Failed to parse Wayback Machine response: %v", err)
			continue
		}

		// The first row contains the column headers
		if len(results) <= 1 {
			s.logger.Debug("No results found in Wayback Machine for %s", domain)
			continue
		}

		// Process the results (skipping the header row)
		for i, row := range results {
			if i == 0 {
				continue // Skip header row
			}

			if len(row) < 5 {
				continue // Skip rows with insufficient data
			}

			originalURL := row[0]
			mimeType := row[1]
			
			// Parse status code
			statusCode := 0
			if row[2] != "" {
				fmt.Sscanf(row[2], "%d", &statusCode)
			}

			// Parse timestamp
			captureDate := time.Time{}
			if row[3] != "" {
				timeStr := row[3]
				if len(timeStr) >= 14 {
					captureDate, _ = time.Parse("20060102150405", timeStr[:14])
				}
			}

			// Parse content length
			contentLength := 0
			if row[4] != "" {
				fmt.Sscanf(row[4], "%d", &contentLength)
			}

			// Only include URLs that are in scope
			if project.Scope.IsInScope(models.AssetTypeURL, originalURL) {
				result := WaybackResult{
					URL:           originalURL,
					MimeType:      mimeType,
					StatusCode:    statusCode,
					CaptureDate:   captureDate,
					OriginalURL:   originalURL,
					ContentLength: contentLength,
				}
				allResults = append(allResults, result)
			}
		}

		s.logger.Debug("Found %d historical URLs for domain %s", len(allResults)-len(allResults), domain)
	}

	// Filter for unique URLs
	uniqueURLs := make(map[string]bool)
	var filteredResults []WaybackResult
	for _, result := range allResults {
		if !uniqueURLs[result.URL] {
			uniqueURLs[result.URL] = true
			filteredResults = append(filteredResults, result)
		}
	}

	s.logger.Debug("Wayback scan completed with %d unique historical URLs", len(filteredResults))

	return filteredResults, nil
}
