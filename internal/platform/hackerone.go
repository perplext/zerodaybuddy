package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/ratelimit"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// HackerOne implements the Platform interface for HackerOne
type HackerOne struct {
	config    *config.HackerOneConfig
	client    *ratelimit.HTTPClient
	logger    *utils.Logger
}

// NewHackerOne creates a new HackerOne platform instance
func NewHackerOne(cfg config.HackerOneConfig, logger *utils.Logger) Platform {
	// Create rate limiter with HackerOne specific config
	rlConfig := ratelimit.DefaultConfig()
	rateLimiter := ratelimit.New(rlConfig)
	
	// Create HTTP client with rate limiting
	httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
		Service: "hackerone",
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
	
	return &HackerOne{
		config: &cfg,
		client: httpClient,
		logger: logger,
	}
}

// NewHackerOneWithRateLimiter creates a new HackerOne platform instance with a shared rate limiter
func NewHackerOneWithRateLimiter(cfg config.HackerOneConfig, logger *utils.Logger, rateLimiter *ratelimit.RateLimiter) Platform {
	// Create HTTP client with shared rate limiter
	httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
		Service: "hackerone",
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
	
	return &HackerOne{
		config: &cfg,
		client: httpClient,
		logger: logger,
	}
}

// ListPrograms lists all available bug bounty programs on HackerOne.
// Follows JSON:API pagination links to fetch all pages of results.
func (h *HackerOne) ListPrograms(ctx context.Context) ([]models.Program, error) {
	h.logger.Debug("Listing HackerOne programs")

	if h.config.APIKey == "" {
		return nil, fmt.Errorf("HackerOne API credentials not configured")
	}

	var programs []models.Program
	nextURL := fmt.Sprintf("%s/programs", h.config.APIUrl)

	for page := 0; nextURL != "" && page < maxPages; page++ {
		pagePrograms, next, err := h.fetchProgramsPage(ctx, nextURL)
		if err != nil {
			return nil, err
		}
		programs = append(programs, pagePrograms...)
		nextURL = next
	}

	h.logger.Debug("Found %d HackerOne programs", len(programs))
	return programs, nil
}

// fetchProgramsPage fetches a single page of programs and returns the next page URL (if any).
func (h *HackerOne) fetchProgramsPage(ctx context.Context, endpoint string) ([]models.Program, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s",
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", h.config.APIKey, h.config.APIKey)))))

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, "", fmt.Errorf("authentication failed (401): %s. Note: Individual hacker accounts may have limited API access. Organization accounts are required for full API functionality", string(body))
		}
		return nil, "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var response struct {
		Data []struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				Handle      string `json:"handle"`
				Name        string `json:"name"`
				Description string `json:"description"`
				URL         string `json:"url"`
				CreatedAt   string `json:"created_at"`
				UpdatedAt   string `json:"updated_at"`
			} `json:"attributes"`
		} `json:"data"`
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, "", fmt.Errorf("failed to parse response: %w", err)
	}

	programs := make([]models.Program, 0, len(response.Data))
	for _, p := range response.Data {
		createdAt, _ := time.Parse(time.RFC3339, p.Attributes.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, p.Attributes.UpdatedAt)

		programs = append(programs, models.Program{
			ID:          p.ID,
			Name:        p.Attributes.Name,
			Handle:      p.Attributes.Handle,
			Description: p.Attributes.Description,
			URL:         p.Attributes.URL,
			Platform:    "hackerone",
			CreatedAt:   createdAt,
			UpdatedAt:   updatedAt,
		})
	}

	return programs, response.Links.Next, nil
}

// GetProgram retrieves a specific bug bounty program from HackerOne
func (h *HackerOne) GetProgram(ctx context.Context, handle string) (*models.Program, error) {
	h.logger.Debug("Getting HackerOne program: %s", handle)
	
	if h.config.APIKey == "" {
		return nil, fmt.Errorf("HackerOne API credentials not configured")
	}

	// HackerOne API endpoint for a specific program
	endpoint := fmt.Sprintf("%s/programs/%s", h.config.APIUrl, handle)
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Accept", "application/json")
	// For hacker API tokens, the token is used as both username and password
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", 
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", h.config.APIKey, h.config.APIKey)))))
	
	// Send request
	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("authentication failed (401): %s. Note: Individual hacker accounts may have limited API access. Organization accounts are required for full API functionality", string(body))
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	var response struct {
		Data struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				Handle      string `json:"handle"`
				Name        string `json:"name"`
				Description string `json:"description"`
				URL         string `json:"url"`
				Policy      string `json:"policy"`
				CreatedAt   string `json:"created_at"`
				UpdatedAt   string `json:"updated_at"`
			} `json:"attributes"`
		} `json:"data"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	createdAt, _ := time.Parse(time.RFC3339, response.Data.Attributes.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, response.Data.Attributes.UpdatedAt)
	
	// Fetch scope
	scope, err := h.FetchScope(ctx, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scope: %w", err)
	}
	
	program := &models.Program{
		ID:          response.Data.ID,
		Name:        response.Data.Attributes.Name,
		Handle:      response.Data.Attributes.Handle,
		Description: response.Data.Attributes.Description,
		URL:         response.Data.Attributes.URL,
		Platform:    "hackerone",
		Policy:      response.Data.Attributes.Policy,
		Scope:       *scope,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
	
	h.logger.Debug("Got HackerOne program: %s", program.Name)
	
	return program, nil
}

// FetchScope fetches the scope for a bug bounty program
func (h *HackerOne) FetchScope(ctx context.Context, handle string) (*models.Scope, error) {
	h.logger.Debug("Fetching scope for HackerOne program: %s", handle)
	
	if h.config.APIKey == "" {
		return nil, fmt.Errorf("HackerOne API credentials not configured")
	}

	// HackerOne API endpoint for program scope
	endpoint := fmt.Sprintf("%s/programs/%s/structured_scopes", h.config.APIUrl, handle)
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Accept", "application/json")
	// For hacker API tokens, the token is used as both username and password
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", 
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", h.config.APIKey, h.config.APIKey)))))
	
	// Send request
	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("authentication failed (401): %s. Note: Individual hacker accounts may have limited API access. Organization accounts are required for full API functionality", string(body))
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	var response struct {
		Data []struct {
			Attributes struct {
				Asset       string                 `json:"asset_identifier"`
				AssetType   string                 `json:"asset_type"`
				Instruction string                 `json:"instruction"`
				EligibleFor []string               `json:"eligible_for_submission"`
				Attributes  map[string]interface{} `json:"attributes"`
			} `json:"attributes"`
		} `json:"data"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Process scope items
	scope := &models.Scope{
		InScope:   make([]models.Asset, 0),
		OutOfScope: make([]models.Asset, 0),
	}
	
	for _, item := range response.Data {
		asset := models.Asset{
			Value:        item.Attributes.Asset,
			Description:  item.Attributes.Instruction,
			Attributes:   item.Attributes.Attributes,
			Instructions: item.Attributes.Instruction,
		}
		
		// Determine asset type
		switch strings.ToLower(item.Attributes.AssetType) {
		case "url":
			asset.Type = models.AssetTypeURL
		case "domain", "wildcard":
			asset.Type = models.AssetTypeDomain
		case "ip_address", "cidr", "ip_range":
			asset.Type = models.AssetTypeIP
		case "android", "ios", "windows", "macos", "other":
			asset.Type = models.AssetTypeMobile
		case "executable", "source_code", "other_asset":
			asset.Type = models.AssetTypeBinary
		default:
			asset.Type = models.AssetTypeOther
		}
		
		// Check if in scope
		if len(item.Attributes.EligibleFor) > 0 {
			scope.InScope = append(scope.InScope, asset)
		} else {
			scope.OutOfScope = append(scope.OutOfScope, asset)
		}
	}
	
	h.logger.Debug("Fetched scope for HackerOne program %s: %d in-scope, %d out-of-scope", 
		handle, len(scope.InScope), len(scope.OutOfScope))
	
	return scope, nil
}

// GetName returns the name of the platform
func (h *HackerOne) GetName() string {
	return "hackerone"
}
