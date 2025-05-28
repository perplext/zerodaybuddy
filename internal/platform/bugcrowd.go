package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/ratelimit"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// Bugcrowd implements the Platform interface for Bugcrowd
type Bugcrowd struct {
	config *config.BugcrowdConfig
	client *ratelimit.HTTPClient
	logger *utils.Logger
}

// NewBugcrowd creates a new Bugcrowd platform instance
func NewBugcrowd(cfg config.BugcrowdConfig, logger *utils.Logger) Platform {
	// Create rate limiter with Bugcrowd specific config
	rlConfig := ratelimit.DefaultConfig()
	rateLimiter := ratelimit.New(rlConfig)
	
	// Create HTTP client with rate limiting
	httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
		Service: "bugcrowd",
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
	
	return &Bugcrowd{
		config: &cfg,
		client: httpClient,
		logger: logger,
	}
}

// NewBugcrowdWithRateLimiter creates a new Bugcrowd platform instance with a shared rate limiter
func NewBugcrowdWithRateLimiter(cfg config.BugcrowdConfig, logger *utils.Logger, rateLimiter *ratelimit.RateLimiter) Platform {
	// Create HTTP client with shared rate limiter
	httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
		Service: "bugcrowd",
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
	
	return &Bugcrowd{
		config: &cfg,
		client: httpClient,
		logger: logger,
	}
}

// ListPrograms lists all available bug bounty programs on Bugcrowd
func (b *Bugcrowd) ListPrograms(ctx context.Context) ([]models.Program, error) {
	b.logger.Debug("Listing Bugcrowd programs")
	
	if b.config.CookieValue == "" {
		return nil, fmt.Errorf("Bugcrowd cookie not configured")
	}
	
	// Bugcrowd API endpoint for programs (this is an unofficial API endpoint)
	endpoint := fmt.Sprintf("%s/programs.json", b.config.APIUrl)
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers and cookies
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ZeroDayBuddy/1.0")
	req.Header.Set("Cookie", fmt.Sprintf("_crowdcontrol_session=%s", b.config.CookieValue))
	
	// Send request
	resp, err := b.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Parse response
	var response struct {
		Programs []struct {
			ID           string    `json:"id"`
			Name         string    `json:"name"`
			Code         string    `json:"code"`
			Description  string    `json:"description"`
			URL          string    `json:"url"`
			CreatedAt    time.Time `json:"created_at"`
			UpdatedAt    time.Time `json:"updated_at"`
			LogoAttachment struct {
				URL string `json:"url"`
			} `json:"logo_attachment"`
		} `json:"programs"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Convert to models.Program
	programs := make([]models.Program, 0, len(response.Programs))
	for _, p := range response.Programs {
		programs = append(programs, models.Program{
			ID:          p.ID,
			Name:        p.Name,
			Handle:      p.Code,
			Description: p.Description,
			URL:         fmt.Sprintf("%s/%s", b.config.APIUrl, p.Code),
			Platform:    "bugcrowd",
			CreatedAt:   p.CreatedAt,
			UpdatedAt:   p.UpdatedAt,
		})
	}
	
	b.logger.Debug("Found %d Bugcrowd programs", len(programs))
	
	return programs, nil
}

// GetProgram retrieves a specific bug bounty program from Bugcrowd
func (b *Bugcrowd) GetProgram(ctx context.Context, handle string) (*models.Program, error) {
	b.logger.Debug("Getting Bugcrowd program: %s", handle)
	
	if b.config.CookieValue == "" {
		return nil, fmt.Errorf("Bugcrowd cookie not configured")
	}
	
	// Bugcrowd API endpoint for a specific program
	endpoint := fmt.Sprintf("%s/%s.json", b.config.APIUrl, handle)
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers and cookies
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ZeroDayBuddy/1.0")
	req.Header.Set("Cookie", fmt.Sprintf("_crowdcontrol_session=%s", b.config.CookieValue))
	
	// Send request
	resp, err := b.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Parse response
	var response struct {
		Program struct {
			ID           string    `json:"id"`
			Name         string    `json:"name"`
			Code         string    `json:"code"`
			Description  string    `json:"description"`
			URL          string    `json:"url"`
			CreatedAt    time.Time `json:"created_at"`
			UpdatedAt    time.Time `json:"updated_at"`
			BriefingInfo string    `json:"briefing"`
		} `json:"program"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Fetch scope
	scope, err := b.FetchScope(ctx, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scope: %w", err)
	}
	
	program := &models.Program{
		ID:          response.Program.ID,
		Name:        response.Program.Name,
		Handle:      response.Program.Code,
		Description: response.Program.Description,
		URL:         fmt.Sprintf("%s/%s", b.config.APIUrl, response.Program.Code),
		Platform:    "bugcrowd",
		Policy:      response.Program.BriefingInfo,
		Scope:       *scope,
		CreatedAt:   response.Program.CreatedAt,
		UpdatedAt:   response.Program.UpdatedAt,
	}
	
	b.logger.Debug("Got Bugcrowd program: %s", program.Name)
	
	return program, nil
}

// FetchScope fetches the scope for a bug bounty program
func (b *Bugcrowd) FetchScope(ctx context.Context, handle string) (*models.Scope, error) {
	b.logger.Debug("Fetching scope for Bugcrowd program: %s", handle)
	
	if b.config.CookieValue == "" {
		return nil, fmt.Errorf("Bugcrowd cookie not configured")
	}
	
	// Bugcrowd API endpoint for program targets (this is an unofficial API endpoint)
	endpoint := fmt.Sprintf("%s/%s/targets.json", b.config.APIUrl, handle)
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers and cookies
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ZeroDayBuddy/1.0")
	req.Header.Set("Cookie", fmt.Sprintf("_crowdcontrol_session=%s", b.config.CookieValue))
	
	// Send request
	resp, err := b.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Parse response
	var response struct {
		Targets []struct {
			ID          string    `json:"id"`
			Name        string    `json:"name"`
			Category    string    `json:"category"`
			Description string    `json:"description"`
			URI         string    `json:"uri"`
			InScope     bool      `json:"in_scope"`
			CreatedAt   time.Time `json:"created_at"`
			UpdatedAt   time.Time `json:"updated_at"`
		} `json:"targets"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Process scope items
	scope := &models.Scope{
		InScope:   make([]models.Asset, 0),
		OutOfScope: make([]models.Asset, 0),
	}
	
	for _, target := range response.Targets {
		asset := models.Asset{
			Value:        target.URI,
			Description:  target.Description,
			Instructions: target.Description,
			Attributes:   make(map[string]interface{}),
		}
		
		// Determine asset type based on category
		switch strings.ToLower(target.Category) {
		case "website", "api", "web":
			if strings.HasPrefix(target.URI, "http") {
				asset.Type = models.AssetTypeURL
			} else {
				asset.Type = models.AssetTypeDomain
			}
		case "mobile":
			asset.Type = models.AssetTypeMobile
		case "binary":
			asset.Type = models.AssetTypeBinary
		case "ip", "ip_range", "network":
			asset.Type = models.AssetTypeIP
		default:
			asset.Type = models.AssetTypeOther
		}
		
		// Check if in scope
		if target.InScope {
			scope.InScope = append(scope.InScope, asset)
		} else {
			scope.OutOfScope = append(scope.OutOfScope, asset)
		}
	}
	
	b.logger.Debug("Fetched scope for Bugcrowd program %s: %d in-scope, %d out-of-scope", 
		handle, len(scope.InScope), len(scope.OutOfScope))
	
	return scope, nil
}

// GetName returns the name of the platform
func (b *Bugcrowd) GetName() string {
	return "bugcrowd"
}
