package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// ErrHackerTierToken signals that the configured HackerOne token returned 401 on
// both the organization API and the hacker API — typically invalid credentials.
// (If the hacker API works but the org API fails, we fall back silently.)
var ErrHackerTierToken = errors.New(
	"hackerone authentication failed (401): invalid API credentials or token expired. " +
		"Check your HackerOne API token at https://hackerone.com/settings/api_token and ensure " +
		"it hasn't been revoked.")

// HackerOne implements the Platform interface for HackerOne
type HackerOne struct {
	config *config.HackerOneConfig
	client *ratelimit.HTTPClient
	logger *utils.Logger
	// useHackerAPI is set to true after a successful hacker API call, allowing
	// subsequent requests to skip the organization API attempt.
	useHackerAPI bool
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
// Tries the organization API first (/programs), then falls back to the hacker
// API (/hackers/programs) if the token doesn't have organization access.
func (h *HackerOne) ListPrograms(ctx context.Context) ([]models.Program, error) {
	h.logger.Debug("Listing HackerOne programs")

	if h.config.APIKey == "" {
		return nil, fmt.Errorf("HackerOne API credentials not configured")
	}

	// Try hacker API directly if we know the token is hacker-tier.
	if h.useHackerAPI {
		return h.listProgramsHackerAPI(ctx)
	}

	// Try organization API first.
	programs, err := h.listProgramsOrgAPI(ctx)
	if err == nil {
		return programs, nil
	}

	// On 401, try the hacker API.
	if isUnauthorizedError(err) {
		h.logger.Debug("Organization API returned 401, trying hacker API")
		programs, hackerErr := h.listProgramsHackerAPI(ctx)
		if hackerErr == nil {
			h.useHackerAPI = true
			return programs, nil
		}
		// Both APIs failed — return the hacker API error for better UX.
		return nil, hackerErr
	}

	return nil, err
}

// listProgramsOrgAPI fetches programs from the organization API (/programs).
func (h *HackerOne) listProgramsOrgAPI(ctx context.Context) ([]models.Program, error) {
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

	h.logger.Debug("Found %d HackerOne programs (org API)", len(programs))
	return programs, nil
}

// listProgramsHackerAPI fetches programs from the hacker API (/hackers/programs).
func (h *HackerOne) listProgramsHackerAPI(ctx context.Context) ([]models.Program, error) {
	var programs []models.Program
	nextURL := fmt.Sprintf("%s/hackers/programs", h.config.APIUrl)

	for page := 0; nextURL != "" && page < maxPages; page++ {
		pagePrograms, next, err := h.fetchProgramsPageHackerAPI(ctx, nextURL)
		if err != nil {
			return nil, err
		}
		programs = append(programs, pagePrograms...)
		nextURL = next
	}

	h.logger.Debug("Found %d HackerOne programs (hacker API)", len(programs))
	return programs, nil
}

// fetchProgramsPage fetches a single page of programs from the org API.
func (h *HackerOne) fetchProgramsPage(ctx context.Context, endpoint string) ([]models.Program, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", h.authHeader())

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			h.logger.Debug("HackerOne org API 401 response body: %s", string(body))
			return nil, "", &unauthorizedError{api: "org"}
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

// fetchProgramsPageHackerAPI fetches a single page of programs from the hacker API.
func (h *HackerOne) fetchProgramsPageHackerAPI(ctx context.Context, endpoint string) ([]models.Program, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", h.authHeader())

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			h.logger.Debug("HackerOne hacker API 401 response body: %s", string(body))
			return nil, "", ErrHackerTierToken
		}
		return nil, "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Hacker API response structure — similar to org API but may have different fields.
	var response struct {
		Data []struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				Handle      string `json:"handle"`
				Name        string `json:"name"`
				Description string `json:"description"`
				URL         string `json:"url"`
				Policy      string `json:"policy"`
				Currency    string `json:"currency"`
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
			Policy:      p.Attributes.Policy,
			CreatedAt:   createdAt,
			UpdatedAt:   updatedAt,
		})
	}

	return programs, response.Links.Next, nil
}

// GetProgram retrieves a specific bug bounty program from HackerOne.
// Tries the organization API first, then falls back to the hacker API.
func (h *HackerOne) GetProgram(ctx context.Context, handle string) (*models.Program, error) {
	h.logger.Debug("Getting HackerOne program: %s", handle)

	if h.config.APIKey == "" {
		return nil, fmt.Errorf("HackerOne API credentials not configured")
	}

	// Try hacker API directly if we know the token is hacker-tier.
	if h.useHackerAPI {
		return h.getProgramHackerAPI(ctx, handle)
	}

	// Try organization API first.
	program, err := h.getProgramOrgAPI(ctx, handle)
	if err == nil {
		return program, nil
	}

	// On 401, try the hacker API.
	if isUnauthorizedError(err) {
		h.logger.Debug("Organization API returned 401, trying hacker API for program %s", handle)
		program, hackerErr := h.getProgramHackerAPI(ctx, handle)
		if hackerErr == nil {
			h.useHackerAPI = true
			return program, nil
		}
		return nil, hackerErr
	}

	return nil, err
}

// getProgramOrgAPI fetches a program from the organization API.
func (h *HackerOne) getProgramOrgAPI(ctx context.Context, handle string) (*models.Program, error) {
	endpoint := fmt.Sprintf("%s/programs/%s", h.config.APIUrl, handle)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", h.authHeader())

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			h.logger.Debug("HackerOne org API 401 response body: %s", string(body))
			return nil, &unauthorizedError{api: "org"}
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

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

	if decodeErr := json.NewDecoder(resp.Body).Decode(&response); decodeErr != nil {
		return nil, fmt.Errorf("failed to parse response: %w", decodeErr)
	}

	createdAt, _ := time.Parse(time.RFC3339, response.Data.Attributes.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, response.Data.Attributes.UpdatedAt)

	// Fetch scope using org API.
	scope, err := h.fetchScopeOrgAPI(ctx, handle)
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

	h.logger.Debug("Got HackerOne program (org API): %s", program.Name)
	return program, nil
}

// getProgramHackerAPI fetches a program from the hacker API.
func (h *HackerOne) getProgramHackerAPI(ctx context.Context, handle string) (*models.Program, error) {
	endpoint := fmt.Sprintf("%s/hackers/programs/%s", h.config.APIUrl, handle)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", h.authHeader())

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			h.logger.Debug("HackerOne hacker API 401 response body: %s", string(body))
			return nil, ErrHackerTierToken
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("program %q not found on HackerOne", handle)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

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
				Currency    string `json:"currency"`
				CreatedAt   string `json:"created_at"`
				UpdatedAt   string `json:"updated_at"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if decodeErr := json.NewDecoder(resp.Body).Decode(&response); decodeErr != nil {
		return nil, fmt.Errorf("failed to parse response: %w", decodeErr)
	}

	createdAt, _ := time.Parse(time.RFC3339, response.Data.Attributes.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, response.Data.Attributes.UpdatedAt)

	// Fetch scope using hacker API.
	scope, err := h.fetchScopeHackerAPI(ctx, handle)
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

	h.logger.Debug("Got HackerOne program (hacker API): %s", program.Name)
	return program, nil
}

// FetchScope fetches the scope for a bug bounty program.
// Tries the organization API first, then falls back to the hacker API.
func (h *HackerOne) FetchScope(ctx context.Context, handle string) (*models.Scope, error) {
	h.logger.Debug("Fetching scope for HackerOne program: %s", handle)

	if h.config.APIKey == "" {
		return nil, fmt.Errorf("HackerOne API credentials not configured")
	}

	// Try hacker API directly if we know the token is hacker-tier.
	if h.useHackerAPI {
		return h.fetchScopeHackerAPI(ctx, handle)
	}

	// Try organization API first.
	scope, err := h.fetchScopeOrgAPI(ctx, handle)
	if err == nil {
		return scope, nil
	}

	// On 401, try the hacker API.
	if isUnauthorizedError(err) {
		h.logger.Debug("Organization API returned 401, trying hacker API for scope %s", handle)
		scope, hackerErr := h.fetchScopeHackerAPI(ctx, handle)
		if hackerErr == nil {
			h.useHackerAPI = true
			return scope, nil
		}
		return nil, hackerErr
	}

	return nil, err
}

// fetchScopeOrgAPI fetches scope from the organization API.
func (h *HackerOne) fetchScopeOrgAPI(ctx context.Context, handle string) (*models.Scope, error) {
	endpoint := fmt.Sprintf("%s/programs/%s/structured_scopes", h.config.APIUrl, handle)
	return h.fetchScopeFromEndpoint(ctx, endpoint, "org")
}

// fetchScopeHackerAPI fetches scope from the hacker API.
func (h *HackerOne) fetchScopeHackerAPI(ctx context.Context, handle string) (*models.Scope, error) {
	endpoint := fmt.Sprintf("%s/hackers/programs/%s/structured_scopes", h.config.APIUrl, handle)
	return h.fetchScopeFromEndpoint(ctx, endpoint, "hacker")
}

// fetchScopeFromEndpoint is a shared implementation for fetching scope from either API.
func (h *HackerOne) fetchScopeFromEndpoint(ctx context.Context, endpoint, apiName string) (*models.Scope, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", h.authHeader())

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			h.logger.Debug("HackerOne %s API 401 response body: %s", apiName, string(body))
			if apiName == "org" {
				return nil, &unauthorizedError{api: "org"}
			}
			return nil, ErrHackerTierToken
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse response — same structure for both APIs.
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

	// Process scope items.
	scope := &models.Scope{
		InScope:    make([]models.Asset, 0),
		OutOfScope: make([]models.Asset, 0),
	}

	for _, item := range response.Data {
		asset := models.Asset{
			Value:        item.Attributes.Asset,
			Description:  item.Attributes.Instruction,
			Attributes:   item.Attributes.Attributes,
			Instructions: item.Attributes.Instruction,
		}

		// Determine asset type.
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

		// Check if in scope.
		if len(item.Attributes.EligibleFor) > 0 {
			scope.InScope = append(scope.InScope, asset)
		} else {
			scope.OutOfScope = append(scope.OutOfScope, asset)
		}
	}

	h.logger.Debug("Fetched scope for HackerOne program (%s API): %d in-scope, %d out-of-scope",
		apiName, len(scope.InScope), len(scope.OutOfScope))

	return scope, nil
}

// GetName returns the name of the platform
func (h *HackerOne) GetName() string {
	return "hackerone"
}

// authHeader returns the Authorization header value for HackerOne API requests.
// HackerOne uses the API token as both username and password for Basic auth.
func (h *HackerOne) authHeader() string {
	return fmt.Sprintf("Basic %s",
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", h.config.APIKey, h.config.APIKey))))
}

// unauthorizedError is an internal error type to distinguish org API 401s
// (which should trigger hacker API fallback) from hacker API 401s (terminal).
type unauthorizedError struct {
	api string // "org" or "hacker"
}

func (e *unauthorizedError) Error() string {
	return fmt.Sprintf("HackerOne %s API returned 401", e.api)
}

// isUnauthorizedError checks if the error is an internal org API 401 that should
// trigger a fallback to the hacker API.
func isUnauthorizedError(err error) bool {
	var unauthErr *unauthorizedError
	return errors.As(err, &unauthErr) && unauthErr.api == "org"
}
