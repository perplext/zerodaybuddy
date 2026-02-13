package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/ratelimit"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

const immunefiDefaultAPIURL = "https://immunefi.com/api"

// Immunefi implements the Platform interface for the Immunefi web3 bug bounty platform.
type Immunefi struct {
	config     *config.ImmunefiConfig
	httpClient *ratelimit.HTTPClient
	logger     *utils.Logger
}

// NewImmunefi creates a new Immunefi platform instance.
func NewImmunefi(cfg config.ImmunefiConfig, logger *utils.Logger) Platform {
	if cfg.APIUrl == "" {
		cfg.APIUrl = immunefiDefaultAPIURL
	}

	// Create rate limiter with default config
	rlConfig := ratelimit.DefaultConfig()
	rateLimiter := ratelimit.New(rlConfig)

	httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
		Service: "immunefi",
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

	return &Immunefi{
		config:     &cfg,
		httpClient: httpClient,
		logger:     logger,
	}
}

func (i *Immunefi) GetName() string { return "immunefi" }

// immunefiBounciesResponse represents the Immunefi bounties API response.
type immunefiBounciesResponse struct {
	PageProps struct {
		Bounties []immunefiBounty `json:"bounties"`
	} `json:"pageProps"`
}

type immunefiBounty struct {
	ID           string `json:"id"`
	Project      string `json:"project"`
	MaxBounty    int64  `json:"maxBounty"`
	LaunchDate   string `json:"launchDate"`
	UpdatedDate  string `json:"updatedDate"`
	KYCRequired  bool   `json:"kyc"`
	IsPaused     bool   `json:"isPaused"`
	Features     []string `json:"features"`
	Ecosystem    []string `json:"ecosystem"`
	ProductType  []string `json:"productType"`
	ProgramURL   string `json:"programUrl"`
}

type immunefiAsset struct {
	Target  string `json:"target"`
	Type    string `json:"type"`
	URL     string `json:"url,omitempty"`
}

// ListPrograms lists all available Immunefi bug bounty programs.
func (i *Immunefi) ListPrograms(ctx context.Context) ([]models.Program, error) {
	i.logger.Debug("Listing Immunefi programs")

	endpoint := fmt.Sprintf("%s/bounties", i.config.APIUrl)

	resp, err := i.httpClient.Get(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Immunefi programs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Immunefi API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var apiResp immunefiBounciesResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse Immunefi response: %w", err)
	}

	var programs []models.Program
	for _, bounty := range apiResp.PageProps.Bounties {
		if bounty.IsPaused {
			continue
		}
		program := models.Program{
			Handle:   bounty.ID,
			Name:     bounty.Project,
			Platform: "immunefi",
			URL:      bounty.ProgramURL,
		}
		programs = append(programs, program)
	}

	i.logger.Debug("Found %d active Immunefi programs", len(programs))
	return programs, nil
}

// GetProgram retrieves a specific Immunefi bug bounty program.
func (i *Immunefi) GetProgram(ctx context.Context, handle string) (*models.Program, error) {
	i.logger.Debug("Getting Immunefi program: %s", handle)

	programs, err := i.ListPrograms(ctx)
	if err != nil {
		return nil, err
	}

	for _, p := range programs {
		if p.Handle == handle || strings.EqualFold(p.Name, handle) {
			return &p, nil
		}
	}

	return nil, fmt.Errorf("Immunefi program %q not found", handle)
}

// FetchScope fetches the scope for an Immunefi bug bounty program.
func (i *Immunefi) FetchScope(ctx context.Context, handle string) (*models.Scope, error) {
	i.logger.Debug("Fetching scope for Immunefi program: %s", handle)

	endpoint := fmt.Sprintf("%s/bounty/%s", i.config.APIUrl, url.PathEscape(handle))

	resp, err := i.httpClient.Get(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Immunefi scope: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Immunefi API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse the bounty detail response for assets
	var bountyDetail struct {
		PageProps struct {
			Bounty struct {
				Assets []immunefiAsset `json:"assets"`
			} `json:"bounty"`
		} `json:"pageProps"`
	}
	if err := json.Unmarshal(body, &bountyDetail); err != nil {
		return nil, fmt.Errorf("failed to parse Immunefi bounty detail: %w", err)
	}

	scope := &models.Scope{
		InScope:    make([]models.Asset, 0),
		OutOfScope: make([]models.Asset, 0),
	}

	for _, asset := range bountyDetail.PageProps.Bounty.Assets {
		a := models.Asset{
			Value: asset.Target,
			Type:  immunefiAssetType(asset.Type),
		}
		scope.InScope = append(scope.InScope, a)
	}

	return scope, nil
}

// immunefiAssetType maps Immunefi asset types to our asset types.
func immunefiAssetType(assetType string) models.AssetType {
	switch strings.ToLower(assetType) {
	case "smart_contract", "smart contract":
		return models.AssetTypeSmartContract
	case "websites_and_applications", "web", "website":
		return models.AssetTypeURL
	case "blockchain_dlt", "blockchain":
		return models.AssetTypeOther
	case "github", "repository":
		return models.AssetTypeRepository
	default:
		return models.AssetTypeOther
	}
}
