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

func newTestImmunefi(serverURL string) Platform {
	logger := utils.NewLogger("", true)
	rlConfig := ratelimit.DefaultConfig()
	rateLimiter := ratelimit.New(rlConfig)
	httpClient := ratelimit.NewHTTPClient(rateLimiter, ratelimit.HTTPClientConfig{
		Service: "immunefi",
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

	return &Immunefi{
		config:     &config.ImmunefiConfig{APIUrl: serverURL},
		httpClient: httpClient,
		logger:     logger,
	}
}

func TestNewImmunefi(t *testing.T) {
	logger := utils.NewLogger("", true)

	t.Run("default API URL", func(t *testing.T) {
		cfg := config.ImmunefiConfig{}
		p := NewImmunefi(cfg, logger)
		assert.NotNil(t, p)
		assert.Equal(t, "immunefi", p.GetName())
	})

	t.Run("custom API URL", func(t *testing.T) {
		cfg := config.ImmunefiConfig{APIUrl: "https://custom.api.com"}
		p := NewImmunefi(cfg, logger)
		assert.NotNil(t, p)
	})
}

func TestImmunefi_ListPrograms_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/bounties", r.URL.Path)
		resp := immunefiBounciesResponse{}
		resp.PageProps.Bounties = []immunefiBounty{
			{ID: "prog-1", Project: "DeFi Protocol", IsPaused: false, ProgramURL: "https://immunefi.com/bounty/defi"},
			{ID: "prog-2", Project: "Paused Project", IsPaused: true, ProgramURL: "https://immunefi.com/bounty/paused"},
			{ID: "prog-3", Project: "Active DAO", IsPaused: false, ProgramURL: "https://immunefi.com/bounty/dao"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.ImmunefiConfig{APIUrl: server.URL}
	logger := utils.NewLogger("", true)
	p := NewImmunefi(cfg, logger)

	programs, err := p.ListPrograms(context.Background())
	assert.NoError(t, err)
	assert.Len(t, programs, 2, "paused programs should be filtered out")

	assert.Equal(t, "prog-1", programs[0].Handle)
	assert.Equal(t, "DeFi Protocol", programs[0].Name)
	assert.Equal(t, "immunefi", programs[0].Platform)

	assert.Equal(t, "prog-3", programs[1].Handle)
}

func TestImmunefi_ListPrograms_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := immunefiBounciesResponse{}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.ImmunefiConfig{APIUrl: server.URL}
	p := NewImmunefi(cfg, utils.NewLogger("", true))

	programs, err := p.ListPrograms(context.Background())
	assert.NoError(t, err)
	assert.Empty(t, programs)
}

func TestImmunefi_ListPrograms_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Use a direct struct construction with MaxAttempts: 1 to avoid slow retries
	p := newTestImmunefi(server.URL)

	_, err := p.ListPrograms(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestImmunefi_ListPrograms_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	cfg := config.ImmunefiConfig{APIUrl: server.URL}
	p := NewImmunefi(cfg, utils.NewLogger("", true))

	_, err := p.ListPrograms(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestImmunefi_GetProgram_Found(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := immunefiBounciesResponse{}
		resp.PageProps.Bounties = []immunefiBounty{
			{ID: "target-prog", Project: "Target Protocol", IsPaused: false},
			{ID: "other-prog", Project: "Other Protocol", IsPaused: false},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.ImmunefiConfig{APIUrl: server.URL}
	p := NewImmunefi(cfg, utils.NewLogger("", true))

	program, err := p.GetProgram(context.Background(), "target-prog")
	assert.NoError(t, err)
	assert.NotNil(t, program)
	assert.Equal(t, "target-prog", program.Handle)
	assert.Equal(t, "Target Protocol", program.Name)
}

func TestImmunefi_GetProgram_CaseInsensitive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := immunefiBounciesResponse{}
		resp.PageProps.Bounties = []immunefiBounty{
			{ID: "defi", Project: "DeFi Protocol", IsPaused: false},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.ImmunefiConfig{APIUrl: server.URL}
	p := NewImmunefi(cfg, utils.NewLogger("", true))

	// Case-insensitive name match
	program, err := p.GetProgram(context.Background(), "defi protocol")
	assert.NoError(t, err)
	assert.NotNil(t, program)
	assert.Equal(t, "DeFi Protocol", program.Name)
}

func TestImmunefi_GetProgram_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := immunefiBounciesResponse{}
		resp.PageProps.Bounties = []immunefiBounty{
			{ID: "other", Project: "Other", IsPaused: false},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.ImmunefiConfig{APIUrl: server.URL}
	p := NewImmunefi(cfg, utils.NewLogger("", true))

	_, err := p.GetProgram(context.Background(), "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestImmunefi_FetchScope_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/bounty/test-prog", r.URL.Path)
		resp := struct {
			PageProps struct {
				Bounty struct {
					Assets []immunefiAsset `json:"assets"`
				} `json:"bounty"`
			} `json:"pageProps"`
		}{}
		resp.PageProps.Bounty.Assets = []immunefiAsset{
			{Target: "https://app.example.com", Type: "web"},
			{Target: "0x1234...abcd", Type: "smart_contract"},
			{Target: "https://github.com/example/repo", Type: "github"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.ImmunefiConfig{APIUrl: server.URL}
	p := NewImmunefi(cfg, utils.NewLogger("", true))

	scope, err := p.FetchScope(context.Background(), "test-prog")
	assert.NoError(t, err)
	assert.NotNil(t, scope)
	assert.Len(t, scope.InScope, 3)

	// Check asset type mapping
	assert.Equal(t, models.AssetTypeURL, scope.InScope[0].Type)
	assert.Equal(t, models.AssetTypeSmartContract, scope.InScope[1].Type)
	assert.Equal(t, models.AssetTypeRepository, scope.InScope[2].Type)
}

func TestImmunefi_FetchScope_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Use a direct struct construction with MaxAttempts: 1 to avoid slow retries
	p := newTestImmunefi(server.URL)

	_, err := p.FetchScope(context.Background(), "missing")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 404")
}

func TestImmunefiAssetType(t *testing.T) {
	tests := []struct {
		input string
		want  models.AssetType
	}{
		{"smart_contract", models.AssetTypeSmartContract},
		{"smart contract", models.AssetTypeSmartContract},
		{"web", models.AssetTypeURL},
		{"website", models.AssetTypeURL},
		{"websites_and_applications", models.AssetTypeURL},
		{"blockchain_dlt", models.AssetTypeOther},
		{"blockchain", models.AssetTypeOther},
		{"github", models.AssetTypeRepository},
		{"repository", models.AssetTypeRepository},
		{"unknown_type", models.AssetTypeOther},
		{"", models.AssetTypeOther},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := immunefiAssetType(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestImmunefi_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response — context should cancel before we respond
		<-r.Context().Done()
	}))
	defer server.Close()

	cfg := config.ImmunefiConfig{APIUrl: server.URL}
	p := NewImmunefi(cfg, utils.NewLogger("", true))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := p.ListPrograms(ctx)
	assert.Error(t, err)
}
