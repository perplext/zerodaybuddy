package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

func TestNewScannerFactory(t *testing.T) {
	cfg := config.Config{
		Tools: config.ToolsConfig{
			MaxThreads:       10,
			DefaultRateLimit: 10,
		},
	}
	logger := utils.NewLogger("", true)

	factory := NewScannerFactory(cfg, logger)

	assert.NotNil(t, factory)
	assert.NotNil(t, factory.all)
	assert.Greater(t, len(factory.all), 0)
	assert.Equal(t, cfg, factory.config)
	assert.Equal(t, logger, factory.logger)
}

func TestScannerFactory_GetScanner(t *testing.T) {
	cfg := config.Config{
		Tools: config.ToolsConfig{
			MaxThreads:       10,
			DefaultRateLimit: 10,
		},
	}
	logger := utils.NewLogger("", true)
	factory := NewScannerFactory(cfg, logger)

	tests := []struct {
		name        string
		scannerName string
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "Get existing scanner - subfinder",
			scannerName: "subfinder",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - httpx",
			scannerName: "httpx",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - amass",
			scannerName: "amass",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - naabu",
			scannerName: "naabu",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - ffuf",
			scannerName: "ffuf",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - katana",
			scannerName: "katana",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - wayback",
			scannerName: "waybackurls",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - nuclei",
			scannerName: "nuclei",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - trivy",
			scannerName: "trivy",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - gitleaks",
			scannerName: "gitleaks",
			wantErr:     false,
		},
		{
			name:        "Get non-existing scanner",
			scannerName: "nonexistent",
			wantErr:     true,
			errMsg:      "scanner 'nonexistent' not found",
		},
		{
			name:        "Get with empty name",
			scannerName: "",
			wantErr:     true,
			errMsg:      "scanner '' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := factory.GetScanner(tt.scannerName)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, scanner)
				if tt.errMsg != "" {
					assert.Equal(t, tt.errMsg, err.Error())
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, scanner)
				assert.Equal(t, tt.scannerName, scanner.Name())
			}
		})
	}
}

func TestScannerFactory_ListScanners(t *testing.T) {
	cfg := config.Config{
		Tools: config.ToolsConfig{
			MaxThreads:       10,
			DefaultRateLimit: 10,
		},
	}
	logger := utils.NewLogger("", true)
	factory := NewScannerFactory(cfg, logger)

	scanners := factory.ListScanners()

	assert.NotEmpty(t, scanners)
	assert.Equal(t, 10, len(scanners))

	// Check that we have all expected scanners
	expectedScanners := []string{
		"subfinder",
		"amass",
		"httpx",
		"naabu",
		"katana",
		"waybackurls",
		"ffuf",
		"nuclei",
		"trivy",
		"gitleaks",
	}

	scannerNames := make(map[string]bool)
	for _, scanner := range scanners {
		scannerNames[scanner.Name()] = true
	}

	for _, expected := range expectedScanners {
		assert.True(t, scannerNames[expected], "Expected scanner %s not found", expected)
	}
}

func TestScannerFactory_GetScannersByType(t *testing.T) {
	cfg := config.Config{
		Tools: config.ToolsConfig{
			MaxThreads:       10,
			DefaultRateLimit: 10,
		},
	}
	logger := utils.NewLogger("", true)
	factory := NewScannerFactory(cfg, logger)

	tests := []struct {
		name         string
		scannerType  string
		expectedList []string
		count        int
	}{
		{
			name:         "Get subdomain scanners",
			scannerType:  "subdomain",
			expectedList: []string{"subfinder", "amass"},
			count:        2,
		},
		{
			name:         "Get http scanners",
			scannerType:  "http",
			expectedList: []string{"httpx"},
			count:        1,
		},
		{
			name:         "Get port scanners",
			scannerType:  "port",
			expectedList: []string{"naabu"},
			count:        1,
		},
		{
			name:         "Get content scanners",
			scannerType:  "content",
			expectedList: []string{"ffuf", "katana", "waybackurls"},
			count:        3,
		},
		{
			name:         "Get vulnerability scanners",
			scannerType:  "vulnerability",
			expectedList: []string{"nuclei", "trivy", "gitleaks"},
			count:        3,
		},
		{
			name:         "Get non-existing type",
			scannerType:  "nonexistent",
			expectedList: []string{},
			count:        0,
		},
		{
			name:         "Get empty type",
			scannerType:  "",
			expectedList: []string{},
			count:        0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanners := factory.GetScannersByType(tt.scannerType)

			assert.Equal(t, tt.count, len(scanners))

			// Check that expected scanners are present
			scannerNames := make(map[string]bool)
			for _, scanner := range scanners {
				scannerNames[scanner.Name()] = true
			}

			for _, expected := range tt.expectedList {
				assert.True(t, scannerNames[expected], "Expected scanner %s not found for type %s", expected, tt.scannerType)
			}
		})
	}
}

func TestScannerRegistry_AutoCategorization(t *testing.T) {
	cfg := config.Config{
		Tools: config.ToolsConfig{
			MaxThreads:       10,
			DefaultRateLimit: 10,
		},
	}
	logger := utils.NewLogger("", true)
	registry := NewScannerRegistry(cfg, logger)

	// Verify typed accessor methods return the correct scanners
	subScanners := registry.SubdomainScanners()
	assert.Len(t, subScanners, 2, "Expected 2 subdomain scanners")

	probers := registry.HostProbers()
	assert.Len(t, probers, 1, "Expected 1 host prober")

	portScanners := registry.PortScanners()
	assert.Len(t, portScanners, 1, "Expected 1 port scanner")

	epScanners := registry.EndpointDiscoverers()
	assert.Len(t, epScanners, 3, "Expected 3 endpoint discoverers")

	vulnScanners := registry.VulnerabilityScanners()
	assert.Len(t, vulnScanners, 3, "Expected 3 vulnerability scanners")
}

func TestScannerFactory_registerScanners(t *testing.T) {
	cfg := config.Config{
		Tools: config.ToolsConfig{
			MaxThreads:       10,
			DefaultRateLimit: 10,
		},
	}
	logger := utils.NewLogger("", true)

	// Create registry without registering scanners
	registry := &ScannerRegistry{
		config: cfg,
		logger: logger,
		all:    make(map[string]Scanner),
	}

	// Verify no scanners initially
	assert.Empty(t, registry.all)

	// Register scanners
	registry.registerDefaults()

	// Verify all scanners are registered
	assert.Len(t, registry.all, 10)

	// Check specific scanners
	expectedScanners := map[string]bool{
		"subfinder":   true,
		"amass":       true,
		"httpx":       true,
		"naabu":       true,
		"ffuf":        true,
		"katana":      true,
		"waybackurls": true,
		"nuclei":      true,
		"trivy":       true,
		"gitleaks":    true,
	}

	for name := range expectedScanners {
		scanner, err := registry.GetScanner(name)
		assert.NoError(t, err)
		assert.NotNil(t, scanner)
		assert.Equal(t, name, scanner.Name())
	}
}
