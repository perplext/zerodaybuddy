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
	assert.NotNil(t, factory.scanners)
	assert.Greater(t, len(factory.scanners), 0)
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
			scannerName: "wayback",
			wantErr:     false,
		},
		{
			name:        "Get existing scanner - nuclei",
			scannerName: "nuclei",
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
	assert.Equal(t, 8, len(scanners)) // We expect 8 scanners based on registerScanners()
	
	// Check that we have all expected scanners
	expectedScanners := []string{
		"subfinder",
		"amass",
		"httpx",
		"naabu",
		"katana",
		"wayback",
		"ffuf",
		"nuclei",
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
			expectedList: []string{"ffuf"},
			count:        1,
		},
		{
			name:         "Get vulnerability scanners",
			scannerType:  "vulnerability",
			expectedList: []string{"nuclei"},
			count:        1,
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

func TestScannerFactory_registerScanners(t *testing.T) {
	cfg := config.Config{
		Tools: config.ToolsConfig{
			MaxThreads:       10,
			DefaultRateLimit: 10,
		},
	}
	logger := utils.NewLogger("", true)
	
	// Create factory without registering scanners
	factory := &ScannerFactory{
		config:   cfg,
		logger:   logger,
		scanners: make(map[string]Scanner),
	}
	
	// Verify no scanners initially
	assert.Empty(t, factory.scanners)
	
	// Register scanners
	factory.registerScanners()
	
	// Verify all scanners are registered
	assert.Len(t, factory.scanners, 8)
	
	// Check specific scanners
	expectedScanners := map[string]bool{
		"subfinder": true,
		"amass":     true,
		"httpx":     true,
		"naabu":     true,
		"ffuf":      true,
		"katana":    true,
		"wayback":   true,
		"nuclei":    true,
	}
	
	for name := range expectedScanners {
		scanner, err := factory.GetScanner(name)
		assert.NoError(t, err)
		assert.NotNil(t, scanner)
		assert.Equal(t, name, scanner.Name())
	}
}