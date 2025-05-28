package scan

import (
	"context"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/internal/recon"
	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStore is a mock implementation of the store interface
type MockStore struct {
	mock.Mock
}

func (m *MockStore) GetProject(ctx context.Context, id string) (*models.Project, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Project), args.Error(1)
}

func (m *MockStore) GetHost(ctx context.Context, id string) (*models.Host, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Host), args.Error(1)
}

func (m *MockStore) GetEndpoint(ctx context.Context, id string) (*models.Endpoint, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Endpoint), args.Error(1)
}

func (m *MockStore) ListHosts(ctx context.Context, projectID string) ([]*models.Host, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Host), args.Error(1)
}

func (m *MockStore) ListEndpoints(ctx context.Context, projectID string) ([]*models.Endpoint, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Endpoint), args.Error(1)
}

func (m *MockStore) CreateFinding(ctx context.Context, finding *models.Finding) error {
	args := m.Called(ctx, finding)
	return args.Error(0)
}

func (m *MockStore) CreateTask(ctx context.Context, task *models.Task) error {
	args := m.Called(ctx, task)
	return args.Error(0)
}

func (m *MockStore) UpdateTask(ctx context.Context, task *models.Task) error {
	args := m.Called(ctx, task)
	return args.Error(0)
}

// MockScanner is a mock implementation of the Scanner interface
type MockScanner struct {
	mock.Mock
}

func (m *MockScanner) Name() string {
	return "nuclei"
}

func (m *MockScanner) Description() string {
	return "Mock nuclei scanner"
}

func (m *MockScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	args := m.Called(ctx, project, target, options)
	return args.Get(0), args.Error(1)
}

func TestScanService_ScanTarget(t *testing.T) {
	tests := []struct {
		name      string
		projectID string
		target    string
		concurrency int
		setupMocks func(*MockStore, *MockScanner)
		expectError bool
		errorMsg   string
	}{
		{
			name:      "invalid project ID",
			projectID: "",
			target:    "all",
			concurrency: 10,
			setupMocks: func(ms *MockStore, scanner *MockScanner) {},
			expectError: true,
			errorMsg:   "project ID is required",
		},
		{
			name:      "invalid concurrency",
			projectID: "550e8400-e29b-41d4-a716-446655440000",
			target:    "all",
			concurrency: -1,
			setupMocks: func(ms *MockStore, scanner *MockScanner) {},
			expectError: true,
			errorMsg:   "concurrency must be between 1 and 100",
		},
		{
			name:      "scan all endpoints successfully",
			projectID: "550e8400-e29b-41d4-a716-446655440000",
			target:    "all",
			concurrency: 10,
			setupMocks: func(ms *MockStore, scanner *MockScanner) {
				project := &models.Project{
					ID:   "550e8400-e29b-41d4-a716-446655440000",
					Name: "Test Project",
					Scope: models.Scope{
						InScope: []models.Asset{
							{Type: models.AssetTypeDomain, Value: "example.com"},
						},
					},
				}
				
				ms.On("GetProject", mock.Anything, "550e8400-e29b-41d4-a716-446655440000").Return(project, nil)
				ms.On("CreateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				ms.On("UpdateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				
				endpoints := []*models.Endpoint{
					{
						ID:        "endpoint1",
						ProjectID: project.ID,
						HostID:    "host1",
						URL:       "https://example.com:443/",
					},
					{
						ID:        "endpoint2",
						ProjectID: project.ID,
						HostID:    "host1",
						URL:       "http://example.com:80/api",
					},
				}
				ms.On("ListEndpoints", mock.Anything, project.ID).Return(endpoints, nil)
				
				// Mock nuclei results
				nucleiResults := []recon.NucleiResult{
					{
						TemplateID: "tech-detect",
						Info: recon.NucleiResultInfo{
							Name:        "Technology Detection",
							Description: "Detects various technologies",
							Severity:    "info",
						},
						Host:      "https://example.com:443/",
						Severity:  "info",
						Timestamp: time.Now().Format(time.RFC3339),
					},
				}
				
				// Scanner will be called with the URLs
				scanner.On("Scan", mock.Anything, project, mock.AnythingOfType("[]string"), mock.Anything).Return(nucleiResults, nil)
				
				// Expect finding to be created
				ms.On("CreateFinding", mock.Anything, mock.AnythingOfType("*models.Finding")).Return(nil)
			},
			expectError: false,
		},
		{
			name:      "scan specific host",
			projectID: "550e8400-e29b-41d4-a716-446655440000",
			target:    "host:host123",
			concurrency: 5,
			setupMocks: func(ms *MockStore, scanner *MockScanner) {
				project := &models.Project{
					ID:   "550e8400-e29b-41d4-a716-446655440000",
					Name: "Test Project",
					Scope: models.Scope{
						InScope: []models.Asset{
							{Type: models.AssetTypeDomain, Value: "example.com"},
						},
					},
				}
				
				host := &models.Host{
					ID:        "host123",
					ProjectID: project.ID,
					Value:     "example.com",
				}
				
				ms.On("GetProject", mock.Anything, "550e8400-e29b-41d4-a716-446655440000").Return(project, nil)
				ms.On("CreateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				ms.On("UpdateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				ms.On("GetHost", mock.Anything, "host123").Return(host, nil)
				
				endpoints := []*models.Endpoint{
					{
						ID:        "endpoint1",
						ProjectID: project.ID,
						HostID:    "host123",
						URL:       "https://example.com:443/",
					},
				}
				ms.On("ListEndpoints", mock.Anything, project.ID).Return(endpoints, nil)
				
				scanner.On("Scan", mock.Anything, project, []string{"https://example.com:443/"}, mock.Anything).Return([]recon.NucleiResult{}, nil)
			},
			expectError: false,
		},
		{
			name:      "scan specific URL",
			projectID: "550e8400-e29b-41d4-a716-446655440000",
			target:    "https://example.com/test",
			concurrency: 1,
			setupMocks: func(ms *MockStore, scanner *MockScanner) {
				project := &models.Project{
					ID:   "550e8400-e29b-41d4-a716-446655440000",
					Name: "Test Project",
					Scope: models.Scope{
						InScope: []models.Asset{
							{Type: models.AssetTypeDomain, Value: "example.com"},
						},
					},
				}
				
				ms.On("GetProject", mock.Anything, "550e8400-e29b-41d4-a716-446655440000").Return(project, nil)
				ms.On("CreateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				ms.On("UpdateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				
				scanner.On("Scan", mock.Anything, project, []string{"https://example.com/test"}, mock.Anything).Return([]recon.NucleiResult{}, nil)
			},
			expectError: false,
		},
		{
			name:      "URL not in scope",
			projectID: "550e8400-e29b-41d4-a716-446655440000",
			target:    "https://notinscope.com",
			concurrency: 1,
			setupMocks: func(ms *MockStore, scanner *MockScanner) {
				project := &models.Project{
					ID:   "550e8400-e29b-41d4-a716-446655440000",
					Name: "Test Project",
					Scope: models.Scope{
						InScope: []models.Asset{
							{Type: models.AssetTypeDomain, Value: "example.com"},
						},
					},
				}
				
				ms.On("GetProject", mock.Anything, "550e8400-e29b-41d4-a716-446655440000").Return(project, nil)
				ms.On("CreateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				ms.On("UpdateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
			},
			expectError: true,
			errorMsg:   "not in project scope",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := new(MockStore)
			mockScanner := new(MockScanner)
			logger := utils.NewLogger("test", false)
			
			// Create a mock scanner factory
			service := &Service{
				store:  mockStore,
				config: config.Config{},
				logger: logger,
				scannerFactory: &recon.ScannerFactory{},
			}
			
			// Override the scanner factory to return our mock
			service.scannerFactory = &recon.ScannerFactory{}
			
			// Setup mocks
			tt.setupMocks(mockStore, mockScanner)
			
			// For tests that use the scanner, we need to mock the factory
			if tt.name == "scan all endpoints successfully" || tt.name == "scan specific host" || tt.name == "scan specific URL" {
				// Create a custom service with mock scanner
				service = &Service{
					store:  mockStore,
					config: config.Config{},
					logger: logger,
					scannerFactory: &mockScannerFactory{scanner: mockScanner},
				}
			}
			
			// Run the test
			err := service.ScanTarget(context.Background(), tt.projectID, tt.target, tt.concurrency)
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
			
			mockStore.AssertExpectations(t)
			mockScanner.AssertExpectations(t)
		})
	}
}

// mockScannerFactory is a test scanner factory that returns our mock scanner
type mockScannerFactory struct {
	scanner recon.Scanner
}

func (f *mockScannerFactory) GetScanner(name string) (recon.Scanner, error) {
	return f.scanner, nil
}

func (f *mockScannerFactory) GetScannerByType(scanType string) (recon.Scanner, error) {
	return f.scanner, nil
}

func (f *mockScannerFactory) ListScanners() []string {
	return []string{"nuclei"}
}

func TestScanService_ProcessFinding(t *testing.T) {
	mockStore := new(MockStore)
	logger := utils.NewLogger("test", false)
	
	service := &Service{
		store:  mockStore,
		config: config.Config{},
		logger: logger,
	}
	
	project := &models.Project{
		ID: "test-project",
	}
	
	nucleiResult := recon.NucleiResult{
		TemplateID: "cve-2021-44228",
		Info: recon.NucleiResultInfo{
			Name:        "Log4j Remote Code Execution",
			Description: "Apache Log4j2 <=2.14.1 JNDI features used in configuration",
			Severity:    "critical",
			Authors:     []string{"author1", "author2"},
			Tags:        []string{"cve", "log4j", "rce"},
			Reference:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
			Classification: struct {
				CVEIDs    []string `json:"cve-id,omitempty"`
				CVSSScore string   `json:"cvss-score,omitempty"`
				CVE       string   `json:"cve,omitempty"`
			}{
				CVEIDs:    []string{"CVE-2021-44228"},
				CVSSScore: "10.0",
			},
		},
		Host:         "https://example.com",
		Severity:     "critical",
		MatcherName:  "status",
		MatchedAt:    "https://example.com/api/v1/test",
		CurlCommand:  "curl -X GET https://example.com/api/v1/test",
		Timestamp:    time.Now().Format(time.RFC3339),
	}
	
	// Expect CreateFinding to be called with correct data
	mockStore.On("CreateFinding", mock.Anything, mock.MatchedBy(func(f *models.Finding) bool {
		return f.ProjectID == project.ID &&
			f.Type == models.FindingTypeVulnerability &&
			f.Title == "Log4j Remote Code Execution" &&
			f.Severity == models.SeverityCritical &&
			f.URL == "https://example.com" &&
			f.FoundBy == "nuclei"
	})).Return(nil)
	
	err := service.processFinding(context.Background(), project, nucleiResult)
	assert.NoError(t, err)
	
	mockStore.AssertExpectations(t)
}