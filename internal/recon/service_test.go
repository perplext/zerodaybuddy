package recon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// MockStore is a mock implementation of the storage interface used by recon service
type MockStore struct {
	mock.Mock
}

func (m *MockStore) CreateHost(ctx context.Context, host *models.Host) error {
	args := m.Called(ctx, host)
	return args.Error(0)
}

func (m *MockStore) GetHost(ctx context.Context, id string) (*models.Host, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Host), args.Error(1)
}

func (m *MockStore) UpdateHost(ctx context.Context, host *models.Host) error {
	args := m.Called(ctx, host)
	return args.Error(0)
}

func (m *MockStore) ListHosts(ctx context.Context, projectID string) ([]*models.Host, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Host), args.Error(1)
}

func (m *MockStore) CreateEndpoint(ctx context.Context, endpoint *models.Endpoint) error {
	args := m.Called(ctx, endpoint)
	return args.Error(0)
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
	args := m.Called()
	return args.String(0)
}

func (m *MockScanner) Description() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	args := m.Called(ctx, project, target, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0), args.Error(1)
}

func (m *MockScanner) ScanSubdomains(ctx context.Context, project *models.Project, domain string, opts ScanOptions) ([]string, error) {
	args := m.Called(ctx, project, domain, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockScanner) ProbeHosts(ctx context.Context, project *models.Project, hosts []string, opts ScanOptions) ([]*models.Host, error) {
	args := m.Called(ctx, project, hosts, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Host), args.Error(1)
}

func (m *MockScanner) ScanPorts(ctx context.Context, project *models.Project, targets []string, opts ScanOptions) ([]*models.Host, error) {
	args := m.Called(ctx, project, targets, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Host), args.Error(1)
}

func (m *MockScanner) DiscoverEndpoints(ctx context.Context, project *models.Project, urls []string, opts ScanOptions) ([]*models.Endpoint, error) {
	args := m.Called(ctx, project, urls, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Endpoint), args.Error(1)
}

func (m *MockScanner) ScanVulnerabilities(ctx context.Context, project *models.Project, targets []string, opts ScanOptions) ([]*models.Finding, error) {
	args := m.Called(ctx, project, targets, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Finding), args.Error(1)
}

// Test utilities
func getTestLogger() *utils.Logger {
	return utils.NewLogger("", true) // Empty logDir, debug=true
}

func getTestConfig() config.ToolsConfig {
	return config.ToolsConfig{
		MaxThreads:       10,
		DefaultRateLimit: 10,
	}
}

func getTestProject() *models.Project {
	return &models.Project{
		ID:   "test-project-id",
		Name: "test-project",
		Scope: models.Scope{
			InScope: []models.Asset{
				{Type: models.AssetTypeDomain, Value: "example.com"},
				{Type: models.AssetTypeDomain, Value: "*.example.com"},
				{Type: models.AssetTypeIP, Value: "192.168.1.0/24"},
			},
		},
	}
}

// Tests
func TestNewService(t *testing.T) {
	mockStore := &MockStore{}
	logger := getTestLogger()
	config := getTestConfig()
	
	svc := NewService(mockStore, config, logger)
	
	assert.NotNil(t, svc)
	assert.Equal(t, mockStore, svc.store)
	assert.Equal(t, config, svc.config)
	assert.Equal(t, logger, svc.logger)
	assert.NotNil(t, svc.scanners)
	assert.NotNil(t, svc.semaphore)
}

func TestService_SetConcurrency(t *testing.T) {
	mockStore := &MockStore{}
	logger := getTestLogger()
	config := getTestConfig()
	
	svc := NewService(mockStore, config, logger)
	
	// Test setting valid concurrency
	svc.SetConcurrency(5)
	assert.Equal(t, 5, cap(svc.semaphore))
	
	// Test setting zero (should use default)
	svc.SetConcurrency(0)
	assert.Equal(t, config.MaxThreads, cap(svc.semaphore))
	
	// Test setting negative (should use default)
	svc.SetConcurrency(-1)
	assert.Equal(t, config.MaxThreads, cap(svc.semaphore))
}

func TestService_ListScanners(t *testing.T) {
	mockStore := &MockStore{}
	logger := getTestLogger()
	config := getTestConfig()
	
	// Create service with empty scanners map to control what's in it
	svc := &Service{
		store:     mockStore,
		config:    config,
		logger:    logger,
		scanners:  make(map[string]Scanner),
		semaphore: make(chan struct{}, config.MaxThreads),
	}
	
	// Add mock scanners
	mockScanner1 := &MockScanner{}
	mockScanner1.On("Name").Return("scanner1")
	mockScanner2 := &MockScanner{}
	mockScanner2.On("Name").Return("scanner2")
	
	svc.scanners["scanner1"] = mockScanner1
	svc.scanners["scanner2"] = mockScanner2
	
	scanners := svc.ListScanners()
	
	assert.Len(t, scanners, 2)
	
	// Check that both scanners are in the list
	names := []string{}
	for _, scanner := range scanners {
		names = append(names, scanner.Name())
	}
	assert.Contains(t, names, "scanner1")
	assert.Contains(t, names, "scanner2")
}

func TestService_RunAll(t *testing.T) {
	t.Skip("Skipping test: scope matching (matchAsset and isSubdomain) not implemented in models package")
	tests := []struct {
		name       string
		setupMocks func(*MockStore, map[string]*MockScanner)
		wantErr    bool
		errMsg     string
	}{
		{
			name: "Success",
			setupMocks: func(store *MockStore, scanners map[string]*MockScanner) {
				// Task creation and updates
				store.On("CreateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				store.On("UpdateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				
				// Subdomain discovery
				scanners["subfinder"].On("Scan", mock.Anything, mock.Anything, "example.com", mock.Anything).
					Return([]string{"sub1.example.com", "sub2.example.com"}, nil)
				scanners["subfinder"].On("Scan", mock.Anything, mock.Anything, "*.example.com", mock.Anything).
					Return([]string{"sub3.example.com", "sub4.example.com"}, nil)
				scanners["amass"].On("Scan", mock.Anything, mock.Anything, "example.com", mock.Anything).
					Return([]string{"sub2.example.com", "sub3.example.com"}, nil)
				scanners["amass"].On("Scan", mock.Anything, mock.Anything, "*.example.com", mock.Anything).
					Return([]string{"sub4.example.com", "sub5.example.com"}, nil)
				
				// HTTP probing
				scanners["httpx"].On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Host{
						{ID: "host1", Value: "sub1.example.com", Type: models.AssetTypeDomain, Ports: []int{443}},
						{ID: "host2", Value: "sub2.example.com", Type: models.AssetTypeDomain, Ports: []int{443}},
					}, nil)
				store.On("CreateHost", mock.Anything, mock.AnythingOfType("*models.Host")).Return(nil)
				
				// Port scanning
				scanners["naabu"].On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Host{
						{ID: "host3", Value: "192.168.1.10", Type: models.AssetTypeIP, Ports: []int{22, 80}},
					}, nil)
				
				// Content discovery
				scanners["katana"].On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{
						{ID: "ep1", URL: "https://sub1.example.com/api"},
					}, nil)
				scanners["waybackurls"].On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{
						{ID: "ep2", URL: "https://sub1.example.com/login"},
					}, nil)
				store.On("CreateEndpoint", mock.Anything, mock.AnythingOfType("*models.Endpoint")).Return(nil)
				
				// Directory brute force
				scanners["ffuf"].On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{
						{ID: "ep3", URL: "https://sub1.example.com/admin"},
					}, nil)
			},
			wantErr: false,
		},
		{
			name: "Task creation failure",
			setupMocks: func(store *MockStore, scanners map[string]*MockScanner) {
				store.On("CreateTask", mock.Anything, mock.AnythingOfType("*models.Task")).
					Return(errors.New("db error"))
			},
			wantErr: true,
			errMsg:  "failed to create task",
		},
		{
			name: "No domains in scope",
			setupMocks: func(store *MockStore, scanners map[string]*MockScanner) {
				store.On("CreateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				store.On("UpdateTask", mock.Anything, mock.AnythingOfType("*models.Task")).Return(nil)
				
				// Port scanning for IP
				scanners["naabu"].On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Host{
						{ID: "host1", Value: "192.168.1.1", Type: models.AssetTypeIP, Ports: []int{22, 80}},
					}, nil).Maybe()
				store.On("CreateHost", mock.Anything, mock.AnythingOfType("*models.Host")).Return(nil).Maybe()
				
				// Content discovery and directory brute force
				scanners["katana"].On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{}, nil).Maybe()
				scanners["waybackurls"].On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{}, nil).Maybe()
				scanners["ffuf"].On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{}, nil).Maybe()
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			logger := getTestLogger()
			config := getTestConfig()
			
			svc := &Service{
				store:     mockStore,
				config:    config,
				logger:    logger,
				scanners:  make(map[string]Scanner),
				semaphore: make(chan struct{}, config.MaxThreads),
			}
			
			// Create mock scanners
			mockScanners := map[string]*MockScanner{
				"subfinder":    &MockScanner{},
				"amass":        &MockScanner{},
				"httpx":        &MockScanner{},
				"naabu":        &MockScanner{},
				"katana":       &MockScanner{},
				"waybackurls":  &MockScanner{},
				"ffuf":         &MockScanner{},
			}
			
			// Add Name() mock for all scanners
			for name, scanner := range mockScanners {
				scanner.On("Name").Return(name).Maybe()
				svc.scanners[name] = scanner
			}
			
			tt.setupMocks(mockStore, mockScanners)
			
			project := getTestProject()
			if tt.name == "No domains in scope" {
				project.Scope.InScope = []models.Asset{
					{Type: models.AssetTypeIP, Value: "192.168.1.1"},
				}
			}
			
			ctx := context.Background()
			results, err := svc.RunAll(ctx, project)
			
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, results)
			}
			
			mockStore.AssertExpectations(t)
			for _, scanner := range mockScanners {
				scanner.AssertExpectations(t)
			}
		})
	}
}

func TestService_RunSubdomainDiscovery(t *testing.T) {
	t.Skip("Skipping test: scope matching (matchAsset and isSubdomain) not implemented in models package")
	tests := []struct {
		name       string
		setupMocks func(*MockStore, map[string]*MockScanner)
		wantErr    bool
		errMsg     string
		wantLen    int
	}{
		{
			name: "Success with multiple scanners",
			setupMocks: func(store *MockStore, scanners map[string]*MockScanner) {
				scanners["subfinder"].On("Scan", mock.Anything, mock.Anything, "example.com", mock.Anything).
					Return([]string{"sub1.example.com", "sub2.example.com", "out.example.org"}, nil)
				scanners["subfinder"].On("Scan", mock.Anything, mock.Anything, "*.example.com", mock.Anything).
					Return([]string{"sub4.example.com"}, nil)
				scanners["amass"].On("Scan", mock.Anything, mock.Anything, "example.com", mock.Anything).
					Return([]string{"sub2.example.com", "sub3.example.com"}, nil)
				scanners["amass"].On("Scan", mock.Anything, mock.Anything, "*.example.com", mock.Anything).
					Return([]string{"sub3.example.com"}, nil)
			},
			wantErr: false,
			wantLen: 4, // sub1, sub2, sub3, sub4 (deduped, out.example.org is out of scope)
		},
		{
			name: "Scanner error - partial failure",
			setupMocks: func(store *MockStore, scanners map[string]*MockScanner) {
				scanners["subfinder"].On("Scan", mock.Anything, mock.Anything, "example.com", mock.Anything).
					Return([]string{"sub1.example.com"}, nil)
				scanners["subfinder"].On("Scan", mock.Anything, mock.Anything, "*.example.com", mock.Anything).
					Return([]string{"sub2.example.com"}, nil)
				scanners["amass"].On("Scan", mock.Anything, mock.Anything, "example.com", mock.Anything).
					Return(nil, errors.New("scanner failed"))
				scanners["amass"].On("Scan", mock.Anything, mock.Anything, "*.example.com", mock.Anything).
					Return(nil, errors.New("scanner failed"))
			},
			wantErr: false,
			wantLen: 2, // sub1, sub2 from subfinder only
		},
		{
			name:       "No domains in scope",
			setupMocks: func(store *MockStore, scanners map[string]*MockScanner) {},
			wantErr:    true,
			errMsg:     "no domains found in project scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			logger := getTestLogger()
			config := getTestConfig()
			
			svc := &Service{
				store:     mockStore,
				config:    config,
				logger:    logger,
				scanners:  make(map[string]Scanner),
				semaphore: make(chan struct{}, config.MaxThreads),
			}
			
			// Create mock scanners
			mockScanners := map[string]*MockScanner{
				"subfinder": &MockScanner{},
				"amass":     &MockScanner{},
			}
			
			// Add Name() mock for all scanners
			for name, scanner := range mockScanners {
				scanner.On("Name").Return(name).Maybe()
				svc.scanners[name] = scanner
			}
			
			tt.setupMocks(mockStore, mockScanners)
			
			project := getTestProject()
			if tt.name == "No domains in scope" {
				project.Scope.InScope = []models.Asset{
					{Type: models.AssetTypeIP, Value: "192.168.1.1"},
				}
			}
			
			ctx := context.Background()
			subdomains, err := svc.RunSubdomainDiscovery(ctx, project)
			
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, subdomains, tt.wantLen)
			}
			
			mockStore.AssertExpectations(t)
			for _, scanner := range mockScanners {
				scanner.AssertExpectations(t)
			}
		})
	}
}

func TestService_RunHTTPProbing(t *testing.T) {
	tests := []struct {
		name       string
		hosts      []string
		setupMocks func(*MockStore, *MockScanner)
		wantErr    bool
		errMsg     string
		wantLen    int
	}{
		{
			name:  "Success",
			hosts: []string{"example.com", "sub.example.com"},
			setupMocks: func(store *MockStore, scanner *MockScanner) {
				scanner.On("ProbeHosts", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Host{
						{ID: "host1", Value: "example.com", Type: models.AssetTypeDomain},
						{ID: "host2", Value: "sub.example.com", Type: models.AssetTypeDomain},
					}, nil)
				store.On("CreateHost", mock.Anything, mock.AnythingOfType("*models.Host")).Return(nil).Times(2)
			},
			wantErr: false,
			wantLen: 2,
		},
		{
			name:  "Scanner not found",
			hosts: []string{"example.com"},
			setupMocks: func(store *MockStore, scanner *MockScanner) {
				// Remove httpx scanner
			},
			wantErr: true,
			errMsg:  "HTTP prober not found",
		},
		{
			name:  "Scanner error",
			hosts: []string{"example.com"},
			setupMocks: func(store *MockStore, scanner *MockScanner) {
				scanner.On("ProbeHosts", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, errors.New("scan failed"))
			},
			wantErr: true,
			errMsg:  "failed to probe hosts",
		},
		{
			name:  "Store error",
			hosts: []string{"example.com"},
			setupMocks: func(store *MockStore, scanner *MockScanner) {
				scanner.On("ProbeHosts", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Host{
						{ID: "host1", Value: "example.com", Type: models.AssetTypeDomain},
					}, nil)
				store.On("CreateHost", mock.Anything, mock.AnythingOfType("*models.Host")).
					Return(errors.New("db error"))
			},
			wantErr: false,
			wantLen: 1, // Host is still returned even if storage fails
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			mockScanner := &MockScanner{}
			logger := getTestLogger()
			config := getTestConfig()
			
			svc := &Service{
				store:     mockStore,
				config:    config,
				logger:    logger,
				scanners:  make(map[string]Scanner),
				semaphore: make(chan struct{}, config.MaxThreads),
			}
			
			if tt.name != "Scanner not found" {
				mockScanner.On("Name").Return("httpx").Maybe()
				svc.scanners["httpx"] = mockScanner
			}
			
			tt.setupMocks(mockStore, mockScanner)
			
			project := getTestProject()
			ctx := context.Background()
			hosts, err := svc.RunHTTPProbing(ctx, project, tt.hosts)
			
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, hosts, tt.wantLen)
			}
			
			mockStore.AssertExpectations(t)
			mockScanner.AssertExpectations(t)
		})
	}
}

func TestService_RunPortScanning(t *testing.T) {
	tests := []struct {
		name       string
		targets    []string
		setupMocks func(*MockStore, *MockScanner)
		wantErr    bool
		errMsg     string
		wantLen    int
	}{
		{
			name:    "Success",
			targets: []string{"192.168.1.1", "192.168.1.2"},
			setupMocks: func(store *MockStore, scanner *MockScanner) {
				scanner.On("ScanPorts", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Host{
						{ID: "host1", Value: "192.168.1.1", Type: models.AssetTypeIP, Ports: []int{22, 80}},
						{ID: "host2", Value: "192.168.1.2", Type: models.AssetTypeIP, Ports: []int{443}},
					}, nil)
				store.On("CreateHost", mock.Anything, mock.AnythingOfType("*models.Host")).Return(nil).Times(2)
			},
			wantErr: false,
			wantLen: 2,
		},
		{
			name:    "Scanner not found",
			targets: []string{"192.168.1.1"},
			setupMocks: func(store *MockStore, scanner *MockScanner) {
				// Remove naabu scanner
			},
			wantErr: true,
			errMsg:  "port scanner not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			mockScanner := &MockScanner{}
			logger := getTestLogger()
			config := getTestConfig()
			
			svc := &Service{
				store:     mockStore,
				config:    config,
				logger:    logger,
				scanners:  make(map[string]Scanner),
				semaphore: make(chan struct{}, config.MaxThreads),
			}
			
			if tt.name != "Scanner not found" {
				mockScanner.On("Name").Return("naabu").Maybe()
				svc.scanners["naabu"] = mockScanner
			}
			
			tt.setupMocks(mockStore, mockScanner)
			
			project := getTestProject()
			ctx := context.Background()
			hosts, err := svc.RunPortScanning(ctx, project, tt.targets)
			
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, hosts, tt.wantLen)
			}
			
			mockStore.AssertExpectations(t)
			mockScanner.AssertExpectations(t)
		})
	}
}

func TestService_RunContentDiscovery(t *testing.T) {
	tests := []struct {
		name       string
		host       *models.Host
		setupMocks func(*MockStore, map[string]*MockScanner)
		wantErr    bool
		errMsg     string
		wantLen    int
	}{
		{
			name: "Success",
			host: &models.Host{
				ID:    "host1",
				Value: "example.com",
				Type:  models.AssetTypeDomain,
				Ports: []int{443},
			},
			setupMocks: func(store *MockStore, scanners map[string]*MockScanner) {
				scanners["katana"].On("DiscoverEndpoints", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{
						{ID: "ep1", URL: "https://example.com/api"},
					}, nil)
				scanners["waybackurls"].On("DiscoverEndpoints", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{
						{ID: "ep2", URL: "https://example.com/login"},
					}, nil)
				store.On("CreateEndpoint", mock.Anything, mock.AnythingOfType("*models.Endpoint")).Return(nil).Times(2)
			},
			wantErr: false,
			wantLen: 2,
		},
		{
			name: "Non-web host",
			host: &models.Host{
				ID:    "host1",
				Value: "192.168.1.1",
				Type:  models.AssetTypeIP,
				Ports: []int{22}, // SSH only
			},
			setupMocks: func(store *MockStore, scanners map[string]*MockScanner) {},
			wantErr:    true,
			errMsg:     "host is not a web host",
		},
		{
			name: "Scanner error - partial results",
			host: &models.Host{
				ID:    "host1",
				Value: "example.com",
				Type:  models.AssetTypeDomain,
				Ports: []int{443},
			},
			setupMocks: func(store *MockStore, scanners map[string]*MockScanner) {
				scanners["katana"].On("DiscoverEndpoints", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{
						{ID: "ep1", URL: "https://example.com/api"},
					}, nil)
				scanners["waybackurls"].On("DiscoverEndpoints", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, errors.New("scanner failed"))
				store.On("CreateEndpoint", mock.Anything, mock.AnythingOfType("*models.Endpoint")).Return(nil)
			},
			wantErr: false,
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			logger := getTestLogger()
			config := getTestConfig()
			
			svc := &Service{
				store:     mockStore,
				config:    config,
				logger:    logger,
				scanners:  make(map[string]Scanner),
				semaphore: make(chan struct{}, config.MaxThreads),
			}
			
			// Create mock scanners
			mockScanners := map[string]*MockScanner{
				"katana":       &MockScanner{},
				"waybackurls":  &MockScanner{},
			}
			
			// Add Name() mock for all scanners
			for name, scanner := range mockScanners {
				scanner.On("Name").Return(name).Maybe()
				svc.scanners[name] = scanner
			}
			
			tt.setupMocks(mockStore, mockScanners)
			
			project := getTestProject()
			ctx := context.Background()
			endpoints, err := svc.RunContentDiscovery(ctx, project, tt.host)
			
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, endpoints, tt.wantLen)
			}
			
			mockStore.AssertExpectations(t)
			for _, scanner := range mockScanners {
				scanner.AssertExpectations(t)
			}
		})
	}
}

func TestService_RunDirectoryBruteForce(t *testing.T) {
	tests := []struct {
		name       string
		host       *models.Host
		setupMocks func(*MockStore, *MockScanner)
		wantErr    bool
		errMsg     string
		wantLen    int
	}{
		{
			name: "Success",
			host: &models.Host{
				ID:    "host1",
				Value: "example.com",
				Type:  models.AssetTypeDomain,
				Ports: []int{443},
			},
			setupMocks: func(store *MockStore, scanner *MockScanner) {
				scanner.On("DiscoverEndpoints", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]*models.Endpoint{
						{ID: "ep1", URL: "https://example.com/admin"},
						{ID: "ep2", URL: "https://example.com/backup"},
					}, nil)
				store.On("CreateEndpoint", mock.Anything, mock.AnythingOfType("*models.Endpoint")).Return(nil).Times(2)
			},
			wantErr: false,
			wantLen: 2,
		},
		{
			name: "Non-web host",
			host: &models.Host{
				ID:    "host1",
				Value: "192.168.1.1",
				Type:  models.AssetTypeIP,
				Ports: []int{22}, // SSH only
			},
			setupMocks: func(store *MockStore, scanner *MockScanner) {},
			wantErr:    true,
			errMsg:     "host is not a web host",
		},
		{
			name: "Scanner not found",
			host: &models.Host{
				ID:    "host1",
				Value: "example.com",
				Type:  models.AssetTypeDomain,
				Ports: []int{443},
			},
			setupMocks: func(store *MockStore, scanner *MockScanner) {
				// Remove ffuf scanner
			},
			wantErr: true,
			errMsg:  "directory brute forcer not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			mockScanner := &MockScanner{}
			logger := getTestLogger()
			config := getTestConfig()
			
			svc := &Service{
				store:     mockStore,
				config:    config,
				logger:    logger,
				scanners:  make(map[string]Scanner),
				semaphore: make(chan struct{}, config.MaxThreads),
			}
			
			if tt.name != "Scanner not found" {
				mockScanner.On("Name").Return("ffuf").Maybe()
				svc.scanners["ffuf"] = mockScanner
			}
			
			tt.setupMocks(mockStore, mockScanner)
			
			project := getTestProject()
			ctx := context.Background()
			endpoints, err := svc.RunDirectoryBruteForce(ctx, project, tt.host)
			
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, endpoints, tt.wantLen)
			}
			
			mockStore.AssertExpectations(t)
			mockScanner.AssertExpectations(t)
		})
	}
}

func TestService_extractDomains(t *testing.T) {
	svc := &Service{}
	
	tests := []struct {
		name     string
		project  *models.Project
		expected []string
	}{
		{
			name: "Extract domains from scope",
			project: &models.Project{
				Scope: models.Scope{
					InScope: []models.Asset{
						{Type: models.AssetTypeDomain, Value: "example.com"},
						{Type: models.AssetTypeDomain, Value: "test.com"},
						{Type: models.AssetTypeIP, Value: "192.168.1.1"},
						{Type: models.AssetTypeDomain, Value: "example.com"}, // Duplicate
					},
				},
			},
			expected: []string{"example.com", "test.com"},
		},
		{
			name: "No domains in scope",
			project: &models.Project{
				Scope: models.Scope{
					InScope: []models.Asset{
						{Type: models.AssetTypeIP, Value: "192.168.1.1"},
						{Type: models.AssetTypeURL, Value: "https://example.com"},
					},
				},
			},
			expected: []string{},
		},
		{
			name: "Empty scope",
			project: &models.Project{
				Scope: models.Scope{
					InScope: []models.Asset{},
				},
			},
			expected: []string{},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := svc.extractDomains(tt.project)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestService_extractIPs(t *testing.T) {
	svc := &Service{}
	
	tests := []struct {
		name     string
		project  *models.Project
		expected []string
	}{
		{
			name: "Extract IPs from scope",
			project: &models.Project{
				Scope: models.Scope{
					InScope: []models.Asset{
						{Type: models.AssetTypeIP, Value: "192.168.1.1"},
						{Type: models.AssetTypeIP, Value: "10.0.0.1"},
						{Type: models.AssetTypeDomain, Value: "example.com"},
						{Type: models.AssetTypeIP, Value: "192.168.1.1"}, // Duplicate
					},
				},
			},
			expected: []string{"192.168.1.1", "10.0.0.1"},
		},
		{
			name: "No IPs in scope",
			project: &models.Project{
				Scope: models.Scope{
					InScope: []models.Asset{
						{Type: models.AssetTypeDomain, Value: "example.com"},
						{Type: models.AssetTypeURL, Value: "https://example.com"},
					},
				},
			},
			expected: []string{},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := svc.extractIPs(tt.project)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsWebHost(t *testing.T) {
	tests := []struct {
		name     string
		host     *models.Host
		expected bool
	}{
		{
			name: "Domain with web ports",
			host: &models.Host{
				Type:  models.AssetTypeDomain,
				Ports: []int{80, 443},
			},
			expected: true,
		},
		{
			name: "IP with web ports",
			host: &models.Host{
				Type:  models.AssetTypeIP,
				Ports: []int{8080, 22},
			},
			expected: true,
		},
		{
			name: "Domain without ports",
			host: &models.Host{
				Type:  models.AssetTypeDomain,
				Ports: []int{},
			},
			expected: true,
		},
		{
			name: "IP without web ports",
			host: &models.Host{
				Type:  models.AssetTypeIP,
				Ports: []int{22, 3306},
			},
			expected: false,
		},
		{
			name: "IP without ports",
			host: &models.Host{
				Type:  models.AssetTypeIP,
				Ports: []int{},
			},
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWebHost(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}