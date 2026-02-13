package report

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

func (m *MockStore) GetFinding(ctx context.Context, id string) (*models.Finding, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Finding), args.Error(1)
}

func (m *MockStore) CreateReport(ctx context.Context, report *models.Report) (*models.Report, error) {
	args := m.Called(ctx, report)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Report), args.Error(1)
}

func (m *MockStore) GetReport(ctx context.Context, id string) (*models.Report, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Report), args.Error(1)
}

func (m *MockStore) ListFindings(ctx context.Context, projectID string) ([]*models.Finding, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Finding), args.Error(1)
}

func (m *MockStore) ListReports(ctx context.Context, projectID string) ([]*models.Report, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Report), args.Error(1)
}

func TestNewService(t *testing.T) {
	mockStore := new(MockStore)
	logger := utils.NewLogger("", false)

	svc := NewService(mockStore, logger)

	assert.NotNil(t, svc)
	assert.Equal(t, mockStore, svc.store)
	assert.Equal(t, logger, svc.logger)
}

func TestService_CreateReport_ProjectLevel(t *testing.T) {
	tests := []struct {
		name          string
		report        *models.Report
		project       *models.Project
		setupMocks    func(*MockStore)
		expectedError string
	}{
		{
			name: "successful project report creation",
			report: &models.Report{
				ProjectID: "test-project-id",
				Format:    "markdown",
			},
			project: &models.Project{
				ID:   "test-project-id",
				Name: "Test Project",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetProject", mock.Anything, "test-project-id").Return(&models.Project{
					ID:   "test-project-id",
					Name: "Test Project",
				}, nil)
				m.On("CreateReport", mock.Anything, mock.AnythingOfType("*models.Report")).Return(&models.Report{
					ID:        "generated-id",
					ProjectID: "test-project-id",
										Format:    "markdown",
					Content:   "# Project Report: Test Project",
					CreatedAt: time.Now(),
				}, nil)
			},
		},
		{
			name: "project report with existing ID",
			report: &models.Report{
				ID:        "existing-id",
				ProjectID: "test-project-id",
								Format:    "markdown",
			},
			project: &models.Project{
				ID:   "test-project-id",
				Name: "Test Project",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetProject", mock.Anything, "test-project-id").Return(&models.Project{
					ID:   "test-project-id",
					Name: "Test Project",
				}, nil)
				m.On("CreateReport", mock.Anything, mock.AnythingOfType("*models.Report")).Return(&models.Report{
					ID:        "existing-id",
					ProjectID: "test-project-id",
										Format:    "markdown",
					Content:   "# Project Report: Test Project",
					CreatedAt: time.Now(),
				}, nil)
			},
		},
		{
			name: "project not found",
			report: &models.Report{
				ProjectID: "non-existent-project",
								Format:    "markdown",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetProject", mock.Anything, "non-existent-project").Return(nil, errors.New("project not found"))
			},
			expectedError: "failed to generate report content: failed to get project: project not found",
		},
		{
			name: "store create report error",
			report: &models.Report{
				ProjectID: "test-project-id",
				Format:    "markdown",
			},
			project: &models.Project{
				ID:   "test-project-id",
				Name: "Test Project",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetProject", mock.Anything, "test-project-id").Return(&models.Project{
					ID:   "test-project-id",
					Name: "Test Project",
				}, nil)
				m.On("CreateReport", mock.Anything, mock.AnythingOfType("*models.Report")).Return(nil, errors.New("database error"))
			},
			expectedError: "database error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := new(MockStore)
			logger := utils.NewLogger("", false)
			svc := NewService(mockStore, logger)

			tt.setupMocks(mockStore)

			ctx := context.Background()
			result, err := svc.CreateReport(ctx, tt.report)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.ID)
				assert.NotZero(t, result.CreatedAt)
			}

			mockStore.AssertExpectations(t)
		})
	}
}

func TestService_CreateReport_FindingLevel(t *testing.T) {
	tests := []struct {
		name          string
		report        *models.Report
		finding       *models.Finding
		project       *models.Project
		setupMocks    func(*MockStore)
		expectedError string
	}{
		{
			name: "successful finding report creation",
			report: &models.Report{
				ProjectID: "test-project-id",
				FindingID: "test-finding-id",
								Format:    "markdown",
			},
			finding: &models.Finding{
				ID:          "test-finding-id",
				Title:       "Test Finding",
				Description: "Test finding description",
				Severity:    models.SeverityHigh,
				Details:     "Detailed information",
			},
			project: &models.Project{
				ID:   "test-project-id",
				Name: "Test Project",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetFinding", mock.Anything, "test-finding-id").Return(&models.Finding{
					ID:          "test-finding-id",
					Title:       "Test Finding",
					Description: "Test finding description",
					Severity:    models.SeverityHigh,
					Details:     "Detailed information",
				}, nil)
				m.On("GetProject", mock.Anything, "test-project-id").Return(&models.Project{
					ID:   "test-project-id",
					Name: "Test Project",
				}, nil)
				m.On("CreateReport", mock.Anything, mock.AnythingOfType("*models.Report")).Return(&models.Report{
					ID:        "generated-id",
					ProjectID: "test-project-id",
					FindingID: "test-finding-id",
										Format:    "markdown",
					Content:   "# Finding Report: Test Finding",
					CreatedAt: time.Now(),
				}, nil)
			},
		},
		{
			name: "finding not found",
			report: &models.Report{
				ProjectID: "test-project-id",
				FindingID: "non-existent-finding",
								Format:    "markdown",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetFinding", mock.Anything, "non-existent-finding").Return(nil, errors.New("finding not found"))
			},
			expectedError: "failed to generate report content: failed to get finding: finding not found",
		},
		{
			name: "project not found for finding report",
			report: &models.Report{
				ProjectID: "test-project-id",
				FindingID: "test-finding-id",
								Format:    "markdown",
			},
			finding: &models.Finding{
				ID:          "test-finding-id",
				Title:       "Test Finding",
				Description: "Test finding description",
				Severity:    models.SeverityHigh,
				Details:     "Detailed information",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetFinding", mock.Anything, "test-finding-id").Return(&models.Finding{
					ID:          "test-finding-id",
					Title:       "Test Finding",
					Description: "Test finding description",
					Severity:    models.SeverityHigh,
					Details:     "Detailed information",
				}, nil)
				m.On("GetProject", mock.Anything, "test-project-id").Return(nil, errors.New("project not found"))
			},
			expectedError: "failed to generate report content: failed to get project: project not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := new(MockStore)
			logger := utils.NewLogger("", false)
			svc := NewService(mockStore, logger)

			tt.setupMocks(mockStore)

			ctx := context.Background()
			result, err := svc.CreateReport(ctx, tt.report)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.ID)
				assert.NotZero(t, result.CreatedAt)
			}

			mockStore.AssertExpectations(t)
		})
	}
}

func TestService_generateProjectReportContent(t *testing.T) {
	tests := []struct {
		name          string
		projectID     string
		format        string
		project       *models.Project
		setupMocks    func(*MockStore)
		expectedError string
		checkContent  func(t *testing.T, content string)
	}{
		{
			name:      "successful project report content generation",
			projectID: "test-project-id",
			format:    "markdown",
			project: &models.Project{
				ID:   "test-project-id",
				Name: "Test Project",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetProject", mock.Anything, "test-project-id").Return(&models.Project{
					ID:   "test-project-id",
					Name: "Test Project",
				}, nil)
			},
			checkContent: func(t *testing.T, content string) {
				assert.Contains(t, content, "# Project Report: Test Project")
				assert.Contains(t, content, "This is a placeholder for the full project report")
				assert.Contains(t, content, "Generated on:")
			},
		},
		{
			name:      "project not found",
			projectID: "non-existent-project",
			format:    "markdown",
			setupMocks: func(m *MockStore) {
				m.On("GetProject", mock.Anything, "non-existent-project").Return(nil, errors.New("project not found"))
			},
			expectedError: "failed to get project: project not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := new(MockStore)
			logger := utils.NewLogger("", false)
			svc := NewService(mockStore, logger)

			tt.setupMocks(mockStore)

			ctx := context.Background()
			content, err := svc.generateProjectReportContent(ctx, tt.projectID, tt.format)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, content)
				if tt.checkContent != nil {
					tt.checkContent(t, content)
				}
			}

			mockStore.AssertExpectations(t)
		})
	}
}

func TestService_generateFindingReportContent(t *testing.T) {
	tests := []struct {
		name          string
		projectID     string
		findingID     string
		format        string
		finding       *models.Finding
		project       *models.Project
		setupMocks    func(*MockStore)
		expectedError string
		checkContent  func(t *testing.T, content string)
	}{
		{
			name:      "successful finding report content generation",
			projectID: "test-project-id",
			findingID: "test-finding-id",
			format:    "markdown",
			finding: &models.Finding{
				ID:          "test-finding-id",
				Title:       "SQL Injection Vulnerability",
				Description: "SQL injection vulnerability found in login endpoint",
				Severity:    models.SeverityHigh,
				Details:     "The login endpoint is vulnerable to SQL injection attacks",
			},
			project: &models.Project{
				ID:   "test-project-id",
				Name: "Test Project",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetFinding", mock.Anything, "test-finding-id").Return(&models.Finding{
					ID:          "test-finding-id",
					Title:       "SQL Injection Vulnerability",
					Description: "SQL injection vulnerability found in login endpoint",
					Severity:    models.SeverityHigh,
					Details:     "The login endpoint is vulnerable to SQL injection attacks",
				}, nil)
				m.On("GetProject", mock.Anything, "test-project-id").Return(&models.Project{
					ID:   "test-project-id",
					Name: "Test Project",
				}, nil)
			},
			checkContent: func(t *testing.T, content string) {
				assert.Contains(t, content, "# Finding Report: SQL Injection Vulnerability")
				assert.Contains(t, content, "## Project: Test Project")
				assert.Contains(t, content, "## Description")
				assert.Contains(t, content, "SQL injection vulnerability found in login endpoint")
				assert.Contains(t, content, "## Severity")
				assert.Contains(t, content, string(models.SeverityHigh))
				assert.Contains(t, content, "## Details")
				assert.Contains(t, content, "The login endpoint is vulnerable to SQL injection attacks")
				assert.Contains(t, content, "Generated on:")
			},
		},
		{
			name:      "finding not found",
			projectID: "test-project-id",
			findingID: "non-existent-finding",
			format:    "markdown",
			setupMocks: func(m *MockStore) {
				m.On("GetFinding", mock.Anything, "non-existent-finding").Return(nil, errors.New("finding not found"))
			},
			expectedError: "failed to get finding: finding not found",
		},
		{
			name:      "project not found",
			projectID: "test-project-id",
			findingID: "test-finding-id",
			format:    "markdown",
			finding: &models.Finding{
				ID:          "test-finding-id",
				Title:       "Test Finding",
				Description: "Test description",
				Severity:    models.SeverityMedium,
				Details:     "Test details",
			},
			setupMocks: func(m *MockStore) {
				m.On("GetFinding", mock.Anything, "test-finding-id").Return(&models.Finding{
					ID:          "test-finding-id",
					Title:       "Test Finding",
					Description: "Test description",
					Severity:    models.SeverityMedium,
					Details:     "Test details",
				}, nil)
				m.On("GetProject", mock.Anything, "test-project-id").Return(nil, errors.New("project not found"))
			},
			expectedError: "failed to get project: project not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := new(MockStore)
			logger := utils.NewLogger("", false)
			svc := NewService(mockStore, logger)

			tt.setupMocks(mockStore)

			ctx := context.Background()
			content, err := svc.generateFindingReportContent(ctx, tt.projectID, tt.findingID, tt.format)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, content)
				if tt.checkContent != nil {
					tt.checkContent(t, content)
				}
			}

			mockStore.AssertExpectations(t)
		})
	}
}

func TestService_ReportContentGeneration(t *testing.T) {
	// Test that generated content is valid and contains expected fields
	mockStore := new(MockStore)
	logger := utils.NewLogger("", false)
	svc := NewService(mockStore, logger)

	// Setup mock for project report
	mockStore.On("GetProject", mock.Anything, "project-123").Return(&models.Project{
		ID:          "project-123",
		Name:        "Security Assessment Project",
		Description: "Testing security assessment",
	}, nil)

	ctx := context.Background()
	projectContent, err := svc.generateProjectReportContent(ctx, "project-123", "markdown")
	require.NoError(t, err)

	// Verify markdown structure
	assert.True(t, strings.HasPrefix(projectContent, "# Project Report:"))
	assert.Contains(t, projectContent, "Security Assessment Project")

	// Setup mock for finding report
	mockStore.On("GetFinding", mock.Anything, "finding-456").Return(&models.Finding{
		ID:          "finding-456",
		Title:       "Critical XSS Vulnerability",
		Description: "Cross-site scripting vulnerability in user input",
		Severity:    models.SeverityCritical,
		Details:     "Unescaped user input in the search functionality",
	}, nil)
	mockStore.On("GetProject", mock.Anything, "project-123").Return(&models.Project{
		ID:   "project-123",
		Name: "Security Assessment Project",
	}, nil)

	findingContent, err := svc.generateFindingReportContent(ctx, "project-123", "finding-456", "markdown")
	require.NoError(t, err)

	// Verify markdown structure
	assert.True(t, strings.HasPrefix(findingContent, "# Finding Report:"))
	assert.Contains(t, findingContent, "Critical XSS Vulnerability")
	assert.Contains(t, findingContent, "Cross-site scripting vulnerability in user input")
	assert.Contains(t, findingContent, string(models.SeverityCritical))

	mockStore.AssertExpectations(t)
}

func TestService_CreateReportWithTimestamp(t *testing.T) {
	mockStore := new(MockStore)
	logger := utils.NewLogger("", false)
	svc := NewService(mockStore, logger)

	// Test that CreatedAt is set when not provided
	report := &models.Report{
		ProjectID: "test-project",
		Format:    "markdown",
	}

	mockStore.On("GetProject", mock.Anything, "test-project").Return(&models.Project{
		ID:   "test-project",
		Name: "Test Project",
	}, nil).Once()
	
	mockStore.On("CreateReport", mock.Anything, mock.AnythingOfType("*models.Report")).Run(func(args mock.Arguments) {
		r := args.Get(1).(*models.Report)
		assert.NotEmpty(t, r.ID)
		assert.False(t, r.CreatedAt.IsZero())
	}).Return(&models.Report{
		ID:        "generated-id",
		ProjectID: "test-project",
		Format:    "markdown",
		CreatedAt: time.Now(),
	}, nil).Once()

	ctx := context.Background()
	result, err := svc.CreateReport(ctx, report)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.ID)
	assert.False(t, result.CreatedAt.IsZero())

	// Test that existing CreatedAt is preserved
	existingTime := time.Now().Add(-24 * time.Hour)
	reportWithTime := &models.Report{
		ID:        "existing-id",
		ProjectID: "test-project",
		Format:    "markdown",
		CreatedAt: existingTime,
	}

	mockStore.On("GetProject", mock.Anything, "test-project").Return(&models.Project{
		ID:   "test-project",
		Name: "Test Project",
	}, nil).Once()
	
	var capturedReport *models.Report
	mockStore.On("CreateReport", mock.Anything, mock.AnythingOfType("*models.Report")).Run(func(args mock.Arguments) {
		capturedReport = args.Get(1).(*models.Report)
	}).Return(&models.Report{
		ID:        "existing-id",
		ProjectID: "test-project",
		Format:    "markdown",
		Content:   "# Project Report: Test Project",
		CreatedAt: existingTime,
	}, nil).Once()

	result2, err := svc.CreateReport(ctx, reportWithTime)
	require.NoError(t, err)
	assert.NotNil(t, capturedReport)
	assert.True(t, existingTime.Equal(capturedReport.CreatedAt), "Expected service to preserve existing CreatedAt")
	assert.True(t, existingTime.Equal(result2.CreatedAt), "Expected result to have preserved CreatedAt")

	mockStore.AssertExpectations(t)
}