package report

import (
	"context"
	"fmt"
	"time"
	
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/google/uuid"
)

// Service provides reporting functionality
type Service struct {
	store  interface {
		GetProject(ctx context.Context, id string) (*models.Project, error)
		GetFinding(ctx context.Context, id string) (*models.Finding, error)
		CreateReport(ctx context.Context, report *models.Report) (*models.Report, error)
		GetReport(ctx context.Context, id string) (*models.Report, error)
		ListReports(ctx context.Context, projectID string) ([]*models.Report, error)
	}
	logger *utils.Logger
}

// NewService creates a new reporting service
func NewService(store interface {
	GetProject(ctx context.Context, id string) (*models.Project, error)
	GetFinding(ctx context.Context, id string) (*models.Finding, error)
	CreateReport(ctx context.Context, report *models.Report) (*models.Report, error)
	GetReport(ctx context.Context, id string) (*models.Report, error)
	ListReports(ctx context.Context, projectID string) ([]*models.Report, error)
}, logger *utils.Logger) *Service {
	return &Service{
		store:  store,
		logger: logger,
	}
}

// CreateReport creates a new report
func (s *Service) CreateReport(ctx context.Context, report *models.Report) (*models.Report, error) {
	if report.ID == "" {
		report.ID = uuid.New().String()
	}

	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now()
	}

	// Generate report content based on whether it's for a specific finding or the whole project
	var err error
	if report.FindingID == "" {
		// This is a project-level report
		report.Content, err = s.generateProjectReportContent(ctx, report.ProjectID, report.Format)
	} else {
		// This is a finding-specific report
		report.Content, err = s.generateFindingReportContent(ctx, report.ProjectID, report.FindingID, report.Format)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate report content: %w", err)
	}

	// Save report to database
	return s.store.CreateReport(ctx, report)
}

// generateProjectReportContent generates the content for a project report
func (s *Service) generateProjectReportContent(ctx context.Context, projectID, format string) (string, error) {
	// For now, just return a simple template
	project, err := s.store.GetProject(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf("failed to get project: %w", err)
	}

	return fmt.Sprintf("# Project Report: %s\n\nThis is a placeholder for the full project report.\n\nGenerated on: %s", 
		project.Name, time.Now().Format(time.RFC1123)), nil
}

// generateFindingReportContent generates the content for a finding report
func (s *Service) generateFindingReportContent(ctx context.Context, projectID, findingID, format string) (string, error) {
	finding, err := s.store.GetFinding(ctx, findingID)
	if err != nil {
		return "", fmt.Errorf("failed to get finding: %w", err)
	}

	project, err := s.store.GetProject(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf("failed to get project: %w", err)
	}

	return fmt.Sprintf("# Finding Report: %s\n\n## Project: %s\n\n## Description\n%s\n\n## Severity\n%s\n\n## Details\n%s\n\nGenerated on: %s", 
		finding.Title, project.Name, finding.Description, string(finding.Severity), finding.Details, time.Now().Format(time.RFC1123)), nil
}
