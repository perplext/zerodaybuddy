package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/google/uuid"
)

// CreateReport creates a new report
func (s *SQLiteStore) CreateReport(ctx context.Context, report *models.Report) (*models.Report, error) {
	// Generate ID if not provided
	if report.ID == "" {
		report.ID = uuid.New().String()
	}
	
	// Set timestamps
	now := utils.CurrentTime()
	if report.CreatedAt.IsZero() {
		report.CreatedAt = now
	}
	report.UpdatedAt = now
	
	// Convert JSON fields to strings
	metadataJSON, err := utils.ToJSON(report.Metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}
	
	// Handle nullable finding_id
	var findingID interface{}
	if report.FindingID != "" {
		findingID = report.FindingID
	}
	
	// Insert into database
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO reports (
			id, project_id, finding_id, title, format, content, metadata_json,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		report.ID, report.ProjectID, findingID, report.Title, report.Format,
		report.Content, metadataJSON, report.CreatedAt, report.UpdatedAt)
	
	if err != nil {
		return nil, fmt.Errorf("failed to create report: %w", err)
	}
	
	return report, nil
}

// GetReport retrieves a report by ID
func (s *SQLiteStore) GetReport(ctx context.Context, id string) (*models.Report, error) {
	var report models.Report
	var metadataJSON string
	var findingID sql.NullString
	
	err := s.db.QueryRowContext(ctx, `
		SELECT 
			id, project_id, finding_id, title, format, content, metadata_json,
			created_at, updated_at
		FROM reports
		WHERE id = ?
	`, id).Scan(
		&report.ID, &report.ProjectID, &findingID, &report.Title, &report.Format,
		&report.Content, &metadataJSON, &report.CreatedAt, &report.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}
	
	// Handle nullable finding_id
	if findingID.Valid {
		report.FindingID = findingID.String
	}
	
	// Deserialize metadata from JSON
	if err := utils.UnmarshalJSON(metadataJSON, &report.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	
	return &report, nil
}

// ListReports lists all reports for a project
func (s *SQLiteStore) ListReports(ctx context.Context, projectID string) ([]*models.Report, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			id, project_id, finding_id, title, format, content, metadata_json,
			created_at, updated_at
		FROM reports
		WHERE project_id = ?
		ORDER BY created_at DESC
	`, projectID)
	
	if err != nil {
		return nil, fmt.Errorf("failed to query reports: %w", err)
	}
	defer rows.Close()
	
	reports := []*models.Report{}
	
	for rows.Next() {
		var report models.Report
		var metadataJSON string
		var findingID sql.NullString
		
		err := rows.Scan(
			&report.ID, &report.ProjectID, &findingID, &report.Title, &report.Format,
			&report.Content, &metadataJSON, &report.CreatedAt, &report.UpdatedAt,
		)
		
		if err != nil {
			return nil, fmt.Errorf("failed to scan report: %w", err)
		}
		
		// Handle nullable finding_id
		if findingID.Valid {
			report.FindingID = findingID.String
		}
		
		// Deserialize metadata from JSON
		if err := utils.UnmarshalJSON(metadataJSON, &report.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
		
		reports = append(reports, &report)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating reports: %w", err)
	}
	
	return reports, nil
}

// DeleteReport deletes a report
func (s *SQLiteStore) DeleteReport(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM reports WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete report: %w", err)
	}
	
	return nil
}
