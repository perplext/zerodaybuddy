package storage

import (
	"context"
	"fmt"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/google/uuid"
)

// CreateFinding creates a new finding
func (s *SQLiteStore) CreateFinding(ctx context.Context, finding *models.Finding) error {
	// If ID is not provided, generate a new one
	if finding.ID == "" {
		finding.ID = uuid.New().String()
	}
	
	// Set timestamps if not provided
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = utils.CurrentTime()
	}
	if finding.UpdatedAt.IsZero() {
		finding.UpdatedAt = utils.CurrentTime()
	}
	
	// Set default values
	if finding.Type == "" {
		finding.Type = models.FindingTypeVulnerability
	}
	if finding.Confidence == "" {
		finding.Confidence = models.ConfidenceMedium
	}
	
	// Convert JSON fields to strings
	stepsJSON, err := utils.ToJSON(finding.Steps)
	if err != nil {
		return fmt.Errorf("failed to marshal steps: %w", err)
	}
	
	evidenceJSON, err := utils.ToJSON(finding.Evidence)
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
	}
	
	metadataJSON, err := utils.ToJSON(finding.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	
	referencesJSON, err := utils.ToJSON(finding.References)
	if err != nil {
		return fmt.Errorf("failed to marshal references: %w", err)
	}
	
	affectedAssetsJSON, err := utils.ToJSON(finding.AffectedAssets)
	if err != nil {
		return fmt.Errorf("failed to marshal affected assets: %w", err)
	}
	
	// Set found_at if not provided
	if finding.FoundAt.IsZero() {
		finding.FoundAt = utils.CurrentTime()
	}
	
	// Insert into database
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO findings (
			id, project_id, type, title, description, details, severity, confidence, status, url,
			cvss, cwe, steps_json, evidence_json, evidence_map_json, metadata_json, impact, remediation, references_json,
			found_by, found_at, affected_assets_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		finding.ID, finding.ProjectID, finding.Type, finding.Title, finding.Description,
		finding.Details, finding.Severity, finding.Confidence, finding.Status, finding.URL,
		finding.CVSS, finding.CWE, stepsJSON, "[]", evidenceJSON, metadataJSON, finding.Impact, finding.Remediation, 
		referencesJSON, finding.FoundBy, finding.FoundAt, affectedAssetsJSON,
		finding.CreatedAt, finding.UpdatedAt)
	
	if err != nil {
		return fmt.Errorf("failed to create finding: %w", err)
	}
	
	return nil
}
