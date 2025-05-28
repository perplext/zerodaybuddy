package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// GetFinding retrieves a finding by ID
func (s *SQLiteStore) GetFinding(ctx context.Context, id string) (*models.Finding, error) {
	var finding models.Finding
	var findingType, confidence, url, details sql.NullString
	var stepsJSON, evidenceJSON, evidenceMapJSON, metadataJSON, referencesJSON, affectedAssetsJSON string
	
	err := s.db.QueryRowContext(ctx, `
		SELECT 
			id, project_id, type, title, description, details, severity, confidence, status, url,
			cvss, cwe, steps_json, evidence_json, evidence_map_json, metadata_json, impact, remediation, references_json,
			found_by, found_at, affected_assets_json, created_at, updated_at
		FROM findings
		WHERE id = ?
	`, id).Scan(
		&finding.ID, &finding.ProjectID, &findingType, &finding.Title, &finding.Description,
		&details, &finding.Severity, &confidence, &finding.Status, &url,
		&finding.CVSS, &finding.CWE, &stepsJSON, &evidenceJSON, &evidenceMapJSON, &metadataJSON, &finding.Impact, &finding.Remediation,
		&referencesJSON, &finding.FoundBy, &finding.FoundAt, &affectedAssetsJSON,
		&finding.CreatedAt, &finding.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get finding: %w", err)
	}
	
	// Handle nullable fields
	if findingType.Valid {
		finding.Type = models.FindingType(findingType.String)
	} else {
		finding.Type = models.FindingTypeVulnerability
	}
	if confidence.Valid {
		finding.Confidence = models.FindingConfidence(confidence.String)
	} else {
		finding.Confidence = models.ConfidenceMedium
	}
	if url.Valid {
		finding.URL = url.String
	}
	if details.Valid {
		finding.Details = details.String
	}
	
	// Unmarshal JSON fields
	if err := utils.FromJSON(stepsJSON, &finding.Steps); err != nil {
		return nil, fmt.Errorf("failed to unmarshal steps: %w", err)
	}
	
	// Try to unmarshal evidence - first try as map, then as array
	if evidenceMapJSON != "" && evidenceMapJSON != "null" && evidenceMapJSON != "[]" {
		if err := utils.FromJSON(evidenceMapJSON, &finding.Evidence); err != nil {
			return nil, fmt.Errorf("failed to unmarshal evidence map: %w", err)
		}
	} else if evidenceJSON != "" && evidenceJSON != "null" && evidenceJSON != "[]" {
		var evidenceArray []models.Evidence
		if err := utils.FromJSON(evidenceJSON, &evidenceArray); err != nil {
			return nil, fmt.Errorf("failed to unmarshal evidence array: %w", err)
		}
		finding.Evidence = evidenceArray
	}
	
	if metadataJSON != "" && metadataJSON != "null" {
		if err := utils.FromJSON(metadataJSON, &finding.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}
	
	if err := utils.FromJSON(referencesJSON, &finding.References); err != nil {
		return nil, fmt.Errorf("failed to unmarshal references: %w", err)
	}
	if err := utils.FromJSON(affectedAssetsJSON, &finding.AffectedAssets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal affected assets: %w", err)
	}
	
	return &finding, nil
}

// UpdateFinding updates a finding
func (s *SQLiteStore) UpdateFinding(ctx context.Context, finding *models.Finding) error {
	// Update timestamp
	finding.UpdatedAt = utils.CurrentTime()
	
	// Convert JSON fields to strings
	stepsJSON, err := utils.ToJSON(finding.Steps)
	if err != nil {
		return fmt.Errorf("failed to marshal steps: %w", err)
	}
	
	// Handle evidence field based on type
	var evidenceJSON, evidenceMapJSON string
	if finding.Evidence != nil {
		switch v := finding.Evidence.(type) {
		case []models.Evidence:
			// Old format - array of Evidence structs
			evidenceJSON, err = utils.ToJSON(v)
			if err != nil {
				return fmt.Errorf("failed to marshal evidence array: %w", err)
			}
			evidenceMapJSON = "[]"
		case map[string]interface{}:
			// New format - map
			evidenceMapJSON, err = utils.ToJSON(v)
			if err != nil {
				return fmt.Errorf("failed to marshal evidence map: %w", err)
			}
			evidenceJSON = "[]"
		default:
			// Try to marshal as-is
			evidenceMapJSON, err = utils.ToJSON(v)
			if err != nil {
				return fmt.Errorf("failed to marshal evidence: %w", err)
			}
			evidenceJSON = "[]"
		}
	} else {
		evidenceJSON = "[]"
		evidenceMapJSON = "[]"
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
	
	result, err := s.db.ExecContext(ctx, `
		UPDATE findings SET
			type = ?, title = ?, description = ?, details = ?, severity = ?, confidence = ?, status = ?, url = ?,
			cvss = ?, cwe = ?, steps_json = ?, evidence_json = ?, evidence_map_json = ?, metadata_json = ?, impact = ?, remediation = ?, 
			references_json = ?, found_by = ?, found_at = ?, affected_assets_json = ?, updated_at = ?
		WHERE id = ?
	`,
		finding.Type, finding.Title, finding.Description, finding.Details, finding.Severity, finding.Confidence, finding.Status, finding.URL,
		finding.CVSS, finding.CWE, stepsJSON, evidenceJSON, evidenceMapJSON, metadataJSON, finding.Impact,
		finding.Remediation, referencesJSON, finding.FoundBy, finding.FoundAt,
		affectedAssetsJSON, finding.UpdatedAt, finding.ID,
	)
	
	if err != nil {
		return fmt.Errorf("failed to update finding: %w", err)
	}
	
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	
	if rows == 0 {
		return ErrNotFound
	}
	
	return nil
}

// ListFindings lists all findings for a project
func (s *SQLiteStore) ListFindings(ctx context.Context, projectID string) ([]*models.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			id, project_id, type, title, description, details, severity, confidence, status, url,
			cvss, cwe, steps_json, evidence_json, evidence_map_json, metadata_json, impact, remediation, references_json,
			found_by, found_at, affected_assets_json, created_at, updated_at
		FROM findings
		WHERE project_id = ?
		ORDER BY created_at DESC
	`, projectID)
	
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}
	defer rows.Close()
	
	var findings []*models.Finding
	for rows.Next() {
		var finding models.Finding
		var findingType, confidence, url, details sql.NullString
		var stepsJSON, evidenceJSON, evidenceMapJSON, metadataJSON, referencesJSON, affectedAssetsJSON string
		
		err := rows.Scan(
			&finding.ID, &finding.ProjectID, &findingType, &finding.Title, &finding.Description,
			&details, &finding.Severity, &confidence, &finding.Status, &url,
			&finding.CVSS, &finding.CWE, &stepsJSON, &evidenceJSON, &evidenceMapJSON, &metadataJSON, &finding.Impact, &finding.Remediation,
			&referencesJSON, &finding.FoundBy, &finding.FoundAt, &affectedAssetsJSON,
			&finding.CreatedAt, &finding.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}
		
		// Handle nullable fields
		if findingType.Valid {
			finding.Type = models.FindingType(findingType.String)
		} else {
			finding.Type = models.FindingTypeVulnerability
		}
		if confidence.Valid {
			finding.Confidence = models.FindingConfidence(confidence.String)
		} else {
			finding.Confidence = models.ConfidenceMedium
		}
		if url.Valid {
			finding.URL = url.String
		}
		if details.Valid {
			finding.Details = details.String
		}
		
		// Unmarshal JSON fields
		if err := utils.FromJSON(stepsJSON, &finding.Steps); err != nil {
			return nil, fmt.Errorf("failed to unmarshal steps: %w", err)
		}
		
		// Try to unmarshal evidence - first try as map, then as array
		if evidenceMapJSON != "" && evidenceMapJSON != "null" && evidenceMapJSON != "[]" {
			if err := utils.FromJSON(evidenceMapJSON, &finding.Evidence); err != nil {
				return nil, fmt.Errorf("failed to unmarshal evidence map: %w", err)
			}
		} else if evidenceJSON != "" && evidenceJSON != "null" && evidenceJSON != "[]" {
			var evidenceArray []models.Evidence
			if err := utils.FromJSON(evidenceJSON, &evidenceArray); err != nil {
				return nil, fmt.Errorf("failed to unmarshal evidence array: %w", err)
			}
			finding.Evidence = evidenceArray
		}
		
		if metadataJSON != "" && metadataJSON != "null" {
			if err := utils.FromJSON(metadataJSON, &finding.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}
		
		if err := utils.FromJSON(referencesJSON, &finding.References); err != nil {
			return nil, fmt.Errorf("failed to unmarshal references: %w", err)
		}
		if err := utils.FromJSON(affectedAssetsJSON, &finding.AffectedAssets); err != nil {
			return nil, fmt.Errorf("failed to unmarshal affected assets: %w", err)
		}
		
		findings = append(findings, &finding)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate findings: %w", err)
	}
	
	return findings, nil
}

// DeleteFinding deletes a finding by ID
func (s *SQLiteStore) DeleteFinding(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM findings WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete finding: %w", err)
	}
	
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	
	if rows == 0 {
		return ErrNotFound
	}
	
	return nil
}
