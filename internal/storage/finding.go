package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// findingScanDest holds the intermediate scan targets for a finding row.
type findingScanDest struct {
	finding                                                                    models.Finding
	findingType, confidence, url, details                                      sql.NullString
	stepsJSON, evidenceJSON, evidenceMapJSON, metadataJSON, referencesJSON, affectedAssetsJSON sql.NullString
}

// scanArgs returns pointers in column order for use with Scan/QueryRow.
func (d *findingScanDest) scanArgs() []interface{} {
	return []interface{}{
		&d.finding.ID, &d.finding.ProjectID, &d.findingType, &d.finding.Title, &d.finding.Description,
		&d.details, &d.finding.Severity, &d.confidence, &d.finding.Status, &d.url,
		&d.finding.CVSS, &d.finding.CVSSVector, &d.finding.CVSSVersion, &d.finding.CWE,
		&d.stepsJSON, &d.evidenceJSON, &d.evidenceMapJSON, &d.metadataJSON,
		&d.finding.Impact, &d.finding.Remediation, &d.referencesJSON, &d.finding.FoundBy, &d.finding.FoundAt,
		&d.affectedAssetsJSON, &d.finding.CreatedAt, &d.finding.UpdatedAt,
	}
}

// hydrate populates nullable and JSON fields on the embedded finding.
func (d *findingScanDest) hydrate() (*models.Finding, error) {
	f := &d.finding

	if d.findingType.Valid {
		f.Type = models.FindingType(d.findingType.String)
	} else {
		f.Type = models.FindingTypeVulnerability
	}
	if d.confidence.Valid {
		f.Confidence = models.FindingConfidence(d.confidence.String)
	} else {
		f.Confidence = models.ConfidenceMedium
	}
	if d.url.Valid {
		f.URL = d.url.String
	}
	if d.details.Valid {
		f.Details = d.details.String
	}

	stepsStr := d.stepsJSON.String
	if stepsStr != "" {
		if err := utils.FromJSON(stepsStr, &f.Steps); err != nil {
			return nil, fmt.Errorf("failed to unmarshal steps: %w", err)
		}
	}

	evidenceMapStr := d.evidenceMapJSON.String
	evidenceStr := d.evidenceJSON.String
	if evidenceMapStr != "" && evidenceMapStr != "null" && evidenceMapStr != "[]" {
		if err := utils.FromJSON(evidenceMapStr, &f.Evidence); err != nil {
			return nil, fmt.Errorf("failed to unmarshal evidence map: %w", err)
		}
	} else if evidenceStr != "" && evidenceStr != "null" && evidenceStr != "[]" {
		var evidenceArray []models.Evidence
		if err := utils.FromJSON(evidenceStr, &evidenceArray); err != nil {
			return nil, fmt.Errorf("failed to unmarshal evidence array: %w", err)
		}
		f.Evidence = evidenceArray
	}

	metadataStr := d.metadataJSON.String
	if metadataStr != "" && metadataStr != "null" {
		if err := utils.FromJSON(metadataStr, &f.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	referencesStr := d.referencesJSON.String
	if referencesStr != "" {
		if err := utils.FromJSON(referencesStr, &f.References); err != nil {
			return nil, fmt.Errorf("failed to unmarshal references: %w", err)
		}
	}

	affectedAssetsStr := d.affectedAssetsJSON.String
	if affectedAssetsStr != "" {
		if err := utils.FromJSON(affectedAssetsStr, &f.AffectedAssets); err != nil {
			return nil, fmt.Errorf("failed to unmarshal affected assets: %w", err)
		}
	}

	return f, nil
}

const findingSelectCols = `id, project_id, type, title, description, details, severity, confidence, status, url,
			cvss, cvss_vector, cvss_version, cwe, steps_json, evidence_json, evidence_map_json, metadata_json, impact, remediation, references_json,
			found_by, found_at, affected_assets_json, created_at, updated_at`

// GetFinding retrieves a finding by ID
func (s *SQLiteStore) GetFinding(ctx context.Context, id string) (*models.Finding, error) {
	var d findingScanDest

	err := s.db.QueryRowContext(ctx,
		`SELECT `+findingSelectCols+` FROM findings WHERE id = ?`, id,
	).Scan(d.scanArgs()...)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get finding: %w", err)
	}

	return d.hydrate()
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
			cvss = ?, cvss_vector = ?, cvss_version = ?, cwe = ?, steps_json = ?, evidence_json = ?, evidence_map_json = ?, metadata_json = ?, impact = ?, remediation = ?,
			references_json = ?, found_by = ?, found_at = ?, affected_assets_json = ?, updated_at = ?
		WHERE id = ?
	`,
		finding.Type, finding.Title, finding.Description, finding.Details, finding.Severity, finding.Confidence, finding.Status, finding.URL,
		finding.CVSS, finding.CVSSVector, finding.CVSSVersion, finding.CWE, stepsJSON, evidenceJSON, evidenceMapJSON, metadataJSON, finding.Impact,
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
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+findingSelectCols+` FROM findings WHERE project_id = ? ORDER BY created_at DESC`,
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}
	defer rows.Close()

	var findings []*models.Finding
	for rows.Next() {
		var d findingScanDest
		if err := rows.Scan(d.scanArgs()...); err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}
		f, err := d.hydrate()
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
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
