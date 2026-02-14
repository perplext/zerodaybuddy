package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// BulkResult reports the outcome of a bulk insert operation.
type BulkResult struct {
	Attempted int // Total records in the input slice
	Inserted  int // Records actually inserted
	Skipped   int // Records skipped (e.g. duplicates)
}

// BulkCreateHosts inserts multiple hosts in a single transaction.
// Duplicates (same project_id + value) are silently skipped.
func (s *SQLiteStore) BulkCreateHosts(ctx context.Context, hosts []*models.Host) (*BulkResult, error) {
	result := &BulkResult{Attempted: len(hosts)}
	if len(hosts) == 0 {
		return result, nil
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO hosts (
			id, project_id, type, value, ip, status, title, technologies_json,
			ports_json, headers_json, screenshot, notes, found_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	now := utils.CurrentTime()
	for _, host := range hosts {
		if host.ID == "" {
			host.ID = uuid.New().String()
		}
		if host.CreatedAt.IsZero() {
			host.CreatedAt = now
		}
		host.UpdatedAt = now

		technologiesJSON, err := utils.MarshalJSON(host.Technologies)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal technologies: %w", err)
		}
		portsJSON, err := utils.MarshalJSON(host.Ports)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ports: %w", err)
		}
		headersJSON, err := utils.MarshalJSON(host.Headers)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal headers: %w", err)
		}

		res, err := stmt.ExecContext(ctx,
			host.ID, host.ProjectID, host.Type, host.Value, host.IP, host.Status, host.Title,
			technologiesJSON, portsJSON, headersJSON, host.Screenshot, host.Notes, host.FoundBy,
			host.CreatedAt, host.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert host %s: %w", host.Value, err)
		}

		n, _ := res.RowsAffected()
		result.Inserted += int(n)
	}

	result.Skipped = result.Attempted - result.Inserted
	return result, tx.Commit()
}

// BulkCreateEndpoints inserts multiple endpoints in a single transaction.
// Duplicates (same host_id + url + method) are silently skipped.
func (s *SQLiteStore) BulkCreateEndpoints(ctx context.Context, endpoints []*models.Endpoint) (*BulkResult, error) {
	result := &BulkResult{Attempted: len(endpoints)}
	if len(endpoints) == 0 {
		return result, nil
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO endpoints (
			id, project_id, host_id, url, method, status, content_type, title,
			parameters_json, notes, found_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	now := utils.CurrentTime()
	for _, ep := range endpoints {
		if ep.ID == "" {
			ep.ID = uuid.New().String()
		}
		if ep.CreatedAt.IsZero() {
			ep.CreatedAt = now
		}
		ep.UpdatedAt = now

		parametersJSON, err := utils.MarshalJSON(ep.Parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal parameters: %w", err)
		}

		res, err := stmt.ExecContext(ctx,
			ep.ID, ep.ProjectID, ep.HostID, ep.URL, ep.Method,
			ep.Status, ep.ContentType, ep.Title, parametersJSON, ep.Notes,
			ep.FoundBy, ep.CreatedAt, ep.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert endpoint %s: %w", ep.URL, err)
		}

		n, _ := res.RowsAffected()
		result.Inserted += int(n)
	}

	result.Skipped = result.Attempted - result.Inserted
	return result, tx.Commit()
}

// BulkCreateFindings inserts multiple findings in a single transaction.
// Duplicates (same primary key) are silently skipped.
func (s *SQLiteStore) BulkCreateFindings(ctx context.Context, findings []*models.Finding) (*BulkResult, error) {
	result := &BulkResult{Attempted: len(findings)}
	if len(findings) == 0 {
		return result, nil
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO findings (
			id, project_id, type, title, description, details, severity, confidence, status, url,
			cvss, cvss_vector, cvss_version, cwe, steps_json, evidence_json, evidence_map_json, metadata_json, impact, remediation, references_json,
			found_by, found_at, affected_assets_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	now := utils.CurrentTime()
	for _, finding := range findings {
		if finding.ID == "" {
			finding.ID = uuid.New().String()
		}
		if finding.CreatedAt.IsZero() {
			finding.CreatedAt = now
		}
		if finding.UpdatedAt.IsZero() {
			finding.UpdatedAt = now
		}
		if finding.Type == "" {
			finding.Type = models.FindingTypeVulnerability
		}
		if finding.Confidence == "" {
			finding.Confidence = models.ConfidenceMedium
		}
		if finding.FoundAt.IsZero() {
			finding.FoundAt = now
		}

		stepsJSON, err := utils.ToJSON(finding.Steps)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal steps: %w", err)
		}
		evidenceJSON, err := utils.ToJSON(finding.Evidence)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal evidence: %w", err)
		}
		metadataJSON, err := utils.ToJSON(finding.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		referencesJSON, err := utils.ToJSON(finding.References)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal references: %w", err)
		}
		affectedAssetsJSON, err := utils.ToJSON(finding.AffectedAssets)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal affected assets: %w", err)
		}

		res, err := stmt.ExecContext(ctx,
			finding.ID, finding.ProjectID, finding.Type, finding.Title, finding.Description,
			finding.Details, finding.Severity, finding.Confidence, finding.Status, finding.URL,
			finding.CVSS, finding.CVSSVector, finding.CVSSVersion, finding.CWE, stepsJSON, "[]", evidenceJSON, metadataJSON, finding.Impact, finding.Remediation,
			referencesJSON, finding.FoundBy, finding.FoundAt, affectedAssetsJSON,
			finding.CreatedAt, finding.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert finding %s: %w", finding.Title, err)
		}

		n, _ := res.RowsAffected()
		result.Inserted += int(n)
	}

	result.Skipped = result.Attempted - result.Inserted
	return result, tx.Commit()
}
