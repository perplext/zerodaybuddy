package storage

import (
	"context"
	"fmt"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// UpdateEndpoint updates an endpoint
func (s *SQLiteStore) UpdateEndpoint(ctx context.Context, endpoint *models.Endpoint) error {
	// Update timestamp
	endpoint.UpdatedAt = utils.CurrentTime()
	
	// Serialize parameters to JSON
	parametersJSON, err := utils.MarshalJSON(endpoint.Parameters)
	if err != nil {
		return fmt.Errorf("failed to marshal parameters: %w", err)
	}
	
	result, err := s.db.ExecContext(ctx, `
		UPDATE endpoints SET
			url = ?, method = ?, status = ?, content_type = ?, title = ?,
			parameters_json = ?, notes = ?, found_by = ?, updated_at = ?
		WHERE id = ?
	`,
		endpoint.URL, endpoint.Method, endpoint.Status, endpoint.ContentType,
		endpoint.Title, parametersJSON, endpoint.Notes, endpoint.FoundBy,
		endpoint.UpdatedAt, endpoint.ID,
	)
	
	if err != nil {
		return fmt.Errorf("failed to update endpoint: %w", err)
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

// ListEndpoints lists all endpoints for a host
func (s *SQLiteStore) ListEndpoints(ctx context.Context, hostID string) ([]*models.Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			id, project_id, host_id, url, method, status, content_type, title,
			parameters_json, notes, found_by, created_at, updated_at
		FROM endpoints
		WHERE host_id = ?
		ORDER BY url, method
	`, hostID)
	
	if err != nil {
		return nil, fmt.Errorf("failed to list endpoints: %w", err)
	}
	defer rows.Close()
	
	var endpoints []*models.Endpoint
	for rows.Next() {
		var endpoint models.Endpoint
		var parametersJSON string
		
		err := rows.Scan(
			&endpoint.ID, &endpoint.ProjectID, &endpoint.HostID, &endpoint.URL,
			&endpoint.Method, &endpoint.Status, &endpoint.ContentType, &endpoint.Title,
			&parametersJSON, &endpoint.Notes, &endpoint.FoundBy,
			&endpoint.CreatedAt, &endpoint.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan endpoint: %w", err)
		}
		
		// Deserialize parameters from JSON
		if err := utils.UnmarshalJSON(parametersJSON, &endpoint.Parameters); err != nil {
			return nil, fmt.Errorf("failed to unmarshal parameters: %w", err)
		}
		
		endpoints = append(endpoints, &endpoint)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate endpoints: %w", err)
	}
	
	return endpoints, nil
}

// ListEndpointsByProject lists all endpoints for a project
func (s *SQLiteStore) ListEndpointsByProject(ctx context.Context, projectID string) ([]*models.Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			id, project_id, host_id, url, method, status, content_type, title,
			parameters_json, notes, found_by, created_at, updated_at
		FROM endpoints
		WHERE project_id = ?
		ORDER BY url, method
	`, projectID)

	if err != nil {
		return nil, fmt.Errorf("failed to list endpoints by project: %w", err)
	}
	defer rows.Close()

	var endpoints []*models.Endpoint
	for rows.Next() {
		var endpoint models.Endpoint
		var parametersJSON string

		err := rows.Scan(
			&endpoint.ID, &endpoint.ProjectID, &endpoint.HostID, &endpoint.URL,
			&endpoint.Method, &endpoint.Status, &endpoint.ContentType, &endpoint.Title,
			&parametersJSON, &endpoint.Notes, &endpoint.FoundBy,
			&endpoint.CreatedAt, &endpoint.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan endpoint: %w", err)
		}

		// Deserialize parameters from JSON
		if err := utils.UnmarshalJSON(parametersJSON, &endpoint.Parameters); err != nil {
			return nil, fmt.Errorf("failed to unmarshal parameters: %w", err)
		}

		endpoints = append(endpoints, &endpoint)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate endpoints: %w", err)
	}

	return endpoints, nil
}

// DeleteEndpoint deletes an endpoint
func (s *SQLiteStore) DeleteEndpoint(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM endpoints WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete endpoint: %w", err)
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
