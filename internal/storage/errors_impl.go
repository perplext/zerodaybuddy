package storage

import (
	"context"
	"database/sql"

	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// GetProjectWithErrors retrieves a project by ID with improved error handling
func (s *SQLiteStore) GetProjectWithErrors(ctx context.Context, id string) (*models.Project, error) {
	var project models.Project
	var scopeJSON string
	
	err := s.db.QueryRowContext(ctx, `
		SELECT 
			id, name, handle, platform, description, start_date, end_date, 
			status, scope_json, notes, created_at, updated_at
		FROM projects
		WHERE id = ?
	`, id).Scan(
		&project.ID, &project.Name, &project.Handle, &project.Platform, &project.Description,
		&project.StartDate, &project.EndDate, &project.Status, &scopeJSON, &project.Notes,
		&project.CreatedAt, &project.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, pkgerrors.NotFoundError("project", id)
		}
		return nil, pkgerrors.InternalError("failed to get project", err).
			WithContext("projectID", id)
	}
	
	// Deserialize scope from JSON
	if err := utils.UnmarshalJSON(scopeJSON, &project.Scope); err != nil {
		return nil, pkgerrors.InternalError("failed to unmarshal scope", err).
			WithContext("projectID", id)
	}
	
	return &project, nil
}

// GetProjectByNameWithErrors retrieves a project by name with improved error handling
func (s *SQLiteStore) GetProjectByNameWithErrors(ctx context.Context, name string) (*models.Project, error) {
	var project models.Project
	var scopeJSON string
	
	err := s.db.QueryRowContext(ctx, `
		SELECT 
			id, name, handle, platform, description, start_date, end_date, 
			status, scope_json, notes, created_at, updated_at
		FROM projects
		WHERE name = ?
	`, name).Scan(
		&project.ID, &project.Name, &project.Handle, &project.Platform, &project.Description,
		&project.StartDate, &project.EndDate, &project.Status, &scopeJSON, &project.Notes,
		&project.CreatedAt, &project.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, pkgerrors.NotFoundError("project", name).
				WithContext("searchField", "name")
		}
		return nil, pkgerrors.InternalError("failed to get project by name", err).
			WithContext("projectName", name)
	}
	
	// Deserialize scope from JSON
	if err := utils.UnmarshalJSON(scopeJSON, &project.Scope); err != nil {
		return nil, pkgerrors.InternalError("failed to unmarshal scope", err).
			WithContext("projectName", name)
	}
	
	return &project, nil
}

// UpdateProjectWithErrors updates a project with improved error handling
func (s *SQLiteStore) UpdateProjectWithErrors(ctx context.Context, project *models.Project) error {
	// Update timestamp
	project.UpdatedAt = utils.CurrentTime()
	
	// Serialize scope to JSON
	scopeJSON, err := utils.MarshalJSON(project.Scope)
	if err != nil {
		return pkgerrors.InternalError("failed to marshal scope", err).
			WithContext("projectID", project.ID)
	}
	
	result, err := s.db.ExecContext(ctx, `
		UPDATE projects SET
			name = ?, handle = ?, platform = ?, description = ?, start_date = ?, 
			end_date = ?, status = ?, scope_json = ?, notes = ?, updated_at = ?
		WHERE id = ?
	`,
		project.Name, project.Handle, project.Platform, project.Description,
		project.StartDate, project.EndDate, project.Status, scopeJSON, project.Notes,
		project.UpdatedAt, project.ID,
	)
	
	if err != nil {
		if isUniqueConstraintError(err) {
			return pkgerrors.ConflictError("project", "project with this name already exists").
				WithContext("name", project.Name)
		}
		return pkgerrors.InternalError("failed to update project", err).
			WithContext("projectID", project.ID)
	}
	
	rows, err := result.RowsAffected()
	if err != nil {
		return pkgerrors.InternalError("failed to get rows affected", err).
			WithContext("projectID", project.ID)
	}
	
	if rows == 0 {
		return pkgerrors.NotFoundError("project", project.ID)
	}
	
	return nil
}

// DeleteProjectWithErrors deletes a project with improved error handling
func (s *SQLiteStore) DeleteProjectWithErrors(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", id)
	if err != nil {
		return pkgerrors.InternalError("failed to delete project", err).
			WithContext("projectID", id)
	}
	
	rows, err := result.RowsAffected()
	if err != nil {
		return pkgerrors.InternalError("failed to get rows affected", err).
			WithContext("projectID", id)
	}
	
	if rows == 0 {
		return pkgerrors.NotFoundError("project", id)
	}
	
	return nil
}

// CreateHostWithErrors creates a new host with improved error handling
func (s *SQLiteStore) CreateHostWithErrors(ctx context.Context, host *models.Host) error {
	// Validate project exists
	project, err := s.GetProjectWithErrors(ctx, host.ProjectID)
	if err != nil {
		if pkgerrors.Is(err, pkgerrors.ErrorTypeNotFound) {
			return pkgerrors.ValidationError("project does not exist").
				WithContext("projectID", host.ProjectID)
		}
		return err
	}
	
	// Validate host is in scope
	if !project.Scope.IsInScope(host.Type, host.Value) {
		return pkgerrors.ValidationError("host is not in project scope").
			WithContext("host", host.Value).
			WithContext("type", host.Type)
	}
	
	// Continue with normal creation...
	return s.CreateHost(ctx, host)
}

// CreateEndpointWithErrors creates a new endpoint with improved error handling
func (s *SQLiteStore) CreateEndpointWithErrors(ctx context.Context, endpoint *models.Endpoint) error {
	// Validate project exists
	_, err := s.GetProjectWithErrors(ctx, endpoint.ProjectID)
	if err != nil {
		if pkgerrors.Is(err, pkgerrors.ErrorTypeNotFound) {
			return pkgerrors.ValidationError("project does not exist").
				WithContext("projectID", endpoint.ProjectID)
		}
		return err
	}
	
	// Validate host exists
	_, err = s.GetHost(ctx, endpoint.HostID)
	if err != nil {
		if err == sql.ErrNoRows {
			return pkgerrors.ValidationError("host does not exist").
				WithContext("hostID", endpoint.HostID)
		}
		return pkgerrors.InternalError("failed to validate host", err).
			WithContext("hostID", endpoint.HostID)
	}
	
	// Continue with normal creation...
	return s.CreateEndpoint(ctx, endpoint)
}