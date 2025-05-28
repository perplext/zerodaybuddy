package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/google/uuid"
)

// CreateTask creates a new task
func (s *SQLiteStore) CreateTask(ctx context.Context, task *models.Task) error {
	// Generate ID if not provided
	if task.ID == "" {
		task.ID = uuid.New().String()
	}
	
	// Set timestamps
	now := utils.CurrentTime()
	if task.CreatedAt.IsZero() {
		task.CreatedAt = now
	}
	if task.UpdatedAt.IsZero() {
		task.UpdatedAt = now
	}
	if task.StartedAt.IsZero() {
		task.StartedAt = now
	}
	
	// Serialize JSON fields
	detailsJSON, err := utils.ToJSON(task.Details)
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}
	
	resultJSON, err := utils.ToJSON(task.Result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}
	
	metadataJSON, err := utils.ToJSON(task.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	
	// Insert task
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO tasks (
			id, project_id, type, name, description, status, priority, assigned_to,
			progress, details_json, result_json, metadata_json,
			started_at, completed_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		task.ID, task.ProjectID, task.Type, task.Name, task.Description,
		task.Status, task.Priority, task.AssignedTo, task.Progress,
		detailsJSON, resultJSON, metadataJSON, task.StartedAt, task.CompletedAt,
		task.CreatedAt, task.UpdatedAt,
	)
	
	if err != nil {
		return fmt.Errorf("failed to create task: %w", err)
	}
	
	return nil
}

// GetTask retrieves a task by ID
func (s *SQLiteStore) GetTask(ctx context.Context, id string) (*models.Task, error) {
	var task models.Task
	var detailsJSON, resultJSON, metadataJSON string
	var completedAt sql.NullTime
	var description, priority, assignedTo sql.NullString
	
	err := s.db.QueryRowContext(ctx, `
		SELECT 
			id, project_id, type, name, description, status, priority, assigned_to,
			progress, details_json, result_json, metadata_json,
			started_at, completed_at, created_at, updated_at
		FROM tasks
		WHERE id = ?
	`, id).Scan(
		&task.ID, &task.ProjectID, &task.Type, &task.Name, &description,
		&task.Status, &priority, &assignedTo, &task.Progress,
		&detailsJSON, &resultJSON, &metadataJSON, &task.StartedAt, &completedAt,
		&task.CreatedAt, &task.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get task: %w", err)
	}
	
	// Handle nullable fields
	if completedAt.Valid {
		task.CompletedAt = completedAt.Time
	}
	if description.Valid {
		task.Description = description.String
	}
	if priority.Valid {
		task.Priority = priority.String
	}
	if assignedTo.Valid {
		task.AssignedTo = assignedTo.String
	}
	
	// Deserialize JSON fields
	if err := utils.FromJSON(detailsJSON, &task.Details); err != nil {
		return nil, fmt.Errorf("failed to unmarshal details: %w", err)
	}
	if err := utils.FromJSON(resultJSON, &task.Result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}
	if err := utils.FromJSON(metadataJSON, &task.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	
	return &task, nil
}

// UpdateTask updates a task
func (s *SQLiteStore) UpdateTask(ctx context.Context, task *models.Task) error {
	// Update timestamp
	task.UpdatedAt = utils.CurrentTime()
	
	// Serialize JSON fields
	detailsJSON, err := utils.ToJSON(task.Details)
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}
	
	resultJSON, err := utils.ToJSON(task.Result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}
	
	metadataJSON, err := utils.ToJSON(task.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	
	result, err := s.db.ExecContext(ctx, `
		UPDATE tasks SET
			type = ?, name = ?, description = ?, status = ?, priority = ?, assigned_to = ?,
			progress = ?, details_json = ?, result_json = ?, metadata_json = ?,
			started_at = ?, completed_at = ?, updated_at = ?
		WHERE id = ?
	`,
		task.Type, task.Name, task.Description, task.Status, task.Priority, task.AssignedTo,
		task.Progress, detailsJSON, resultJSON, metadataJSON,
		task.StartedAt, task.CompletedAt, task.UpdatedAt, task.ID,
	)
	
	if err != nil {
		return fmt.Errorf("failed to update task: %w", err)
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

// ListTasks lists all tasks for a project
func (s *SQLiteStore) ListTasks(ctx context.Context, projectID string) ([]*models.Task, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			id, project_id, type, name, description, status, priority, assigned_to,
			progress, details_json, result_json, metadata_json,
			started_at, completed_at, created_at, updated_at
		FROM tasks
		WHERE project_id = ?
		ORDER BY created_at DESC
	`, projectID)
	
	if err != nil {
		return nil, fmt.Errorf("failed to list tasks: %w", err)
	}
	defer rows.Close()
	
	var tasks []*models.Task
	for rows.Next() {
		var task models.Task
		var detailsJSON, resultJSON, metadataJSON string
		var completedAt sql.NullTime
		var description, priority, assignedTo sql.NullString
		
		err := rows.Scan(
			&task.ID, &task.ProjectID, &task.Type, &task.Name, &description,
			&task.Status, &priority, &assignedTo, &task.Progress,
			&detailsJSON, &resultJSON, &metadataJSON, &task.StartedAt, &completedAt,
			&task.CreatedAt, &task.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan task: %w", err)
		}
		
		// Handle nullable fields
		if completedAt.Valid {
			task.CompletedAt = completedAt.Time
		}
		if description.Valid {
			task.Description = description.String
		}
		if priority.Valid {
			task.Priority = priority.String
		}
		if assignedTo.Valid {
			task.AssignedTo = assignedTo.String
		}
		
		// Deserialize JSON fields
		if err := utils.FromJSON(detailsJSON, &task.Details); err != nil {
			return nil, fmt.Errorf("failed to unmarshal details: %w", err)
		}
		if err := utils.FromJSON(resultJSON, &task.Result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal result: %w", err)
		}
		if err := utils.FromJSON(metadataJSON, &task.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
		
		tasks = append(tasks, &task)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tasks: %w", err)
	}
	
	return tasks, nil
}

// DeleteTask deletes a task
func (s *SQLiteStore) DeleteTask(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM tasks WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete task: %w", err)
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