-- Description: Add audit fields for tracking data changes

-- +migrate Up
-- Add audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    table_name TEXT NOT NULL,
    record_id TEXT NOT NULL,
    action TEXT NOT NULL, -- INSERT, UPDATE, DELETE
    user_id TEXT,
    changes_json TEXT,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_audit_logs_table_name ON audit_logs(table_name);
CREATE INDEX idx_audit_logs_record_id ON audit_logs(record_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- Add created_by and updated_by to projects
ALTER TABLE projects ADD COLUMN created_by TEXT;
ALTER TABLE projects ADD COLUMN updated_by TEXT;

-- Add created_by and updated_by to hosts
ALTER TABLE hosts ADD COLUMN created_by TEXT;
ALTER TABLE hosts ADD COLUMN updated_by TEXT;

-- Add created_by and updated_by to endpoints
ALTER TABLE endpoints ADD COLUMN created_by TEXT;
ALTER TABLE endpoints ADD COLUMN updated_by TEXT;

-- Add created_by and updated_by to findings
ALTER TABLE findings ADD COLUMN created_by TEXT;
ALTER TABLE findings ADD COLUMN updated_by TEXT;

-- Add created_by and updated_by to tasks
ALTER TABLE tasks ADD COLUMN created_by TEXT;
ALTER TABLE tasks ADD COLUMN updated_by TEXT;

-- Add created_by and updated_by to reports
ALTER TABLE reports ADD COLUMN created_by TEXT;
ALTER TABLE reports ADD COLUMN updated_by TEXT;

-- +migrate Down
-- Note: SQLite doesn't support DROP COLUMN, so we need to recreate tables
-- This is a simplified rollback that just drops the audit_logs table
DROP TABLE IF EXISTS audit_logs;

-- In a real rollback, you would need to:
-- 1. Create new tables without the audit columns
-- 2. Copy data from old tables
-- 3. Drop old tables
-- 4. Rename new tables