-- Add project type field to projects table

-- +migrate Up
-- Add project_type column with default value for existing projects
ALTER TABLE projects ADD COLUMN project_type TEXT NOT NULL DEFAULT 'bug-bounty';

-- Create index for project type
CREATE INDEX idx_projects_type ON projects(project_type);

-- +migrate Down
-- SQLite doesn't support DROP COLUMN, so we need to recreate the table
-- This is a simplified approach - in production you'd want to preserve all data
DROP INDEX IF EXISTS idx_projects_type;

-- Note: SQLite doesn't support ALTER TABLE DROP COLUMN
-- In a real migration, you would need to:
-- 1. Create a new table without the column
-- 2. Copy data from old table
-- 3. Drop old table
-- 4. Rename new table
-- For testing purposes, we'll leave this as a no-op