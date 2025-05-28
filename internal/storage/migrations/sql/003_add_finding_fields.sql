-- Description: Add additional fields to findings table for vulnerability scanning

-- +migrate Up
-- Add missing fields to findings table
ALTER TABLE findings ADD COLUMN type TEXT DEFAULT 'vulnerability';
ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'medium';
ALTER TABLE findings ADD COLUMN url TEXT;
ALTER TABLE findings ADD COLUMN details TEXT;
ALTER TABLE findings ADD COLUMN evidence_map_json TEXT;
ALTER TABLE findings ADD COLUMN metadata_json TEXT;

-- Create indexes for new fields
CREATE INDEX idx_findings_type ON findings(type);
CREATE INDEX idx_findings_confidence ON findings(confidence);

-- +migrate Down
-- Note: SQLite doesn't support DROP COLUMN directly
-- In a real rollback, you would need to:
-- 1. Create a new table without the new columns
-- 2. Copy data from old table
-- 3. Drop old table
-- 4. Rename new table