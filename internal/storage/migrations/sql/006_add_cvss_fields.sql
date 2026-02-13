-- +migrate Up
ALTER TABLE findings ADD COLUMN cvss_vector TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN cvss_version TEXT DEFAULT '';

-- +migrate Down
-- SQLite before 3.35.0 does not support DROP COLUMN; these columns are harmless if left.
