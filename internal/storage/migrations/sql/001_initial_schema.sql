-- Description: Initial database schema for BugBase

-- +migrate Up
-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    handle TEXT NOT NULL,
    platform TEXT NOT NULL,
    description TEXT,
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP,
    status TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    UNIQUE(name)
);

CREATE INDEX idx_projects_name ON projects(name);
CREATE INDEX idx_projects_platform ON projects(platform);
CREATE INDEX idx_projects_status ON projects(status);

-- Hosts table
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    ip TEXT,
    status TEXT NOT NULL,
    title TEXT,
    technologies_json TEXT,
    ports_json TEXT,
    headers_json TEXT,
    screenshot TEXT,
    notes TEXT,
    found_by TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE(project_id, value)
);

CREATE INDEX idx_hosts_project_id ON hosts(project_id);
CREATE INDEX idx_hosts_type ON hosts(type);
CREATE INDEX idx_hosts_value ON hosts(value);
CREATE INDEX idx_hosts_status ON hosts(status);

-- Endpoints table
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT,
    status INTEGER,
    content_type TEXT,
    title TEXT,
    parameters_json TEXT,
    notes TEXT,
    found_by TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    UNIQUE(host_id, url, method)
);

CREATE INDEX idx_endpoints_project_id ON endpoints(project_id);
CREATE INDEX idx_endpoints_host_id ON endpoints(host_id);
CREATE INDEX idx_endpoints_status ON endpoints(status);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    cvss REAL,
    cwe TEXT,
    steps_json TEXT,
    evidence_json TEXT,
    impact TEXT,
    remediation TEXT,
    references_json TEXT,
    found_by TEXT NOT NULL,
    found_at TIMESTAMP NOT NULL,
    affected_assets_json TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX idx_findings_project_id ON findings(project_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);

-- Tasks table
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL,
    priority TEXT,
    assigned_to TEXT,
    progress INTEGER NOT NULL,
    details_json TEXT,
    result_json TEXT,
    metadata_json TEXT,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX idx_tasks_project_id ON tasks(project_id);
CREATE INDEX idx_tasks_type ON tasks(type);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_priority ON tasks(priority);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    finding_id TEXT,
    title TEXT NOT NULL,
    format TEXT NOT NULL,
    content TEXT NOT NULL,
    metadata_json TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX idx_reports_project_id ON reports(project_id);
CREATE INDEX idx_reports_finding_id ON reports(finding_id);
CREATE INDEX idx_reports_format ON reports(format);

-- +migrate Down
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS tasks;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS endpoints;
DROP TABLE IF EXISTS hosts;
DROP TABLE IF EXISTS projects;