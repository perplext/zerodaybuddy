-- Description: Add authentication tables (users and sessions)

-- +migrate Up
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'active',
    last_login TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Create indexes for users table
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for sessions table
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_created_at ON sessions(created_at);

-- Create default admin user (password: AdminPass123!)
INSERT OR IGNORE INTO users (
    id, username, email, full_name, password_hash, role, status, created_at, updated_at
) VALUES (
    'admin-001',
    'admin',
    'admin@bugbase.local',
    'Administrator',
    '$argon2id$v=19$m=65536,t=1,p=4$UXW6JNPves/2q5rw+mrAzA$89/48zuwa8Rb7YckytU3Y8gwl5evnTT3RMANocg9Z7w',
    'admin',
    'active',
    datetime('now'),
    datetime('now')
);

-- +migrate Down
-- Drop sessions table first due to foreign key constraint
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;