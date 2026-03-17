CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
