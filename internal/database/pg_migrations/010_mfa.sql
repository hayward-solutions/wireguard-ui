-- WebAuthn credentials (multiple per user)
CREATE TABLE IF NOT EXISTS user_webauthn_credentials (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   TEXT NOT NULL UNIQUE,
    public_key      TEXT NOT NULL,
    attestation_type TEXT NOT NULL DEFAULT '',
    aaguid          TEXT NOT NULL DEFAULT '',
    sign_count      INTEGER NOT NULL DEFAULT 0,
    transports      JSONB NOT NULL DEFAULT '[]',
    name            TEXT NOT NULL DEFAULT 'Security Key',
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at    TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON user_webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON user_webauthn_credentials(credential_id);

-- TOTP secrets (one per user)
CREATE TABLE IF NOT EXISTS user_totp (
    user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret      TEXT NOT NULL,
    verified    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- MFA challenge tokens (short-lived, for 2-step login)
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);

-- MFA enabled flag on users
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
