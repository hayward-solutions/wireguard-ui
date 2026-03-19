-- Store WebAuthn backup eligibility flags to avoid login validation failures.
ALTER TABLE user_webauthn_credentials ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_webauthn_credentials ADD COLUMN backup_state INTEGER NOT NULL DEFAULT 0;
