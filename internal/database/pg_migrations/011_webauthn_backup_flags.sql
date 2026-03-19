-- Store WebAuthn backup eligibility flags to avoid login validation failures.
ALTER TABLE user_webauthn_credentials ADD COLUMN backup_eligible BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE user_webauthn_credentials ADD COLUMN backup_state BOOLEAN NOT NULL DEFAULT FALSE;
