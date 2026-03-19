package domain

import "time"

// WebAuthnCredential represents a registered WebAuthn/passkey credential for a user.
type WebAuthnCredential struct {
	ID              string     `json:"id"`
	UserID          string     `json:"user_id"`
	CredentialID    string     `json:"credential_id"`
	PublicKey       string     `json:"-"`
	AttestationType string     `json:"attestation_type"`
	AAGUID          string     `json:"aaguid"`
	SignCount       uint32     `json:"sign_count"`
	Transports      []string   `json:"transports"`
	Name            string     `json:"name"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
}

// UserTOTP holds a user's TOTP enrollment. Secret is encrypted at rest.
type UserTOTP struct {
	UserID    string    `json:"user_id"`
	Secret    string    `json:"-"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

// MFAChallenge is a short-lived token issued after password verification
// when MFA is enabled. It must be consumed by a second-factor verification
// within its expiry window.
type MFAChallenge struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}
