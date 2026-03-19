package auth

import (
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPProvider handles TOTP secret generation and validation.
type TOTPProvider struct{}

// GenerateSecret creates a new TOTP secret for a user.
// Returns the OTP key which contains the secret and provisioning URI for QR codes.
func (p *TOTPProvider) GenerateSecret(username, issuer string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
}

// Validate checks a TOTP code against a secret.
func (p *TOTPProvider) Validate(code, secret string) bool {
	return totp.Validate(code, secret)
}
