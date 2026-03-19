package auth

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// WebAuthnProvider manages WebAuthn registration and authentication ceremonies.
type WebAuthnProvider struct {
	wa       *webauthn.WebAuthn
	sessions sync.Map // challenge ID → *sessionEntry
}

type sessionEntry struct {
	data      *webauthn.SessionData
	expiresAt time.Time
}

// NewWebAuthnProvider creates a WebAuthn provider using the full FQDN from baseURL as the RP ID.
func NewWebAuthnProvider(baseURL string) (*WebAuthnProvider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse BASE_URL for webauthn: %w", err)
	}

	rpID := u.Hostname() // full FQDN, e.g. "wg.example.com"
	rpOrigin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	wconfig := &webauthn.Config{
		RPDisplayName: "WireGuard UI",
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}

	p := &WebAuthnProvider{wa: wa}

	// Background cleanup of expired session data
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			p.sessions.Range(func(key, value any) bool {
				if entry, ok := value.(*sessionEntry); ok && now.After(entry.expiresAt) {
					p.sessions.Delete(key)
				}
				return true
			})
		}
	}()

	return p, nil
}

// RPID returns the Relying Party ID (full FQDN).
func (p *WebAuthnProvider) RPID() string {
	return p.wa.Config.RPID
}

// StoreSession saves WebAuthn session data keyed by a challenge ID.
func (p *WebAuthnProvider) StoreSession(challengeID string, data *webauthn.SessionData) {
	p.sessions.Store(challengeID, &sessionEntry{
		data:      data,
		expiresAt: time.Now().Add(5 * time.Minute),
	})
}

// ConsumeSession retrieves and removes WebAuthn session data for a challenge ID.
func (p *WebAuthnProvider) ConsumeSession(challengeID string) (*webauthn.SessionData, bool) {
	val, ok := p.sessions.LoadAndDelete(challengeID)
	if !ok {
		return nil, false
	}
	entry := val.(*sessionEntry)
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.data, true
}

// BeginRegistration starts a WebAuthn registration ceremony.
func (p *WebAuthnProvider) BeginRegistration(user *WebAuthnUser) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return p.wa.BeginRegistration(user)
}

// FinishRegistration completes a WebAuthn registration ceremony.
func (p *WebAuthnProvider) FinishRegistration(user *WebAuthnUser, sessionData *webauthn.SessionData, response *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	return p.wa.CreateCredential(user, *sessionData, response)
}

// BeginLogin starts a WebAuthn authentication ceremony for a specific user.
func (p *WebAuthnProvider) BeginLogin(user *WebAuthnUser) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return p.wa.BeginLogin(user)
}

// FinishLogin completes a WebAuthn authentication ceremony.
func (p *WebAuthnProvider) FinishLogin(user *WebAuthnUser, sessionData *webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	return p.wa.ValidateLogin(user, *sessionData, response)
}

// BeginDiscoverableLogin starts a passwordless WebAuthn ceremony (no user specified).
func (p *WebAuthnProvider) BeginDiscoverableLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return p.wa.BeginDiscoverableLogin()
}

// FinishDiscoverableLogin completes a passwordless WebAuthn ceremony.
func (p *WebAuthnProvider) FinishDiscoverableLogin(handler webauthn.DiscoverableUserHandler, sessionData *webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	return p.wa.ValidateDiscoverableLogin(handler, *sessionData, response)
}

// WebAuthnUser adapts a domain.User + credentials to the webauthn.User interface.
type WebAuthnUser struct {
	User        *domain.User
	Credentials []domain.WebAuthnCredential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.User.ID)
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.User.Username
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.User.Name != "" {
		return u.User.Name
	}
	return u.User.Username
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, 0, len(u.Credentials))
	for _, c := range u.Credentials {
		credID, _ := base64.RawURLEncoding.DecodeString(c.CredentialID)
		pubKey, _ := base64.RawURLEncoding.DecodeString(c.PublicKey)

		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
		for _, t := range c.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}

		creds = append(creds, webauthn.Credential{
			ID:              credID,
			PublicKey:       pubKey,
			AttestationType: c.AttestationType,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
			Transport: transports,
		})
	}
	return creds
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

// CredentialToDomain converts a webauthn.Credential to a domain.WebAuthnCredential.
func CredentialToDomain(userID string, cred *webauthn.Credential, name string) *domain.WebAuthnCredential {
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	aaguid := ""
	if len(cred.Authenticator.AAGUID) > 0 {
		aaguid = base64.RawURLEncoding.EncodeToString(cred.Authenticator.AAGUID)
	}

	return &domain.WebAuthnCredential{
		UserID:          userID,
		CredentialID:    base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:       base64.RawURLEncoding.EncodeToString(cred.PublicKey),
		AttestationType: cred.AttestationType,
		AAGUID:          aaguid,
		SignCount:       cred.Authenticator.SignCount,
		Transports:      transports,
		Name:            name,
		CreatedAt:       time.Now(),
	}
}
