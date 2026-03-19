package api

import (
	"encoding/json"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// --- Request DTOs ---

// LoginRequest is the request body for local username/password login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// CreatePeerRequest is the request body for creating a new peer.
type CreatePeerRequest struct {
	Name                string `json:"name"`
	AllowedIPs          string `json:"allowed_ips"`
	DNS                 string `json:"dns"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
	PublicKey           string `json:"public_key"`
}

// UpdatePeerRequest is the request body for updating a peer.
type UpdatePeerRequest struct {
	Name                string `json:"name"`
	AllowedIPs          string `json:"allowed_ips"`
	DNS                 string `json:"dns"`
	PersistentKeepalive *int   `json:"persistent_keepalive"`
}

// RegeneratePeerRequest is the request body for regenerating peer keys.
type RegeneratePeerRequest struct {
	PublicKey string `json:"public_key"`
}

// CreateTunnelRequest is the request body for creating a new tunnel.
type CreateTunnelRequest struct {
	Name                string `json:"name"`
	Description         string `json:"description"`
	PrivateKey          string `json:"private_key"`
	PublicKey           string `json:"public_key"`
	Address             string `json:"address"`
	ListenPort          int    `json:"listen_port"`
	DNS                 string `json:"dns"`
	MTU                 int    `json:"mtu"`
	PeerPublicKey       string `json:"peer_public_key"`
	PeerEndpoint        string `json:"peer_endpoint"`
	PresharedKey        string `json:"preshared_key"`
	PeerAllowedIPs      string `json:"peer_allowed_ips"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
}

// UpdateTunnelRequest is the request body for updating a tunnel.
type UpdateTunnelRequest struct {
	Name                *string `json:"name"`
	Description         *string `json:"description"`
	Address             *string `json:"address"`
	ListenPort          *int    `json:"listen_port"`
	DNS                 *string `json:"dns"`
	MTU                 *int    `json:"mtu"`
	PeerPublicKey       *string `json:"peer_public_key"`
	PeerEndpoint        *string `json:"peer_endpoint"`
	PeerAllowedIPs      *string `json:"peer_allowed_ips"`
	PersistentKeepalive *int    `json:"persistent_keepalive"`
}

// UpdateServerRequest is the request body for updating server configuration.
type UpdateServerRequest struct {
	ListenPort        int                    `json:"listen_port"`
	Address           string                 `json:"address"`
	DNS               string                 `json:"dns"`
	MTU               int                    `json:"mtu"`
	FirewallConfig    *domain.FirewallConfig `json:"firewall_config,omitempty"`
	PostUp            string                 `json:"post_up"`
	PostDown          string                 `json:"post_down"`
	Endpoint          string                 `json:"endpoint"`
	DefaultAllowedIPs *string                `json:"default_allowed_ips"`
	DefaultDNS        *string                `json:"default_dns"`
	TunnelSubnet      *string                `json:"tunnel_subnet"`
}

// CreateUserRequest is the request body for creating a new user.
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

// UpdateUserRequest is the request body for updating a user.
type UpdateUserRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

// ResetPasswordRequest is the request body for admin password reset.
type ResetPasswordRequest struct {
	Password string `json:"password"`
}

// ChangePasswordRequest is the request body for self-service password change.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// CreateGroupRequest is the request body for creating a group.
type CreateGroupRequest struct {
	Name string `json:"name"`
}

// UpdateGroupRequest is the request body for updating a group.
type UpdateGroupRequest struct {
	Name string `json:"name"`
}

// SetUserGroupsRequest is the request body for setting a user's group memberships.
type SetUserGroupsRequest struct {
	GroupIDs []string `json:"group_ids"`
}

// CreateACLRuleRequest is the request body for creating an ACL rule.
type CreateACLRuleRequest struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Priority    int     `json:"priority"`
	Protocol    string  `json:"protocol"`
	DstCIDR     string  `json:"dst_cidr"`
	DstPorts    string  `json:"dst_ports"`
	GroupID     *string `json:"group_id"`
	UserID      *string `json:"user_id"`
	Enabled     *bool   `json:"enabled"`
}

// UpdateACLRuleRequest is the request body for updating an ACL rule.
type UpdateACLRuleRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Priority    *int    `json:"priority"`
	Protocol    *string `json:"protocol"`
	DstCIDR     *string `json:"dst_cidr"`
	DstPorts    *string `json:"dst_ports"`
	GroupID     *string `json:"group_id"`
	UserID      *string `json:"user_id"`
	Enabled     *bool   `json:"enabled"`
}

// CreateTokenRequest is the request body for creating an API token.
type CreateTokenRequest struct {
	Name      string `json:"name"`
	ExpiresIn string `json:"expires_in"` // e.g. "720h" (30 days)
}

// TOTPVerifyRequest is the request body for verifying a TOTP code.
type TOTPVerifyRequest struct {
	Code string `json:"code"`
}

// MFATokenRequest is the request body containing an MFA token.
type MFATokenRequest struct {
	MFAToken string `json:"mfa_token"`
}

// MFAChallengeRequest is the request body for MFA TOTP challenge.
type MFAChallengeRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

// WebAuthnRegisterFinishRequest is the wrapper for WebAuthn registration completion.
type WebAuthnRegisterFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Name        string          `json:"name"`
	Response    json.RawMessage `json:"response"`
}

// MFAWebAuthnFinishRequest is the wrapper for MFA WebAuthn login completion.
type MFAWebAuthnFinishRequest struct {
	MFAToken string          `json:"mfa_token"`
	Response json.RawMessage `json:"response"`
}

// PasskeyLoginFinishRequest is the wrapper for passkey login completion.
type PasskeyLoginFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Response    json.RawMessage `json:"response"`
}

// --- Response DTOs ---

// MessageResponse is a generic response with a message.
type MessageResponse struct {
	Message string `json:"message"`
}

// CreatePeerResponse wraps domain.Peer to include the preshared key (one-time disclosure).
type CreatePeerResponse struct {
	*domain.Peer
	PresharedKey string `json:"preshared_key,omitempty"`
}

// ServerConfigResponse wraps domain.ServerConfig with additional metadata.
type ServerConfigResponse struct {
	*domain.ServerConfig
	CustomScriptsAllowed bool `json:"custom_scripts_allowed"`
}

// CreateTunnelResponse wraps domain.Tunnel to include the preshared key (one-time disclosure).
type CreateTunnelResponse struct {
	*domain.Tunnel
	PresharedKey string `json:"preshared_key,omitempty"`
}

// TunnelWithStatus wraps a tunnel with its runtime status.
type TunnelWithStatus struct {
	domain.Tunnel
	Status *domain.TunnelStatus `json:"status"`
}

// AuthInfoResponse describes available authentication methods.
type AuthInfoResponse struct {
	OIDCEnabled    bool `json:"oidc_enabled"`
	LocalEnabled   bool `json:"local_enabled"`
	WebAuthnEnabled bool `json:"webauthn_enabled"`
}

// LoginUserInfo is user info returned on successful login.
type LoginUserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

// LoginResponse is returned on successful login.
type LoginResponse struct {
	User *LoginUserInfo `json:"user"`
}

// MFARequiredResponse is returned when MFA is required during login.
type MFARequiredResponse struct {
	MFARequired bool     `json:"mfa_required"`
	MFAToken    string   `json:"mfa_token"`
	MFAMethods  []string `json:"mfa_methods"`
}

// UserInfoResponse is returned by /auth/me and /auth/refresh.
type UserInfoResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// CreateTokenResponse is returned when creating an API token (one-time disclosure).
type CreateTokenResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Token       string     `json:"token"`
	TokenPrefix string     `json:"token_prefix"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// TokenWithStatus annotates an API token with its expiration status.
type TokenWithStatus struct {
	domain.APIToken
	Status string `json:"status"`
}

// MFAStatusResponse describes the user's MFA enrollment status.
type MFAStatusResponse struct {
	MFAEnabled          bool               `json:"mfa_enabled"`
	WebAuthnCredentials []MFACredentialInfo `json:"webauthn_credentials"`
	TOTPEnrolled        bool               `json:"totp_enrolled"`
}

// MFACredentialInfo describes a WebAuthn credential.
type MFACredentialInfo struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// TOTPEnrollResponse is returned when enrolling TOTP.
type TOTPEnrollResponse struct {
	Secret string `json:"secret"`
	QRURI  string `json:"qr_uri"`
}

// WebAuthnRegisterBeginResponse wraps WebAuthn registration options.
type WebAuthnRegisterBeginResponse struct {
	ChallengeID string      `json:"challenge_id"`
	Options     interface{} `json:"options"`
}

// WebAuthnCreatedResponse is returned after registering a credential.
type WebAuthnCreatedResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PasskeyLoginBeginResponse wraps passkey login options.
type PasskeyLoginBeginResponse struct {
	ChallengeID string      `json:"challenge_id"`
	Options     interface{} `json:"options"`
}

// WebAuthnOptionsResponse wraps WebAuthn assertion options.
type WebAuthnOptionsResponse struct {
	Options interface{} `json:"options"`
}

// HealthResponse is the health check response.
type HealthResponse struct {
	Status string `json:"status"`
}
