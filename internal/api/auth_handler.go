package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/acl"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	oidc                   *auth.OIDCProvider
	jwt                    *auth.JWTManager
	store                  database.Store
	loginLimiter           *auth.RateLimiter
	oidcAdminGroup         string
	secureCookie           bool
	sessionExpiry          time.Duration
	policyEngine           *acl.PolicyEngine
	webauthnEnabled        bool
	allowPasswordlessLogin bool
	mfaRequired            bool
}

type AuthHandlerConfig struct {
	OIDC                   *auth.OIDCProvider
	JWT                    *auth.JWTManager
	Store                  database.Store
	LoginLimiter           *auth.RateLimiter
	OIDCAdminGroup         string
	SecureCookie           bool
	SessionExpiry          time.Duration
	PolicyEngine           *acl.PolicyEngine
	WebAuthnEnabled        bool
	AllowPasswordlessLogin bool
	MFARequired            bool
}

func NewAuthHandler(cfg AuthHandlerConfig) *AuthHandler {
	return &AuthHandler{
		oidc:                   cfg.OIDC,
		jwt:                    cfg.JWT,
		store:                  cfg.Store,
		loginLimiter:           cfg.LoginLimiter,
		oidcAdminGroup:         cfg.OIDCAdminGroup,
		secureCookie:           cfg.SecureCookie,
		sessionExpiry:          cfg.SessionExpiry,
		policyEngine:           cfg.PolicyEngine,
		webauthnEnabled:        cfg.WebAuthnEnabled,
		allowPasswordlessLogin: cfg.AllowPasswordlessLogin,
		mfaRequired:            cfg.MFARequired,
	}
}

// HandleLoginPage godoc
// @Summary Login page / OIDC redirect
// @Description Redirects to OIDC provider if configured, otherwise returns an error indicating local login should be used.
// @Tags auth
// @Produce json
// @Success 302 {string} string "Redirect to OIDC provider"
// @Failure 400 {object} Response
// @Router /auth/login [get]
func (h *AuthHandler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	if h.oidc != nil {
		// OIDC redirect flow
		state, err := generateState()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate state")
			return
		}

		nonce, err := generateState() // same random generation as state
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate nonce")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			Secure:   h.secureCookie,
			SameSite: http.SameSiteLaxMode,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_nonce",
			Value:    nonce,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			Secure:   h.secureCookie,
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, h.oidc.AuthCodeURL(state, nonce), http.StatusFound)
		return
	}

	// No OIDC — let the frontend show local login form
	writeError(w, http.StatusBadRequest, "NO_OIDC", "use POST /auth/login with username and password")
}

// HandleLocalLogin godoc
// @Summary Local login
// @Description Authenticates a user with username and password. Returns user info or an MFA challenge if MFA is enabled.
// @Tags auth
// @Accept json
// @Produce json
// @Param body body LoginRequest true "Login credentials"
// @Success 200 {object} Response{data=LoginResponse} "Successful login"
// @Success 200 {object} Response{data=MFARequiredResponse} "MFA required"
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 429 {object} Response
// @Router /auth/login [post]
func (h *AuthHandler) HandleLocalLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	// Per-username rate limiting
	if h.loginLimiter != nil && !h.loginLimiter.Allow(req.Username) {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, try again later")
		return
	}

	user, err := h.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user == nil {
		slog.Warn("audit", "action", "login_failure", "target_name", req.Username, "method", "local", "reason", "unknown_user")
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
		return
	}

	// Check account lockout
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		slog.Warn("audit", "action", "login_failure", "target_name", user.Username, "method", "local", "reason", "account_locked")
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many failed attempts, try again later")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		// Record failed login and potentially lock the account
		attempts, lockErr := h.store.RecordFailedLogin(r.Context(), user.ID)
		if lockErr != nil {
			slog.Error("failed to record failed login", "error", lockErr)
		} else if lockDuration := lockoutDuration(attempts); lockDuration > 0 {
			if lockErr := h.store.LockUser(r.Context(), user.ID, time.Now().Add(lockDuration)); lockErr != nil {
				slog.Error("failed to lock user", "error", lockErr)
			}
			slog.Warn("account locked due to failed login attempts",
				"username", user.Username, "attempts", attempts, "lock_duration", lockDuration)
		}
		slog.Warn("audit", "action", "login_failure", "target_name", user.Username, "method", "local", "reason", "invalid_password")
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
		return
	}

	// Successful login — reset lockout and update last_login
	if err := h.store.ResetFailedLogins(r.Context(), user.ID); err != nil {
		slog.Error("failed to reset failed logins", "error", err)
	}
	if err := h.store.UpdateLastLogin(r.Context(), user.ID); err != nil {
		slog.Error("failed to update last login", "error", err)
	}

	// Check if MFA is required
	if user.MFAEnabled {
		challenge := &domain.MFAChallenge{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		if err := h.store.CreateMFAChallenge(r.Context(), challenge); err != nil {
			slog.Error("failed to create MFA challenge", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to create MFA challenge")
			return
		}

		slog.Warn("audit", "action", "login_mfa_required", "actor", user.ID, "target_name", user.Username, "method", "local")

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mfa_required": true,
			"mfa_token":    challenge.ID,
			"mfa_methods":  getMFAMethods(r, h.store, user.ID),
		})
		return
	}

	// If MFA is globally required but user hasn't enrolled yet, let them in
	// but signal the frontend to force MFA setup.
	mfaSetupRequired := false
	if h.mfaRequired && !user.MFAEnabled {
		methods := getMFAMethods(r, h.store, user.ID)
		if len(methods) == 0 {
			mfaSetupRequired = true
		}
	}

	h.issueSessionAndToken(w, r, user)

	slog.Warn("audit", "action", "login_success", "actor", user.ID, "target_name", user.Username, "method", "local")

	resp := map[string]interface{}{
		"user": map[string]string{
			"id":       user.ID,
			"username": user.Username,
			"name":     user.Name,
			"role":     user.Role,
		},
	}
	if mfaSetupRequired {
		resp["mfa_setup_required"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// HandleAuthInfo godoc
// @Summary Get auth info
// @Description Returns available authentication methods.
// @Tags auth
// @Produce json
// @Success 200 {object} Response{data=AuthInfoResponse}
// @Router /auth/info [get]
func (h *AuthHandler) HandleAuthInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"oidc_enabled":              h.oidc != nil,
		"local_enabled":             true,
		"webauthn_enabled":          h.webauthnEnabled,
		"passwordless_login_enabled": h.webauthnEnabled && h.allowPasswordlessLogin,
	})
}

// HandleCallback godoc
// @Summary OIDC callback
// @Description Handles the OIDC provider callback after authentication.
// @Tags auth
// @Param state query string true "OAuth state parameter"
// @Param code query string true "Authorization code"
// @Success 302 {string} string "Redirect to home"
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /auth/callback [get]
func (h *AuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "OIDC not configured")
		return
	}

	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid state parameter")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookie,
	})

	// Read and clear nonce cookie
	nonceCookie, err := r.Cookie("oauth_nonce")
	if err != nil || nonceCookie.Value == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing nonce cookie")
		return
	}
	nonce := nonceCookie.Value
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_nonce",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookie,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing code parameter")
		return
	}

	oidcUser, err := h.oidc.Exchange(r.Context(), code, nonce)
	if err != nil {
		slog.Error("oidc exchange failed", "error", err)
		slog.Warn("audit", "action", "login_failure", "method", "oidc", "reason", "exchange_failed")
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication failed")
		return
	}

	// Determine role based on OIDC group membership
	role := domain.RoleViewer
	if h.oidcAdminGroup != "" {
		for _, g := range oidcUser.Groups {
			if g == h.oidcAdminGroup {
				role = domain.RoleAdmin
				break
			}
		}
	}

	// Look up or create the OIDC user
	existing, _ := h.store.GetUser(r.Context(), oidcUser.Subject)
	var user *domain.User
	if existing != nil {
		user = existing
		// Sync role from IdP group membership on every login
		if user.Role != role {
			oldRole := user.Role
			user.Role = role
			if err := h.store.UpdateUser(r.Context(), user); err != nil {
				slog.Error("update oidc user role failed", "error", err)
			} else {
				slog.Warn("audit", "action", "role_changed", "actor", user.ID, "target_name", user.Username,
					"old_role", oldRole, "new_role", role, "method", "oidc_sync")
			}
		}
	} else {
		now := time.Now()
		user = &domain.User{
			ID:        oidcUser.Subject,
			Username:  oidcUser.Email,
			Name:      oidcUser.Name,
			Role:      role,
			CreatedAt: now,
		}
		if err := h.store.CreateUser(r.Context(), user); err != nil {
			slog.Error("create oidc user failed", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to save user")
			return
		}
	}

	// Sync OIDC groups
	if len(oidcUser.Groups) > 0 {
		h.syncOIDCGroups(r.Context(), user.ID, oidcUser.Groups)
	}

	if err := h.store.UpdateLastLogin(r.Context(), user.ID); err != nil {
		slog.Error("failed to update last login", "error", err)
	}

	h.issueSessionAndToken(w, r, user)

	slog.Warn("audit", "action", "login_success", "actor", user.ID, "target_name", user.Username, "method", "oidc")

	http.Redirect(w, r, "/", http.StatusFound)
}

// HandleLogout godoc
// @Summary Logout
// @Description Revokes the session and clears authentication cookies.
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} Response{data=MessageResponse}
// @Router /auth/logout [post]
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	actor := actorFromRequest(r)
	slog.Warn("audit", "action", "logout", "actor", actor)

	// Revoke server-side session
	if sessionCookie, err := r.Cookie("session"); err == nil && sessionCookie.Value != "" {
		if err := h.store.RevokeSession(r.Context(), sessionCookie.Value); err != nil {
			slog.Error("failed to revoke session", "error", err)
		}
	}

	// Clear both cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookie,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookie,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   h.secureCookie,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// HandleMe godoc
// @Summary Get current user
// @Description Returns information about the currently authenticated user.
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} Response{data=UserInfoResponse}
// @Failure 401 {object} Response
// @Router /auth/me [get]
func (h *AuthHandler) HandleMe(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	resp := map[string]interface{}{
		"id":       claims.Subject,
		"email":    claims.Email,
		"username": claims.Email,
		"name":     claims.Name,
		"role":     claims.Role,
	}
	if h.mfaRequired {
		methods := getMFAMethods(r, h.store, claims.Subject)
		if len(methods) == 0 {
			resp["mfa_setup_required"] = true
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) syncOIDCGroups(ctx context.Context, userID string, oidcGroups []string) {
	var groupIDs []string
	for _, name := range oidcGroups {
		group, err := h.store.GetGroupByName(ctx, name)
		if err != nil {
			slog.Error("lookup oidc group", "name", name, "error", err)
			continue
		}
		if group == nil {
			group = &domain.Group{
				ID:     uuid.New().String(),
				Name:   name,
				Source: domain.GroupSourceOIDC,
			}
			if err := h.store.CreateGroup(ctx, group); err != nil {
				slog.Error("create oidc group", "name", name, "error", err)
				continue
			}
			slog.Info("created OIDC group", "name", name, "id", group.ID)
		}
		groupIDs = append(groupIDs, group.ID)
	}

	if err := h.store.SyncOIDCGroups(ctx, userID, groupIDs); err != nil {
		slog.Error("sync oidc groups", "user_id", userID, "error", err)
	}

	if h.policyEngine != nil {
		if err := h.policyEngine.Reload(ctx, h.store); err != nil {
			slog.Error("acl reload after oidc sync", "error", err)
		}
	}
}

// HandleRefresh godoc
// @Summary Refresh token
// @Description Issues a new short-lived JWT from a valid session cookie.
// @Tags auth
// @Produce json
// @Success 200 {object} Response{data=UserInfoResponse}
// @Failure 401 {object} Response
// @Router /auth/refresh [post]
func (h *AuthHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session")
	if err != nil || sessionCookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "no session")
		return
	}

	sess, err := h.store.GetSession(r.Context(), sessionCookie.Value)
	if err != nil {
		slog.Error("failed to get session", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "session lookup failed")
		return
	}
	if sess == nil || sess.Revoked || sess.ExpiresAt.Before(time.Now()) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "session expired")
		return
	}

	// Load current user data (picks up role changes)
	user, err := h.store.GetUser(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "user not found")
		return
	}

	token, err := h.jwt.Issue(user.ID, user.Username, user.Name, user.Role)
	if err != nil {
		slog.Error("jwt issue failed on refresh", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to issue token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   int(h.jwt.Expiry().Seconds()),
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	// Rotate CSRF token on refresh to stay in sync with the session.
	h.setCSRFCookie(w)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":       user.ID,
		"email":    user.Username,
		"username": user.Username,
		"name":     user.Name,
		"role":     user.Role,
	})
}

// issueSessionAndToken creates a session and sets both session and JWT cookies.
func (h *AuthHandler) issueSessionAndToken(w http.ResponseWriter, r *http.Request, user *domain.User) {
	// Create session
	now := time.Now()
	sess := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(h.sessionExpiry),
	}
	if err := h.store.CreateSession(r.Context(), sess); err != nil {
		slog.Error("failed to create session", "error", err)
	}

	// Set session cookie (long-lived)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sess.ID,
		Path:     "/",
		MaxAge:   int(h.sessionExpiry.Seconds()),
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	// Issue short-lived JWT
	token, err := h.jwt.Issue(user.ID, user.Username, user.Name, user.Role)
	if err != nil {
		slog.Error("jwt issue failed", "error", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   int(h.jwt.Expiry().Seconds()),
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	// Set CSRF token cookie (readable by JS so the frontend can echo it back).
	h.setCSRFCookie(w)
}

// setCSRFCookie generates a fresh CSRF token and sets it as a non-HttpOnly cookie.
func (h *AuthHandler) setCSRFCookie(w http.ResponseWriter) {
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		slog.Error("failed to generate CSRF token", "error", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   int(h.sessionExpiry.Seconds()),
		HttpOnly: false, // must be readable by JavaScript
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// lockoutDuration returns how long to lock the account based on failed attempts.
// Returns 0 if no lockout should be applied.
func lockoutDuration(attempts int) time.Duration {
	switch {
	case attempts >= 20:
		return 1 * time.Hour
	case attempts >= 15:
		return 15 * time.Minute
	case attempts >= 10:
		return 5 * time.Minute
	case attempts >= 5:
		return 1 * time.Minute
	default:
		return 0
	}
}

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
