package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	oidc            *auth.OIDCProvider
	jwt             *auth.JWTManager
	store           database.Store
	loginLimiter    *auth.RateLimiter
	oidcAdminGroup  string
	secureCookie    bool
	sessionExpiry   time.Duration
}

type AuthHandlerConfig struct {
	OIDC           *auth.OIDCProvider
	JWT            *auth.JWTManager
	Store          database.Store
	LoginLimiter   *auth.RateLimiter
	OIDCAdminGroup string
	SecureCookie   bool
	SessionExpiry  time.Duration
}

func NewAuthHandler(cfg AuthHandlerConfig) *AuthHandler {
	return &AuthHandler{
		oidc:           cfg.OIDC,
		jwt:            cfg.JWT,
		store:          cfg.Store,
		loginLimiter:   cfg.LoginLimiter,
		oidcAdminGroup: cfg.OIDCAdminGroup,
		secureCookie:   cfg.SecureCookie,
		sessionExpiry:  cfg.SessionExpiry,
	}
}

// HandleLoginPage redirects to OIDC or returns auth method info for the UI.
func (h *AuthHandler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	if h.oidc != nil {
		// OIDC redirect flow
		state, err := generateState()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate state")
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

		http.Redirect(w, r, h.oidc.AuthCodeURL(state), http.StatusFound)
		return
	}

	// No OIDC — let the frontend show local login form
	writeError(w, http.StatusBadRequest, "NO_OIDC", "use POST /auth/login with username and password")
}

// HandleLocalLogin handles username/password authentication against DB users.
func (h *AuthHandler) HandleLocalLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
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
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
		return
	}

	// Check account lockout
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
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

	h.issueSessionAndToken(w, r, user)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user": map[string]string{
			"id":       user.ID,
			"username": user.Username,
			"name":     user.Name,
			"role":     user.Role,
		},
	})
}

// HandleAuthInfo returns what auth methods are available.
func (h *AuthHandler) HandleAuthInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"oidc_enabled":  h.oidc != nil,
		"local_enabled": true,
	})
}

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

	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing code parameter")
		return
	}

	oidcUser, err := h.oidc.Exchange(r.Context(), code)
	if err != nil {
		slog.Error("oidc exchange failed", "error", err)
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
			user.Role = role
			if err := h.store.UpdateUser(r.Context(), user); err != nil {
				slog.Error("update oidc user role failed", "error", err)
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

	if err := h.store.UpdateLastLogin(r.Context(), user.ID); err != nil {
		slog.Error("failed to update last login", "error", err)
	}

	h.issueSessionAndToken(w, r, user)

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (h *AuthHandler) HandleMe(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":    claims.Subject,
		"email": claims.Email,
		"name":  claims.Name,
		"role":  claims.Role,
	})
}

// HandleRefresh issues a new short-lived JWT from a valid session cookie.
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":    user.ID,
		"email": user.Username,
		"name":  user.Name,
		"role":  user.Role,
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
