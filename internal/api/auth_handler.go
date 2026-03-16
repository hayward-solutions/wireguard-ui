package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

type AuthHandler struct {
	oidc          *auth.OIDCProvider
	jwt           *auth.JWTManager
	store         database.Store
	adminUsername string
	adminPassword string
}

type AuthHandlerConfig struct {
	OIDC          *auth.OIDCProvider
	JWT           *auth.JWTManager
	Store         database.Store
	AdminUsername string
	AdminPassword string
}

func NewAuthHandler(cfg AuthHandlerConfig) *AuthHandler {
	return &AuthHandler{
		oidc:          cfg.OIDC,
		jwt:           cfg.JWT,
		store:         cfg.Store,
		adminUsername: cfg.AdminUsername,
		adminPassword: cfg.AdminPassword,
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
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, h.oidc.AuthCodeURL(state), http.StatusFound)
		return
	}

	// No OIDC — let the frontend show local login form
	writeError(w, http.StatusBadRequest, "NO_OIDC", "use POST /auth/login with username and password")
}

// HandleLocalLogin handles username/password authentication.
func (h *AuthHandler) HandleLocalLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if h.adminPassword == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "local auth not configured")
		return
	}

	usernameMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(h.adminUsername)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(req.Password), []byte(h.adminPassword)) == 1
	if !usernameMatch || !passwordMatch {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
		return
	}

	// Upsert admin user
	now := time.Now()
	user := &domain.User{
		ID:        "local:" + req.Username,
		Email:     req.Username + "@local",
		Name:      req.Username,
		Role:      domain.RoleAdmin,
		LastLogin: now,
		CreatedAt: now,
	}

	existing, _ := h.store.GetUser(r.Context(), user.ID)
	if existing != nil {
		user.CreatedAt = existing.CreatedAt
	}

	if err := h.store.UpsertUser(r.Context(), user); err != nil {
		slog.Error("upsert user failed", "error", err)
	}

	token, err := h.jwt.Issue(user.ID, user.Email, user.Name, user.Role)
	if err != nil {
		slog.Error("jwt issue failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to issue token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user": map[string]string{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

// HandleAuthInfo returns what auth methods are available.
func (h *AuthHandler) HandleAuthInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"oidc_enabled": h.oidc != nil,
		"local_enabled": h.adminPassword != "",
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

	now := time.Now()
	user := &domain.User{
		ID:        oidcUser.Subject,
		Email:     oidcUser.Email,
		Name:      oidcUser.Name,
		Role:      domain.RoleAdmin,
		LastLogin: now,
		CreatedAt: now,
	}

	existing, _ := h.store.GetUser(r.Context(), oidcUser.Subject)
	if existing != nil {
		user.Role = existing.Role
		user.CreatedAt = existing.CreatedAt
	}

	if err := h.store.UpsertUser(r.Context(), user); err != nil {
		slog.Error("upsert user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to save user")
		return
	}

	token, err := h.jwt.Issue(user.ID, user.Email, user.Name, user.Role)
	if err != nil {
		slog.Error("jwt issue failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to issue token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
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

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
