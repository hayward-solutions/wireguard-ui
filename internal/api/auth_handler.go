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
	oidc           *auth.OIDCProvider
	jwt            *auth.JWTManager
	store          database.Store
	oidcAdminGroup string
	secureCookie   bool
	policyEngine   *acl.PolicyEngine
}

type AuthHandlerConfig struct {
	OIDC           *auth.OIDCProvider
	JWT            *auth.JWTManager
	Store          database.Store
	OIDCAdminGroup string
	SecureCookie   bool
	PolicyEngine   *acl.PolicyEngine
}

func NewAuthHandler(cfg AuthHandlerConfig) *AuthHandler {
	return &AuthHandler{
		oidc:           cfg.OIDC,
		jwt:            cfg.JWT,
		store:          cfg.Store,
		oidcAdminGroup: cfg.OIDCAdminGroup,
		secureCookie:   cfg.SecureCookie,
		policyEngine:   cfg.PolicyEngine,
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

	user, err := h.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
		return
	}

	token, err := h.jwt.Issue(user.ID, user.Username, user.Name, user.Role)
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
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
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

	// Sync OIDC groups
	if len(oidcUser.Groups) > 0 {
		h.syncOIDCGroups(r.Context(), user.ID, oidcUser.Groups)
	}

	token, err := h.jwt.Issue(user.ID, user.Username, user.Name, user.Role)
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
		Secure:   h.secureCookie,
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

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
