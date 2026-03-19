package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

type TokenHandler struct {
	store       database.Store
	maxLifetime time.Duration
}

func NewTokenHandler(store database.Store, maxLifetime time.Duration) *TokenHandler {
	return &TokenHandler{store: store, maxLifetime: maxLifetime}
}

// HandleList godoc
// @Summary List API tokens
// @Description Returns all API tokens for the authenticated user with expiration status.
// @Tags self-service
// @Security BearerAuth
// @Produce json
// @Success 200 {array} TokenWithStatus
// @Failure 401 {object} Response
// @Router /api/v1/me/tokens [get]
func (h *TokenHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	tokens, err := h.store.ListAPITokensByUser(r.Context(), claims.Subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list tokens")
		return
	}

	if tokens == nil {
		tokens = []domain.APIToken{}
	}

	// Annotate tokens with rotation status
	now := time.Now()
	resp := make([]TokenWithStatus, len(tokens))
	for i, t := range tokens {
		resp[i] = TokenWithStatus{APIToken: t, Status: "active"}
		if t.ExpiresAt != nil {
			remaining := t.ExpiresAt.Sub(now)
			switch {
			case remaining <= 0:
				resp[i].Status = "expired"
			case remaining <= 7*24*time.Hour:
				resp[i].Status = "expiring_soon"
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// HandleCreate godoc
// @Summary Create API token
// @Description Creates a new API token for the authenticated user. The raw token is returned only once.
// @Tags self-service
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body CreateTokenRequest true "Token details"
// @Success 201 {object} CreateTokenResponse
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /api/v1/me/tokens [post]
func (h *TokenHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	var req CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
		return
	}

	// Determine token lifetime
	lifetime := h.maxLifetime
	if req.ExpiresIn != "" {
		requested, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid expires_in duration (e.g. \"720h\")")
			return
		}
		if requested <= 0 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "expires_in must be positive")
			return
		}
		if requested > h.maxLifetime {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST",
				"expires_in exceeds maximum token lifetime of "+h.maxLifetime.String())
			return
		}
		lifetime = requested
	}

	// Generate random token
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate token")
		return
	}
	rawToken := "wgui_" + hex.EncodeToString(rawBytes)

	// Hash for storage
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	// Prefix for display (first 8 hex chars after wgui_)
	tokenPrefix := rawToken[:13] // "wgui_" + 8 hex chars

	expiresAt := time.Now().Add(lifetime)
	token := &domain.APIToken{
		ID:          uuid.New().String(),
		UserID:      claims.Subject,
		Name:        req.Name,
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
		ExpiresAt:   &expiresAt,
	}

	if err := h.store.CreateAPIToken(r.Context(), token); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to create token")
		return
	}

	// Return the raw token once
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":           token.ID,
		"name":         token.Name,
		"token":        rawToken,
		"token_prefix": token.TokenPrefix,
		"expires_at":   token.ExpiresAt,
		"created_at":   token.CreatedAt,
	})
}

// HandleDelete godoc
// @Summary Delete API token
// @Description Deletes an API token by ID.
// @Tags self-service
// @Security BearerAuth
// @Produce json
// @Param id path string true "Token ID"
// @Success 200 {object} Response{data=MessageResponse}
// @Failure 401 {object} Response
// @Failure 404 {object} Response
// @Router /api/v1/me/tokens/{id} [delete]
func (h *TokenHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	id := chi.URLParam(r, "id")

	// Verify ownership: list user's tokens and check if this token belongs to them
	tokens, err := h.store.ListAPITokensByUser(r.Context(), claims.Subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to verify token ownership")
		return
	}

	found := false
	for _, t := range tokens {
		if t.ID == id {
			found = true
			break
		}
	}

	if !found && claims.Role != domain.RoleAdmin {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "token not found")
		return
	}

	if err := h.store.DeleteAPIToken(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "token deleted"})
}
