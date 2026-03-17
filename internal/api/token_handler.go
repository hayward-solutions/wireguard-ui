package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

type TokenHandler struct {
	store database.Store
}

func NewTokenHandler(store database.Store) *TokenHandler {
	return &TokenHandler{store: store}
}

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

	writeJSON(w, http.StatusOK, tokens)
}

func (h *TokenHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
		return
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

	token := &domain.APIToken{
		ID:          uuid.New().String(),
		UserID:      claims.Subject,
		Name:        req.Name,
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
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
		"created_at":   token.CreatedAt,
	})
}

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
