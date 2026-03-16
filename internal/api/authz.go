package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// requirePeerAccess fetches the peer by URL param {id} and verifies the caller
// owns the peer or is an admin. Returns the peer and claims on success.
// On failure, writes an error response and returns nil.
func requirePeerAccess(store database.Store, w http.ResponseWriter, r *http.Request) (*domain.Peer, *auth.Claims) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing credentials")
		return nil, nil
	}

	id := chi.URLParam(r, "id")
	peer, err := store.GetPeer(r.Context(), id)
	if err != nil {
		slog.Error("get peer", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get peer")
		return nil, nil
	}
	if peer == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "peer not found")
		return nil, nil
	}

	// Non-admins can only access their own peers (404 to avoid leaking existence)
	if claims.Role != domain.RoleAdmin && peer.CreatedBy != claims.Subject {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "peer not found")
		return nil, nil
	}

	return peer, claims
}

// RequireAdmin is chi middleware that restricts access to admin users only.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := auth.ClaimsFromContext(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing credentials")
			return
		}
		if claims.Role != domain.RoleAdmin {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
