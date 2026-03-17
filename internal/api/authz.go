package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// roleRank returns a numeric rank for role comparison.
// Higher rank = more privileges: admin(3) > editor(2) > viewer(1).
func roleRank(role string) int {
	switch role {
	case domain.RoleAdmin:
		return 3
	case domain.RoleEditor:
		return 2
	case domain.RoleViewer:
		return 1
	default:
		return 0
	}
}

// RequireRole returns middleware that requires the caller to have at least
// the specified minimum role (viewer < editor < admin).
func RequireRole(minRole string) func(http.Handler) http.Handler {
	minRank := roleRank(minRole)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.ClaimsFromContext(r.Context())
			if claims == nil {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing credentials")
				return
			}
			if roleRank(claims.Role) < minRank {
				writeError(w, http.StatusForbidden, "FORBIDDEN",
					fmt.Sprintf("%s access required", minRole))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin is chi middleware that restricts access to admin users only.
var RequireAdmin = RequireRole(domain.RoleAdmin)

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

// actorFromRequest extracts the authenticated user's ID from the request context.
func actorFromRequest(r *http.Request) string {
	if c := auth.ClaimsFromContext(r.Context()); c != nil {
		return c.Subject
	}
	return "unknown"
}
