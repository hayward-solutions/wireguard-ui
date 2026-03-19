package auth

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/database"
)

// APIKeyMiddleware validates requests with an X-API-Key header or Bearer tokens
// that start with "wgui_". It checks the static admin API key first, then
// looks up per-user API tokens in the database.
// The hmacKey is used for keyed HMAC-SHA256 hashing of API tokens.
func APIKeyMiddleware(apiKey string, store database.Store, hmacKey []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try X-API-Key header
			key := r.Header.Get("X-API-Key")
			if key != "" {
				if tryAPIToken(r, next, w, key, apiKey, store, hmacKey) {
					return
				}
			}

			// Try Authorization: Bearer with wgui_ prefix
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {
				if strings.HasPrefix(authHeader, "Bearer wgui_") {
					bearer := strings.TrimPrefix(authHeader, "Bearer ")
					if tryAPIToken(r, next, w, bearer, apiKey, store, hmacKey) {
						return
					}
				}
			}

			// No API key or invalid — pass through to normal JWT auth
			next.ServeHTTP(w, r)
		})
	}
}

// tryAPIToken attempts to authenticate with the given token.
// Returns true if authentication was handled (request served), false to continue.
func tryAPIToken(r *http.Request, next http.Handler, w http.ResponseWriter, token, staticKey string, store database.Store, hmacKey []byte) bool {
	// Check static admin API key (deprecated — prefer per-user tokens)
	if staticKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(staticKey)) == 1 {
		slog.Warn("static ADMIN_API_KEY used for authentication; this is deprecated — create per-user API tokens instead",
			"remote_addr", r.RemoteAddr,
			"path", r.URL.Path)
		claims := &Claims{
			Email: "api@local",
			Name:  "API",
			Role:  "admin",
		}
		claims.Subject = "api-key"
		ctx := SetClaims(r.Context(), claims)
		w.Header().Set("Deprecation", "true")
		w.Header().Set("Sunset", "2026-09-01")
		next.ServeHTTP(w, r.WithContext(ctx))
		return true
	}

	// Check per-user API tokens
	if store != nil && strings.HasPrefix(token, "wgui_") {
		tokenHash := HashAPIToken(hmacKey, token)

		apiToken, err := store.GetAPITokenByHash(r.Context(), tokenHash)
		if err != nil {
			slog.Error("failed to look up API token", "error", err)
			return false
		}
		if apiToken == nil {
			return false
		}

		// Check expiry
		if apiToken.ExpiresAt != nil && apiToken.ExpiresAt.Before(time.Now()) {
			return false
		}

		// Load the user to get their role and info
		user, err := store.GetUser(r.Context(), apiToken.UserID)
		if err != nil || user == nil {
			slog.Error("failed to load user for API token", "error", err, "user_id", apiToken.UserID)
			return false
		}

		claims := &Claims{
			Email: user.Username,
			Name:  user.Name,
			Role:  user.Role,
		}
		claims.Subject = user.ID

		slog.Warn("audit", "action", "api_token_used",
			"actor", user.ID, "target_id", apiToken.ID,
			"token_name", apiToken.Name,
			"remote_addr", r.RemoteAddr, "path", r.URL.Path)

		// Update last_used in background
		go func() {
			if err := store.UpdateAPITokenLastUsed(context.Background(), apiToken.ID); err != nil {
				slog.Error("failed to update API token last used", "error", err)
			}
		}()

		ctx := SetClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
		return true
	}

	return false
}
