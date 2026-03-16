package auth

import (
	"crypto/subtle"
	"net/http"
)

// APIKeyMiddleware validates requests with an X-API-Key header.
// If the API key is empty (not configured), this middleware is a no-op pass-through.
func APIKeyMiddleware(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-API-Key")
			if key != "" && apiKey != "" {
				if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) == 1 {
					// API key valid — inject admin claims into context
					claims := &Claims{
						Email: "api@local",
						Name:  "API",
						Role:  "admin",
					}
					claims.Subject = "api-key"
					ctx := SetClaims(r.Context(), claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
			// No API key or invalid — pass through to normal JWT auth
			next.ServeHTTP(w, r)
		})
	}
}
