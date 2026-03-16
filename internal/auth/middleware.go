package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const claimsKey contextKey = "claims"

// Middleware returns an HTTP middleware that validates JWT tokens from
// the Authorization header or the "token" cookie.
// It skips validation if claims are already set (e.g. by APIKeyMiddleware).
func Middleware(jwtMgr *JWTManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If claims already set (e.g. by API key middleware), pass through
			if ClaimsFromContext(r.Context()) != nil {
				next.ServeHTTP(w, r)
				return
			}

			tokenStr := extractToken(r)
			if tokenStr == "" {
				http.Error(w, `{"data":null,"error":{"code":"UNAUTHORIZED","message":"missing token"}}`, http.StatusUnauthorized)
				return
			}

			claims, err := jwtMgr.Validate(tokenStr)
			if err != nil {
				http.Error(w, `{"data":null,"error":{"code":"UNAUTHORIZED","message":"invalid token"}}`, http.StatusUnauthorized)
				return
			}

			ctx := SetClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SetClaims stores claims in the context.
func SetClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ClaimsFromContext retrieves the JWT claims from the request context.
func ClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsKey).(*Claims)
	return claims
}

func extractToken(r *http.Request) string {
	// Check Authorization header first
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}
	// Fall back to cookie
	if cookie, err := r.Cookie("token"); err == nil {
		return cookie.Value
	}
	return ""
}
