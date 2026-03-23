package api

import "net/http"

// maxRequestBodySize is the maximum allowed request body size (1 MiB).
const maxRequestBodySize = 1 << 20

// BodyLimitMiddleware rejects request bodies larger than maxRequestBodySize.
// This prevents denial-of-service attacks via unbounded memory allocation
// when decoding JSON request bodies.
func BodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		next.ServeHTTP(w, r)
	})
}
