package api

import (
	"net/http"
	"strings"
)

// HTTPSRedirectMiddleware returns a chi middleware that enforces HTTPS.
// It checks X-Forwarded-Proto (for requests behind a reverse proxy / load
// balancer) and falls back to r.TLS for direct TLS connections.
// The health-check endpoint is exempt so load-balancer probes still work
// over plain HTTP.
func HTTPSRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow health checks over HTTP so LB probes succeed.
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		proto := strings.ToLower(r.Header.Get("X-Forwarded-Proto"))
		isHTTPS := proto == "https" || r.TLS != nil

		if !isHTTPS {
			host := r.Host
			if host == "" {
				host = r.URL.Host
			}
			target := "https://" + host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}

		// HSTS: tell browsers to always use HTTPS (2 years).
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}
