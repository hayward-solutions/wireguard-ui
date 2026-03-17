package api

import (
	"net"
	"net/http"
	"strings"
)

// TrustedProxyMiddleware returns middleware that extracts the real client IP
// from X-Forwarded-For or X-Real-IP headers, but only when the direct peer
// is a trusted proxy. When no trusted proxies are configured, forwarded
// headers are ignored entirely.
func TrustedProxyMiddleware(trustedProxies []string) func(http.Handler) http.Handler {
	nets := parseCIDRs(trustedProxies)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(nets) > 0 {
				peerIP, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					peerIP = r.RemoteAddr
				}
				if isTrusted(net.ParseIP(peerIP), nets) {
					if ip := extractClientIP(r, nets); ip != "" {
						r.RemoteAddr = ip + ":0"
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// extractClientIP returns the rightmost non-trusted IP from X-Forwarded-For,
// or falls back to X-Real-IP. This prevents spoofing by untrusted clients
// that prepend fake IPs to the header.
func extractClientIP(r *http.Request, trusted []*net.IPNet) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		// Walk right-to-left, skip trusted proxies, return first untrusted IP.
		for i := len(ips) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(ips[i])
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if !isTrusted(parsed, trusted) {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if parsed := net.ParseIP(strings.TrimSpace(xri)); parsed != nil {
			return strings.TrimSpace(xri)
		}
	}
	return ""
}

// parseCIDRs parses a slice of CIDR strings or bare IPs into []*net.IPNet.
func parseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// If it's a bare IP (no /), treat as /32 or /128.
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func isTrusted(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
