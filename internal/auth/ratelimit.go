package auth

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// entry tracks a rate limiter and when it was last used for eviction.
type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter provides per-key rate limiting with automatic eviction of stale entries.
type RateLimiter struct {
	entries sync.Map
	rps     rate.Limit
	burst   int
	stop    chan struct{}
}

// NewRateLimiter creates a rate limiter that allows rps requests per second
// with the given burst size. Stale entries are evicted every cleanupInterval.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		rps:   rate.Limit(rps),
		burst: burst,
		stop:  make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Allow checks whether a request for the given key should be allowed.
func (rl *RateLimiter) Allow(key string) bool {
	v, _ := rl.entries.LoadOrStore(key, &entry{
		limiter:  rate.NewLimiter(rl.rps, rl.burst),
		lastSeen: time.Now(),
	})
	e := v.(*entry)
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

// Stop halts the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stop)
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case <-ticker.C:
			rl.entries.Range(func(key, value any) bool {
				e := value.(*entry)
				if time.Since(e.lastSeen) > 10*time.Minute {
					rl.entries.Delete(key)
				}
				return true
			})
		}
	}
}

// IPRateLimitMiddleware returns chi middleware that rate-limits by client IP.
func IPRateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow(r.RemoteAddr) {
				w.Header().Set("Retry-After", strconv.Itoa(1))
				http.Error(w, `{"error":{"code":"RATE_LIMITED","message":"too many requests"}}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
