package api

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	ipLimiters   = make(map[string]*rate.Limiter)
	ipLimitersMu sync.RWMutex
)

// GetLimiterForIP returns a rate limiter for the given IP address.
// The limiter is configured with a burst capacity of 100 and an average rate of 100 requests per second.
// Note: When deploying behind a reverse proxy, ensure to use the correct client IP.
func GetLimiterForIP(ip string) *rate.Limiter {
	ipLimitersMu.RLock()
	limiter, exists := ipLimiters[ip]
	ipLimitersMu.RUnlock()
	if exists {
		return limiter
	}
	// Create a new limiter: allow 100 requests per second with a burst of 100.
	limiter = rate.NewLimiter(rate.Every(10*time.Millisecond), 100)
	ipLimitersMu.Lock()
	ipLimiters[ip] = limiter
	ipLimitersMu.Unlock()
	return limiter
}

// IsExcluded checks whether the given IP should bypass rate limiting.
// For example, loopback addresses or trusted networks (e.g., internal Docker networks) can be excluded.
func IsExcluded(ip net.IP) bool {
	// Bypass rate limiting for localhost.
	if ip.IsLoopback() {
		return true
	}
	// Example: Exclude a trusted network (modify as needed).
	_, excludedNet, _ := net.ParseCIDR("172.17.0.0/24")
	return excludedNet.Contains(ip)
}
