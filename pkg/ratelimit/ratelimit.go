package ratelimit

import (
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// entry tracks request count per window
type entry struct {
	count    int
	resetAt  time.Time
}

// Limiter is an in-memory per-IP rate limiter
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	window  time.Duration
}

// New creates a rate limiter with the specified window duration
func New(window time.Duration) *Limiter {
	l := &Limiter{
		entries: make(map[string]*entry),
		window:  window,
	}
	// Cleanup goroutine — evict expired entries every minute
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			l.mu.Lock()
			now := time.Now()
			for k, e := range l.entries {
				if now.After(e.resetAt) {
					delete(l.entries, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

// allow checks if a key is within its rate limit
func (l *Limiter) allow(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	e, exists := l.entries[key]
	if !exists || now.After(e.resetAt) {
		l.entries[key] = &entry{count: 1, resetAt: now.Add(l.window)}
		return true
	}
	e.count++
	return e.count <= limit
}

// getEnvInt reads an int from env with a default
func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}

// Middleware returns a Gin middleware that enforces per-IP rate limits.
// Limits are configurable via environment variables.
func Middleware(limiter *Limiter) gin.HandlerFunc {
	loginLimit := getEnvInt("RATE_LIMIT_LOGIN", 5)
	tokenLimit := getEnvInt("RATE_LIMIT_TOKEN", 10)
	dcrLimit := getEnvInt("RATE_LIMIT_DCR", 5)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		path := c.Request.URL.Path

		var limit int
		var key string

		switch {
		case path == "/.auth/login" || path == "/.auth/password":
			limit = loginLimit
			key = "login:" + ip
		case path == "/.idp/token":
			limit = tokenLimit
			key = "token:" + ip
		case path == "/.idp/register" && c.Request.Method == "POST":
			limit = dcrLimit
			key = "dcr:" + ip
		default:
			// No rate limit on other paths (MCP calls are rate-limited by token, not IP)
			c.Next()
			return
		}

		if !limiter.allow(key, limit) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests. Please try again later.",
			})
			return
		}

		c.Next()
	}
}
