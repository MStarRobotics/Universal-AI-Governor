package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/logging"
	"golang.org/x/time/rate"
)

// Logger middleware for request logging
func Logger(logger logging.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log request details
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		bodySize := c.Writer.Size()

		if raw != "" {
			path = path + "?" + raw
		}

		logger.Info("HTTP Request",
			"method", method,
			"path", path,
			"status", statusCode,
			"latency", latency,
			"client_ip", clientIP,
			"body_size", bodySize,
		)
	}
}

// Recovery middleware for panic recovery
func Recovery(logger logging.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("Panic recovered",
					"error", err,
					"path", c.Request.URL.Path,
					"method", c.Request.Method,
					"client_ip", c.ClientIP(),
				)

				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Internal server error",
				})
				c.Abort()
			}
		}()
		c.Next()
	}
}

// CORS middleware for cross-origin requests
func CORS(config config.CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.Enabled {
			c.Next()
			return
		}

		origin := c.Request.Header.Get("Origin")
		
		// Set CORS headers
		if len(config.AllowedOrigins) > 0 && config.AllowedOrigins[0] != "*" {
			for _, allowedOrigin := range config.AllowedOrigins {
				if origin == allowedOrigin {
					c.Header("Access-Control-Allow-Origin", origin)
					break
				}
			}
		} else {
			c.Header("Access-Control-Allow-Origin", "*")
		}

		if len(config.AllowedMethods) > 0 {
			c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
		}

		if len(config.AllowedHeaders) > 0 {
			c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
		}

		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// Rate limiter storage
type rateLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	rateLimiters = make(map[string]*rateLimiter)
	rateLimiterMu sync.RWMutex
)

// RateLimit middleware for request rate limiting
func RateLimit(config config.RateLimitConfig) gin.HandlerFunc {
	if !config.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Cleanup routine
	go func() {
		ticker := time.NewTicker(config.CleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			rateLimiterMu.Lock()
			for ip, limiter := range rateLimiters {
				if time.Since(limiter.lastSeen) > config.CleanupInterval {
					delete(rateLimiters, ip)
				}
			}
			rateLimiterMu.Unlock()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()

		rateLimiterMu.Lock()
		limiter, exists := rateLimiters[ip]
		if !exists {
			limiter = &rateLimiter{
				limiter: rate.NewLimiter(
					rate.Limit(config.RequestsPerMinute)/60, // Convert to per-second
					config.BurstSize,
				),
				lastSeen: time.Now(),
			}
			rateLimiters[ip] = limiter
		}
		limiter.lastSeen = time.Now()
		rateLimiterMu.Unlock()

		if !limiter.limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// TLS middleware for HTTPS enforcement
func TLS(config config.TLSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.Enabled {
			c.Next()
			return
		}

		// Redirect HTTP to HTTPS
		if c.Request.Header.Get("X-Forwarded-Proto") == "http" {
			httpsURL := "https://" + c.Request.Host + c.Request.RequestURI
			c.Redirect(http.StatusMovedPermanently, httpsURL)
			c.Abort()
			return
		}

		// Set security headers
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")

		c.Next()
	}
}

// Auth middleware for JWT authentication
func Auth(config config.AuthConfig) gin.HandlerFunc {
	if !config.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>" format
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		// Parse and validate JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			
			secret, ok := config.Config["secret"].(string)
			if !ok {
				return nil, fmt.Errorf("JWT secret not configured")
			}
			
			return []byte(secret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		// Extract claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("user_id", claims["sub"])
			c.Set("user_roles", claims["roles"])
			c.Set("user_permissions", claims["permissions"])
		}

		c.Next()
	}
}

// RequestID middleware for request tracing
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("req_%d", time.Now().UnixNano())
		}
		
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// Security middleware for additional security headers
func Security() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")
		
		c.Next()
	}
}

// Timeout middleware for request timeout
func Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
