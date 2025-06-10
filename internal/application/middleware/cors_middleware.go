package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type CorsMiddleware struct {
	allowedOrigins []string
	allowedMethods []string
	allowedHeaders []string
}

func NewCorsMiddleware() *CorsMiddleware {
	return &CorsMiddleware{
		allowedOrigins: []string{"*"}, // In production, specify exact origins
		allowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		allowedHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			"Authorization",
			"X-Requested-With",
			"X-Request-ID",
			"X-Forwarded-For",
			"X-Real-IP",
		},
	}
}

func (m *CorsMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Set CORS headers
		if m.isOriginAllowed(origin) {
			c.Header("Access-Control-Allow-Origin", origin)
		} else if len(m.allowedOrigins) == 1 && m.allowedOrigins[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		}

		c.Header("Access-Control-Allow-Methods", m.joinStrings(m.allowedMethods))
		c.Header("Access-Control-Allow-Headers", m.joinStrings(m.allowedHeaders))
		c.Header("Access-Control-Expose-Headers", "Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func (m *CorsMiddleware) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

		// Remove server information
		c.Header("Server", "")

		c.Next()
	}
}

func (m *CorsMiddleware) isOriginAllowed(origin string) bool {
	for _, allowedOrigin := range m.allowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			return true
		}
	}
	return false
}

func (m *CorsMiddleware) joinStrings(slice []string) string {
	if len(slice) == 0 {
		return ""
	}

	result := slice[0]
	for i := 1; i < len(slice); i++ {
		result += ", " + slice[i]
	}
	return result
}
