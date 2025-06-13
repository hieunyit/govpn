package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type CorsMiddleware struct {
	allowedOrigins []string
	allowedMethods []string
	allowedHeaders []string
}

func NewCorsMiddleware() *CorsMiddleware {
	return &CorsMiddleware{
		// Thêm các origin cần thiết
		allowedOrigins: []string{
			"*", // Cho phép tất cả origins (chỉ dùng trong development)
			"http://localhost:3000",
			"http://localhost:8080",
			"http://127.0.0.1:3000",
			"http://127.0.0.1:8080",
			"https://localhost:3000",
			"https://localhost:8080",
			// Thêm domain của frontend nếu có
		},
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
			"Access-Control-Allow-Origin",
			"Access-Control-Allow-Headers",
			"Access-Control-Allow-Methods",
		},
	}
}

func (m *CorsMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Luôn luôn set CORS headers
		if m.isOriginAllowed(origin) {
			c.Header("Access-Control-Allow-Origin", origin)
		} else {
			// Trong development, cho phép tất cả origins
			c.Header("Access-Control-Allow-Origin", "*")
		}

		c.Header("Access-Control-Allow-Methods", m.joinStrings(m.allowedMethods))
		c.Header("Access-Control-Allow-Headers", m.joinStrings(m.allowedHeaders))
		c.Header("Access-Control-Expose-Headers", "Authorization, Content-Length, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.Header("Content-Type", "text/plain; charset=utf-8")
			c.Header("Content-Length", "0")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func (m *CorsMiddleware) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers - nhưng không quá strict để tránh CORS issues
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "SAMEORIGIN") // Thay đổi từ DENY
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// CSP không quá strict
		c.Header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' *")

		// Chỉ set HSTS nếu đang sử dụng HTTPS
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Remove server information
		c.Header("Server", "")

		c.Next()
	}
}

func (m *CorsMiddleware) isOriginAllowed(origin string) bool {
	if origin == "" {
		return true // Allow requests without origin (e.g., mobile apps)
	}

	for _, allowedOrigin := range m.allowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			return true
		}
		// Check for wildcard subdomains
		if strings.HasPrefix(allowedOrigin, "*.") {
			domain := strings.TrimPrefix(allowedOrigin, "*.")
			if strings.HasSuffix(origin, domain) {
				return true
			}
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
