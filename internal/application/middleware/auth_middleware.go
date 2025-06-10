package middleware

import (
	"context"
	"govpn/pkg/errors"
	"govpn/pkg/jwt"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	jwtService *jwt.Service
}

func NewAuthMiddleware(secret string) *AuthMiddleware {
	// Create a minimal JWT service for token validation
	jwtService := jwt.NewService(secret, "", 0, 0)

	return &AuthMiddleware{
		jwtService: jwtService,
	}
}

func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.respondWithError(c, errors.Unauthorized("Authorization header required", nil))
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			m.respondWithError(c, errors.Unauthorized("Invalid authorization header format", nil))
			return
		}

		token := parts[1]
		if token == "" {
			m.respondWithError(c, errors.Unauthorized("Token required", nil))
			return
		}

		// Validate token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			m.respondWithError(c, errors.Unauthorized("Invalid token", err))
			return
		}

		// Set user information in context
		ctx := context.WithValue(c.Request.Context(), "username", claims.Username)
		ctx = context.WithValue(ctx, "role", claims.Role)
		c.Request = c.Request.WithContext(ctx)

		// Set user info in Gin context for easier access
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)

		c.Next()
	}
}

func (m *AuthMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			m.respondWithError(c, errors.Unauthorized("Authentication required", nil))
			return
		}

		if role != "Admin" {
			m.respondWithError(c, errors.Forbidden("Admin access required", nil))
			return
		}

		c.Next()
	}
}

func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		token := parts[1]
		if token == "" {
			c.Next()
			return
		}

		// Try to validate token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			c.Next()
			return
		}

		// Set user information in context if token is valid
		ctx := context.WithValue(c.Request.Context(), "username", claims.Username)
		ctx = context.WithValue(ctx, "role", claims.Role)
		c.Request = c.Request.WithContext(ctx)

		c.Set("username", claims.Username)
		c.Set("role", claims.Role)

		c.Next()
	}
}

func (m *AuthMiddleware) respondWithError(c *gin.Context, err *errors.AppError) {
	c.JSON(err.Status, gin.H{
		"error": gin.H{
			"code":    err.Code,
			"message": err.Message,
			"status":  err.Status,
		},
	})
	c.Abort()
}
