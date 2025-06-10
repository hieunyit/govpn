package middleware

import (
	"context"
	"govpn/pkg/config"
	"govpn/pkg/errors"
	"govpn/pkg/jwt"
	"govpn/pkg/logger"
	"strings"

	"github.com/gin-gonic/gin"
)

// JWTService interface to support both HMAC and RSA implementations
type JWTService interface {
	ValidateAccessToken(tokenString string) (*jwt.Claims, error)
}

type AuthMiddleware struct {
	jwtService JWTService
}

func NewAuthMiddleware(jwtConfig config.JWTConfig) *AuthMiddleware {
	var jwtService JWTService

	if jwtConfig.UseRSA {
		// Use RSA JWT service
		if jwtConfig.AccessPrivateKey != "" && jwtConfig.RefreshPrivateKey != "" {
			// Use provided RSA keys
			rsaService, err := jwt.NewRSAServiceWithKeys(
				jwtConfig.AccessPrivateKey,
				jwtConfig.RefreshPrivateKey,
				jwtConfig.AccessTokenExpireDuration,
				jwtConfig.RefreshTokenExpireDuration,
			)
			if err != nil {
				logger.Log.WithError(err).Error("Failed to create RSA JWT service with provided keys, falling back to generated keys")
				// Fallback to generated keys
				rsaService, err = jwt.NewRSAService(
					jwtConfig.AccessTokenExpireDuration,
					jwtConfig.RefreshTokenExpireDuration,
				)
				if err != nil {
					logger.Log.WithError(err).Fatal("Failed to create RSA JWT service")
				}
			}
			jwtService = rsaService
			logger.Log.Info("Auth middleware using RSA256 JWT service")
		} else {
			// Generate new RSA keys
			rsaService, err := jwt.NewRSAService(
				jwtConfig.AccessTokenExpireDuration,
				jwtConfig.RefreshTokenExpireDuration,
			)
			if err != nil {
				logger.Log.WithError(err).Fatal("Failed to create RSA JWT service")
			}
			jwtService = rsaService
			logger.Log.Info("Auth middleware using RSA256 JWT service with generated keys")
		}
	} else {
		// Use legacy HMAC JWT service
		hmacService := jwt.NewService(
			jwtConfig.Secret,
			jwtConfig.RefreshSecret,
			jwtConfig.AccessTokenExpireDuration,
			jwtConfig.RefreshTokenExpireDuration,
		)
		jwtService = hmacService
		logger.Log.Warn("Auth middleware using legacy HMAC256 JWT service")
	}

	return &AuthMiddleware{
		jwtService: jwtService,
	}
}

// Legacy constructor for backward compatibility
func NewAuthMiddlewareWithSecret(secret string) *AuthMiddleware {
	// Create legacy HMAC service
	jwtService := jwt.NewService(secret, "", 0, 0)

	return &AuthMiddleware{
		jwtService: jwtService,
	}
}

func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Log the request for debugging
		logger.Log.WithField("path", c.Request.URL.Path).
			WithField("method", c.Request.Method).
			Debug("Processing authentication for request")

		authHeader := c.GetHeader("Authorization")

		// Enhanced logging for auth header
		if authHeader == "" {
			logger.Log.Debug("No Authorization header provided")
			m.respondWithError(c, errors.Unauthorized("Authorization header required", nil))
			return
		}

		logger.Log.WithField("authHeader", authHeader[:min(len(authHeader), 50)]+"...").
			Debug("Authorization header received")

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			logger.Log.WithField("authHeader", authHeader).
				Error("Invalid authorization header format - missing space")
			m.respondWithError(c, errors.Unauthorized("Invalid authorization header format - expected 'Bearer <token>'", nil))
			return
		}

		if parts[0] != "Bearer" {
			logger.Log.WithField("prefix", parts[0]).
				Error("Invalid authorization header format - wrong prefix")
			m.respondWithError(c, errors.Unauthorized("Invalid authorization header format - must start with 'Bearer'", nil))
			return
		}

		token := parts[1]
		if token == "" {
			logger.Log.Error("Empty token in authorization header")
			m.respondWithError(c, errors.Unauthorized("Token required", nil))
			return
		}

		logger.Log.WithField("tokenPrefix", token[:min(len(token), 20)]+"...").
			Debug("Validating JWT token")

		// Validate token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			logger.Log.WithError(err).Error("JWT token validation failed")
			m.respondWithError(c, errors.Unauthorized("Invalid token", err))
			return
		}

		logger.Log.WithField("username", claims.Username).
			WithField("role", claims.Role).
			Debug("JWT token validation successful")

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
			logger.Log.Error("Role not found in context - auth middleware not executed?")
			m.respondWithError(c, errors.Unauthorized("Authentication required", nil))
			return
		}

		userRole := role.(string)
		logger.Log.WithField("userRole", userRole).Debug("Checking admin role requirement")

		if userRole != "Admin" {
			logger.Log.WithField("userRole", userRole).
				Error("User does not have admin role")
			m.respondWithError(c, errors.Forbidden("Admin access required", nil))
			return
		}

		logger.Log.Debug("Admin role requirement satisfied")
		c.Next()
	}
}

func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.Log.Debug("No auth header for optional auth - proceeding without authentication")
			c.Next()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			logger.Log.Debug("Invalid auth header format for optional auth - proceeding without authentication")
			c.Next()
			return
		}

		token := parts[1]
		if token == "" {
			logger.Log.Debug("Empty token for optional auth - proceeding without authentication")
			c.Next()
			return
		}

		// Try to validate token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			logger.Log.WithError(err).Debug("Token validation failed for optional auth - proceeding without authentication")
			c.Next()
			return
		}

		logger.Log.WithField("username", claims.Username).
			Debug("Optional auth successful")

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
	logger.Log.WithField("errorCode", err.Code).
		WithField("errorMessage", err.Message).
		WithField("httpStatus", err.Status).
		Error("Authentication middleware error")

	c.JSON(err.Status, gin.H{
		"error": gin.H{
			"code":    err.Code,
			"message": err.Message,
			"status":  err.Status,
		},
	})
	c.Abort()
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
