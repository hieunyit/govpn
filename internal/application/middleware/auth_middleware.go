package middleware

import (
	"context"
	"govpn/pkg/errors"
	"govpn/pkg/jwt"
	"govpn/pkg/logger"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// =================== ENHANCED AUTH MIDDLEWARE ===================

// AuthMiddleware provides comprehensive authentication and authorization with detailed logging
type AuthMiddleware struct {
	jwtService jwt.JWTServiceInterface
	logger     logger.Logger
}

// NewAuthMiddlewareWithJWTService creates a new auth middleware with enhanced logging and error handling
func NewAuthMiddlewareWithJWTService(jwtService jwt.JWTServiceInterface) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService: jwtService,
		logger:     logger.Log,
	}
}

// =================== REQUEST TRACKING MIDDLEWARE ===================

// TrackRequests tracks all incoming requests with comprehensive metadata and performance monitoring
func (m *AuthMiddleware) TrackRequests() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Generate or extract request ID for complete request tracking
		requestID := m.getOrGenerateRequestID(c)
		c.Set("request_id", requestID)
		c.Set("start_time", startTime)

		// Collect comprehensive request metadata for structured logging
		requestMetadata := map[string]interface{}{
			"request_id":     requestID,
			"method":         c.Request.Method,
			"path":           c.Request.URL.Path,
			"query":          c.Request.URL.RawQuery,
			"user_agent":     c.GetHeader("User-Agent"),
			"content_type":   c.GetHeader("Content-Type"),
			"content_length": c.Request.ContentLength,
			"ip":             c.ClientIP(),
			"start_time":     startTime.Format(time.RFC3339),
		}

		// Log incoming request with comprehensive context
		m.logger.WithFields(requestMetadata).Info("Incoming API request")

		// Set request ID header for client tracking and debugging
		c.Header("X-Request-ID", requestID)

		// Process request through middleware chain
		c.Next()

		// Calculate processing time and log response with performance metrics
		endTime := time.Now()
		duration := endTime.Sub(startTime)

		responseMetadata := map[string]interface{}{
			"request_id":    requestID,
			"method":        c.Request.Method,
			"path":          c.Request.URL.Path,
			"status":        c.Writer.Status(),
			"response_time": duration.Milliseconds(),
			"response_size": c.Writer.Size(),
			"ip":            c.ClientIP(),
			"end_time":      endTime.Format(time.RFC3339),
		}

		// Add user context if available for audit logging
		if username, exists := c.Get("username"); exists {
			responseMetadata["username"] = username
			responseMetadata["authenticated"] = true
		} else {
			responseMetadata["authenticated"] = false
		}

		if role, exists := c.Get("role"); exists {
			responseMetadata["role"] = role
		}

		// Log with appropriate level based on status code and performance
		statusCode := c.Writer.Status()

		if statusCode >= 500 {
			// Server errors - critical logging with full context
			m.logger.WithFields(responseMetadata).Error("API request completed with server error")
		} else if statusCode >= 400 {
			// Client errors - warning level with request details
			m.logger.WithFields(responseMetadata).Warn("API request completed with client error")
		} else if duration > time.Second*5 {
			// Slow successful requests - performance monitoring
			m.logger.WithFields(responseMetadata).Warn("API request completed successfully but slowly")
		} else {
			// Normal successful requests - info level
			m.logger.WithFields(responseMetadata).Info("API request completed successfully")
		}

		// Log performance metrics for monitoring and alerting
		m.logPerformanceMetrics(c, requestMetadata, responseMetadata, duration)
	}
}

// =================== AUTHENTICATION MIDDLEWARE ===================

// RequireAuth ensures the request has valid authentication with comprehensive error handling and logging
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get request ID for consistent logging across the request lifecycle
		requestID := m.getOrGenerateRequestID(c)

		// Extract Authorization header with detailed validation
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.logger.WithFields(map[string]interface{}{
				"request_id": requestID,
				"ip":         c.ClientIP(),
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
			}).Warn("Authentication required - missing Authorization header")

			m.respondWithAuthError(c, errors.Unauthorized("Authentication required", map[string]interface{}{
				"missing_header":  "Authorization",
				"expected_format": "Bearer <token>",
				"help":            "Include 'Authorization: Bearer <your-jwt-token>' header",
			}))
			return
		}

		// Parse Bearer token with format validation
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			m.logger.WithFields(map[string]interface{}{
				"request_id":   requestID,
				"ip":           c.ClientIP(),
				"auth_header":  "Bearer ***", // Masked for security
				"header_parts": len(parts),
			}).Warn("Authentication failed - invalid Authorization header format")

			m.respondWithAuthError(c, errors.Unauthorized("Invalid authorization header format", map[string]interface{}{
				"provided_format": "Invalid",
				"expected_format": "Bearer <token>",
				"example":         "Authorization: Bearer eyJhbGciOiJSUzI1NiIs...",
			}))
			return
		}

		token := parts[1]
		if token == "" {
			m.logger.WithFields(map[string]interface{}{
				"request_id": requestID,
				"ip":         c.ClientIP(),
			}).Warn("Authentication failed - empty token")

			m.respondWithAuthError(c, errors.Unauthorized("Empty authentication token", map[string]interface{}{
				"issue": "Token is empty or missing after 'Bearer '",
				"help":  "Ensure your JWT token is properly included",
			}))
			return
		}

		// Validate JWT token with comprehensive error handling
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			// Log authentication failure with context but don't expose token details
			m.logger.WithFields(map[string]interface{}{
				"request_id":       requestID,
				"ip":               c.ClientIP(),
				"path":             c.Request.URL.Path,
				"method":           c.Request.Method,
				"validation_error": err.Error(),
			}).Warn("Authentication failed - token validation error")

			// Provide specific error messages based on JWT validation failure type
			var errorDetails map[string]interface{}
			errorMsg := "Invalid authentication token"

			if strings.Contains(err.Error(), "expired") {
				errorMsg = "Authentication token has expired"
				errorDetails = map[string]interface{}{
					"error_type":       "token_expired",
					"suggestion":       "Refresh your token or re-authenticate",
					"refresh_endpoint": "/auth/refresh",
				}
			} else if strings.Contains(err.Error(), "invalid") {
				errorMsg = "Authentication token is invalid"
				errorDetails = map[string]interface{}{
					"error_type":     "token_invalid",
					"suggestion":     "Re-authenticate to get a new token",
					"login_endpoint": "/auth/login",
				}
			} else {
				errorDetails = map[string]interface{}{
					"error_type": "token_verification_failed",
					"suggestion": "Check token format and re-authenticate if needed",
				}
			}

			m.respondWithAuthError(c, errors.Unauthorized(errorMsg, errorDetails))
			return
		}

		// Log successful authentication with user context
		m.logger.WithFields(map[string]interface{}{
			"request_id": requestID,
			"username":   claims.Username,
			"role":       claims.Role,
			"ip":         c.ClientIP(),
			"path":       c.Request.URL.Path,
			"method":     c.Request.Method,
		}).Debug("Authentication successful")

		// Set user information in context for downstream handlers and audit logging
		ctx := context.WithValue(c.Request.Context(), "username", claims.Username)
		ctx = context.WithValue(ctx, "role", claims.Role)
		ctx = context.WithValue(ctx, "user_id", claims.UserID)
		c.Request = c.Request.WithContext(ctx)

		// Set in Gin context for easier access in handlers
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Set("user_id", claims.UserID)
		c.Set("authenticated", true)

		c.Next()
	}
}

// RequireAdminRole ensures the authenticated user has admin privileges with detailed logging
func (m *AuthMiddleware) RequireAdminRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := m.getOrGenerateRequestID(c)

		// Check if user is authenticated (this should be called after RequireAuth)
		username, exists := c.Get("username")
		if !exists {
			m.logger.WithFields(map[string]interface{}{
				"request_id": requestID,
				"ip":         c.ClientIP(),
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
			}).Error("Admin role check failed - user not authenticated")

			m.respondWithAuthError(c, errors.Unauthorized("Authentication required for admin access", map[string]interface{}{
				"required_flow": "Must authenticate before checking admin role",
				"help":          "Ensure RequireAuth middleware runs before RequireAdminRole",
			}))
			return
		}

		// Get user role with validation
		role, exists := c.Get("role")
		if !exists {
			m.logger.WithFields(map[string]interface{}{
				"request_id": requestID,
				"username":   username,
				"ip":         c.ClientIP(),
			}).Error("Admin role check failed - role not found in context")

			m.respondWithAuthError(c, errors.Forbidden("Role information not available", map[string]interface{}{
				"issue":      "User role not found in authentication context",
				"suggestion": "Re-authenticate to get proper role information",
			}))
			return
		}

		userRole := role.(string)

		// Log admin role requirement check
		m.logger.WithFields(map[string]interface{}{
			"request_id":    requestID,
			"username":      username,
			"user_role":     userRole,
			"required_role": "Admin",
			"ip":            c.ClientIP(),
			"path":          c.Request.URL.Path,
			"method":        c.Request.Method,
		}).Debug("Checking admin role requirement")

		// Verify admin role with detailed error response
		if userRole != "Admin" {
			m.logger.WithFields(map[string]interface{}{
				"request_id":    requestID,
				"username":      username,
				"user_role":     userRole,
				"required_role": "Admin",
				"ip":            c.ClientIP(),
				"path":          c.Request.URL.Path,
			}).Warn("Admin access denied - insufficient privileges")

			m.respondWithAuthError(c, errors.Forbidden("Admin access required", map[string]interface{}{
				"current_role":  userRole,
				"required_role": "Admin",
				"message":       "This operation requires administrator privileges",
				"contact":       "Contact your system administrator to request admin access",
			}))
			return
		}

		// Log successful admin role verification
		m.logger.WithFields(map[string]interface{}{
			"request_id": requestID,
			"username":   username,
			"role":       userRole,
			"ip":         c.ClientIP(),
			"path":       c.Request.URL.Path,
		}).Debug("Admin role requirement satisfied")

		c.Next()
	}
}

// OptionalAuth provides optional authentication without requiring it, with logging for audit trails
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := m.getOrGenerateRequestID(c)

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.logger.WithFields(map[string]interface{}{
				"request_id": requestID,
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
				"ip":         c.ClientIP(),
			}).Debug("No auth header for optional auth - proceeding without authentication")
			c.Set("authenticated", false)
			c.Next()
			return
		}

		// Try to parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			m.logger.WithFields(map[string]interface{}{
				"request_id": requestID,
				"path":       c.Request.URL.Path,
				"ip":         c.ClientIP(),
			}).Debug("Invalid auth header format for optional auth - proceeding without authentication")
			c.Set("authenticated", false)
			c.Next()
			return
		}

		token := parts[1]
		if token == "" {
			m.logger.WithFields(map[string]interface{}{
				"request_id": requestID,
				"path":       c.Request.URL.Path,
				"ip":         c.ClientIP(),
			}).Debug("Empty token for optional auth - proceeding without authentication")
			c.Set("authenticated", false)
			c.Next()
			return
		}

		// Try to validate token but don't fail if invalid
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			m.logger.WithFields(map[string]interface{}{
				"request_id":       requestID,
				"path":             c.Request.URL.Path,
				"ip":               c.ClientIP(),
				"validation_error": err.Error(),
			}).Debug("Token validation failed for optional auth - proceeding without authentication")
			c.Set("authenticated", false)
			c.Next()
			return
		}

		// Log successful optional authentication
		m.logger.WithFields(map[string]interface{}{
			"request_id": requestID,
			"username":   claims.Username,
			"role":       claims.Role,
			"path":       c.Request.URL.Path,
			"ip":         c.ClientIP(),
		}).Debug("Optional auth successful")

		// Set user information in context if token is valid
		ctx := context.WithValue(c.Request.Context(), "username", claims.Username)
		ctx = context.WithValue(ctx, "role", claims.Role)
		ctx = context.WithValue(ctx, "user_id", claims.UserID)
		c.Request = c.Request.WithContext(ctx)

		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Set("user_id", claims.UserID)
		c.Set("authenticated", true)

		c.Next()
	}
}

// =================== HELPER METHODS ===================

// getOrGenerateRequestID retrieves or generates a unique request ID for tracking
func (m *AuthMiddleware) getOrGenerateRequestID(c *gin.Context) string {
	// Check if already set in context
	if requestID, exists := c.Get("request_id"); exists {
		return requestID.(string)
	}

	// Check X-Request-ID header from client
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		c.Set("request_id", requestID)
		return requestID
	}

	// Check X-Correlation-ID header (alternative naming)
	if requestID := c.GetHeader("X-Correlation-ID"); requestID != "" {
		c.Set("request_id", requestID)
		return requestID
	}

	// Generate new UUID-based request ID for complete request tracking
	requestID := "req_" + uuid.New().String()
	c.Set("request_id", requestID)
	return requestID
}

// respondWithAuthError sends standardized authentication/authorization error responses with enhanced details
func (m *AuthMiddleware) respondWithAuthError(c *gin.Context, err *errors.AppError) {
	requestID := m.getOrGenerateRequestID(c)

	// Log authentication/authorization error with comprehensive context
	m.logger.WithFields(map[string]interface{}{
		"request_id":    requestID,
		"error_code":    err.Code,
		"error_message": err.Message,
		"http_status":   err.Status,
		"ip":            c.ClientIP(),
		"path":          c.Request.URL.Path,
		"method":        c.Request.Method,
		"user_agent":    c.GetHeader("User-Agent"),
	}).Error("Authentication/authorization error")

	// Create standardized error response with enhanced metadata
	response := map[string]interface{}{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"request_id": requestID,
		"version":    "1.1.0",
		"path":       c.Request.URL.Path,
		"method":     c.Request.Method,
		"error": map[string]interface{}{
			"code":     err.Code,
			"message":  err.Message,
			"status":   err.Status,
			"details":  err.Details,
			"severity": "error",
			"trace_id": "trace_" + uuid.New().String(),
		},
	}

	// Add specific suggestions based on error type
	if err.Status == 401 {
		response["error"].(map[string]interface{})["suggestions"] = []string{
			"Provide valid authentication token",
			"Check token expiration",
			"Re-authenticate if token is invalid",
		}
		response["error"].(map[string]interface{})["help_url"] = "https://docs.api.com/authentication"
	} else if err.Status == 403 {
		response["error"].(map[string]interface{})["suggestions"] = []string{
			"Contact administrator for permissions",
			"Verify user role requirements",
			"Check if additional privileges are needed",
		}
		response["error"].(map[string]interface{})["help_url"] = "https://docs.api.com/authorization"
	}

	c.JSON(err.Status, response)
	c.Abort()
}

// logPerformanceMetrics logs detailed performance metrics for monitoring and alerting
func (m *AuthMiddleware) logPerformanceMetrics(c *gin.Context, requestMetadata, responseMetadata map[string]interface{}, duration time.Duration) {
	// Skip metrics logging for health checks and other non-business endpoints
	path := c.Request.URL.Path
	if strings.Contains(path, "/health") ||
		strings.Contains(path, "/metrics") ||
		strings.Contains(path, "/swagger") {
		return
	}

	metricsFields := map[string]interface{}{
		"metric_type":      "api_performance",
		"request_id":       requestMetadata["request_id"],
		"endpoint":         path,
		"method":           c.Request.Method,
		"status_code":      responseMetadata["status"],
		"response_time_ms": duration.Milliseconds(),
		"response_size":    responseMetadata["response_size"],
		"content_length":   requestMetadata["content_length"],
		"timestamp":        time.Now().Unix(),
	}

	// Add user context for business metrics
	if username, exists := responseMetadata["username"]; exists {
		metricsFields["user_type"] = "authenticated"
		metricsFields["username"] = username
		if role, exists := responseMetadata["role"]; exists {
			metricsFields["role"] = role
		}
	} else {
		metricsFields["user_type"] = "anonymous"
	}

	// Categorize endpoint type for better metrics grouping
	metricsFields["endpoint_category"] = m.categorizeEndpoint(path)

	// Log performance metrics for external monitoring systems
	m.logger.WithFields(metricsFields).Info("API performance metrics")

	// Generate alerts for slow endpoints with detailed context
	if duration > time.Second*10 {
		alertFields := map[string]interface{}{
			"alert_type":        "slow_endpoint",
			"request_id":        requestMetadata["request_id"],
			"endpoint":          path,
			"response_time_sec": duration.Seconds(),
			"threshold_sec":     10.0,
			"severity":          "warning",
			"ip":                c.ClientIP(),
			"user_agent":        requestMetadata["user_agent"],
		}

		if username, exists := responseMetadata["username"]; exists {
			alertFields["username"] = username
		}

		m.logger.WithFields(alertFields).Error("Slow endpoint performance alert")
	}

	// Generate alerts for high error rates
	if statusCode := responseMetadata["status"].(int); statusCode >= 500 {
		alertFields := map[string]interface{}{
			"alert_type":  "server_error",
			"request_id":  requestMetadata["request_id"],
			"endpoint":    path,
			"status_code": statusCode,
			"severity":    "critical",
			"ip":          c.ClientIP(),
		}

		m.logger.WithFields(alertFields).Error("Server error alert")
	}
}

// categorizeEndpoint categorizes endpoints for better metrics organization
func (m *AuthMiddleware) categorizeEndpoint(path string) string {
	switch {
	case strings.Contains(path, "/auth"):
		return "authentication"
	case strings.Contains(path, "/users"):
		return "user_management"
	case strings.Contains(path, "/groups"):
		return "group_management"
	case strings.Contains(path, "/bulk"):
		return "bulk_operations"
	case strings.Contains(path, "/search"):
		return "search_operations"
	case strings.Contains(path, "/health"):
		return "system_health"
	case strings.Contains(path, "/admin"):
		return "administration"
	default:
		return "other"
	}
}

// =================== SECURITY HEADERS MIDDLEWARE ===================

// SecurityHeaders adds comprehensive security headers to all responses
func (m *AuthMiddleware) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := m.getOrGenerateRequestID(c)

		// Set comprehensive security headers for protection against common attacks
		c.Header("X-Content-Type-Options", "nosniff")                                // Prevent MIME type sniffing
		c.Header("X-Frame-Options", "DENY")                                          // Prevent clickjacking
		c.Header("X-XSS-Protection", "1; mode=block")                                // Enable XSS protection
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")               // Control referrer information
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'") // CSP for XSS protection
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains") // HSTS for HTTPS enforcement

		// API-specific headers for client information and debugging
		c.Header("X-API-Version", "1.1.0")
		c.Header("X-Service-Name", "govpn-api")
		c.Header("X-Request-ID", requestID)

		// Rate limiting information headers (would be populated by rate limiting middleware)
		c.Header("X-RateLimit-Limit", "1000")  // Requests per hour
		c.Header("X-RateLimit-Window", "3600") // Window in seconds

		// Log security headers application for audit purposes
		m.logger.WithFields(map[string]interface{}{
			"request_id":       requestID,
			"security_headers": "applied",
			"path":             c.Request.URL.Path,
			"method":           c.Request.Method,
		}).Debug("Security headers applied")

		c.Next()
	}
}
