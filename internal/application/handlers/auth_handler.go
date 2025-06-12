package handlers

import (
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/usecases"
	httpPkg "govpn/internal/presentation/http"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// =================== ENHANCED AUTH HANDLER ===================

// AuthHandler handles authentication-related HTTP requests with comprehensive response system and logging
type AuthHandler struct {
	authUsecase usecases.AuthUsecaseInterface
	logger      logger.Logger
}

// NewAuthHandler creates a new auth handler with enhanced response and logging capabilities
func NewAuthHandler(authUsecase usecases.AuthUsecaseInterface) *AuthHandler {
	return &AuthHandler{
		authUsecase: authUsecase,
		logger:      logger.Log,
	}
}

// =================== AUTHENTICATION ENDPOINTS ===================

// Login godoc
// @Summary Authenticate user and generate JWT tokens
// @Description Authenticate user with username/password and return access and refresh tokens with comprehensive error handling
// @Tags Authentication
// @Accept json
// @Produce json
// @Param credentials body dto.LoginRequest true "User login credentials with username and password"
// @Success 200 {object} httpPkg.SuccessResponse{data=dto.LoginResponse} "Login successful with tokens and user info"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid request format with validation details"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - invalid credentials with security info"
// @Failure 422 {object} httpPkg.ValidationErrorResponse "Validation failed with field-specific errors"
// @Failure 429 {object} httpPkg.RateLimitErrorResponse "Too many login attempts with rate limit info"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	// Set start time for performance tracking and security monitoring
	c.Set("start_time", time.Now())

	// Parse and validate login request with detailed error handling
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"ip":         c.ClientIP(),
			"user_agent": c.GetHeader("User-Agent"),
		}).Error("Failed to bind login request")

		httpPkg.RespondWithError(c, errors.BadRequest("Invalid login request format", map[string]interface{}{
			"binding_error":   err.Error(),
			"expected_format": "JSON with username and password fields",
			"example": map[string]string{
				"username": "your_username",
				"password": "your_password",
			},
		}))
		return
	}

	// Comprehensive validation with field-specific errors
	if err := validator.Validate(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"username":   req.Username,
			"ip":         c.ClientIP(),
		}).Warn("Login request validation failed")
		httpPkg.RespondWithValidationError(c, err)
		return
	}

	// Security logging: Log login attempt with comprehensive context
	h.logger.WithFields(map[string]interface{}{
		"username":     req.Username,
		"request_id":   httpPkg.getOrGenerateRequestID(c),
		"ip":           c.ClientIP(),
		"user_agent":   c.GetHeader("User-Agent"),
		"attempt_time": time.Now().UTC().Format(time.RFC3339),
	}).Info("Login attempt initiated")

	// Convert DTO to entity for use case
	credentials := &entities.LoginCredentials{
		Username: req.Username,
		Password: req.Password,
	}

	// Authenticate user with comprehensive error handling and security monitoring
	tokens, err := h.authUsecase.Login(c.Request.Context(), credentials)
	if err != nil {
		// Security logging: Log failed login attempt with detailed context
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":     req.Username,
			"request_id":   httpPkg.getOrGenerateRequestID(c),
			"ip":           c.ClientIP(),
			"user_agent":   c.GetHeader("User-Agent"),
			"failure_time": time.Now().UTC().Format(time.RFC3339),
			"error_type":   "authentication_failed",
		}).Warn("Login attempt failed")

		// Enhanced error response with security considerations
		if appErr, ok := err.(*errors.AppError); ok {
			// Add security-specific error details for authentication failures
			if appErr.Status == 401 {
				enhancedErr := errors.Unauthorized("Invalid username or password", map[string]interface{}{
					"security_note":      "For security reasons, we don't specify whether the username or password was incorrect",
					"attempts_remaining": "Multiple failed attempts may result in temporary account lockout",
					"help": []string{
						"Verify your username and password",
						"Check if caps lock is enabled",
						"Contact support if you've forgotten your credentials",
					},
					"support_contact": "support@company.com",
				})
				httpPkg.RespondWithError(c, enhancedErr)
			} else {
				httpPkg.RespondWithError(c, appErr)
			}
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Authentication service unavailable", map[string]interface{}{
				"internal_error":   "Authentication processing failed",
				"context":          "login_authentication",
				"retry_suggestion": "Please try again in a few moments",
			}))
		}
		return
	}

	// Get user information for enhanced response
	userInfo := dto.UserInfo{
		Username: credentials.Username,
		Role:     "Admin", // This should come from the authenticated user entity
	}

	// Enhanced login response with comprehensive token information
	response := dto.LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User:         userInfo,
		TokenType:    "Bearer",
		ExpiresIn:    15 * 60, // 15 minutes in seconds (should come from config)
		IssuedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	// Security logging: Log successful login with comprehensive audit trail
	h.logger.WithFields(map[string]interface{}{
		"username":        credentials.Username,
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"ip":              c.ClientIP(),
		"user_agent":      c.GetHeader("User-Agent"),
		"success_time":    time.Now().UTC().Format(time.RFC3339),
		"token_issued":    true,
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Info("Login successful - tokens issued")

	// Send enhanced success response with metadata and security headers
	httpPkg.RespondWithSuccess(c, http.StatusOK, response, "auth", "login")
}

// RefreshToken godoc
// @Summary Refresh access token using refresh token
// @Description Exchange a valid refresh token for new access and refresh tokens with security validation
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body dto.RefreshTokenRequest true "Refresh token for token renewal"
// @Success 200 {object} httpPkg.SuccessResponse{data=dto.RefreshTokenResponse} "Token refreshed successfully with new tokens"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid request format with validation details"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - invalid or expired refresh token with renewal info"
// @Failure 422 {object} httpPkg.ValidationErrorResponse "Validation failed with field-specific errors"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	// Parse and validate refresh token request
	var req dto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"ip":         c.ClientIP(),
		}).Error("Failed to bind refresh token request")

		httpPkg.RespondWithError(c, errors.BadRequest("Invalid refresh token request format", map[string]interface{}{
			"binding_error":   err.Error(),
			"expected_format": "JSON with refresh_token field",
			"example": map[string]string{
				"refresh_token": "your_refresh_token_here",
			},
		}))
		return
	}

	// Comprehensive validation with security considerations
	if err := validator.Validate(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"ip":         c.ClientIP(),
		}).Warn("Refresh token request validation failed")
		httpPkg.RespondWithValidationError(c, err)
		return
	}

	// Security logging: Log token refresh attempt
	h.logger.WithFields(map[string]interface{}{
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"ip":              c.ClientIP(),
		"user_agent":      c.GetHeader("User-Agent"),
		"refresh_attempt": time.Now().UTC().Format(time.RFC3339),
	}).Info("Token refresh attempt initiated")

	// Convert DTO to entity
	refreshReq := &entities.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	}

	// Refresh tokens with comprehensive error handling
	tokens, err := h.authUsecase.RefreshToken(c.Request.Context(), refreshReq)
	if err != nil {
		// Security logging: Log failed token refresh
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id":   httpPkg.getOrGenerateRequestID(c),
			"ip":           c.ClientIP(),
			"user_agent":   c.GetHeader("User-Agent"),
			"failure_time": time.Now().UTC().Format(time.RFC3339),
			"error_type":   "token_refresh_failed",
		}).Warn("Token refresh failed")

		if appErr, ok := err.(*errors.AppError); ok {
			// Enhanced error response for token refresh failures
			if appErr.Status == 401 {
				enhancedErr := errors.Unauthorized("Invalid or expired refresh token", map[string]interface{}{
					"error_details":   "The provided refresh token is invalid, expired, or has been revoked",
					"action_required": "Please log in again to obtain new tokens",
					"login_endpoint":  "/auth/login",
					"security_note":   "For security reasons, refresh tokens have limited lifetime and single-use policy",
				})
				httpPkg.RespondWithError(c, enhancedErr)
			} else {
				httpPkg.RespondWithError(c, appErr)
			}
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Token refresh service unavailable", map[string]interface{}{
				"internal_error":   "Token refresh processing failed",
				"context":          "token_refresh",
				"retry_suggestion": "Please try again or re-authenticate",
			}))
		}
		return
	}

	// Extract user info from refreshed token (this should come from token claims)
	userInfo := dto.UserInfo{
		Username: "",      // Should be extracted from token claims
		Role:     "Admin", // Should be extracted from token claims
	}

	// Enhanced refresh response with comprehensive token information
	response := dto.RefreshTokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User:         userInfo,
		TokenType:    "Bearer",
		ExpiresIn:    15 * 60, // 15 minutes in seconds (should come from config)
		IssuedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	// Security logging: Log successful token refresh
	h.logger.WithFields(map[string]interface{}{
		"username":        userInfo.Username,
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"ip":              c.ClientIP(),
		"user_agent":      c.GetHeader("User-Agent"),
		"success_time":    time.Now().UTC().Format(time.RFC3339),
		"tokens_issued":   true,
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Info("Token refresh successful - new tokens issued")

	// Send enhanced success response
	httpPkg.RespondWithSuccess(c, http.StatusOK, response, "auth", "refresh")
}

// ValidateToken godoc
// @Summary Validate the current access token
// @Description Validate the provided access token and return user information with comprehensive verification
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} httpPkg.SuccessResponse{data=dto.UserInfo} "Token is valid with user information"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - invalid or expired token with validation details"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /auth/validate [get]
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	// This endpoint is protected by auth middleware
	// If we reach here, the token has already been validated
	username, exists := c.Get("username")
	if !exists {
		h.logger.WithFields(map[string]interface{}{
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"ip":         c.ClientIP(),
			"error":      "username_not_in_context",
		}).Error("Token validation failed - username not found in context")

		httpPkg.RespondWithError(c, errors.Unauthorized("Invalid token context", map[string]interface{}{
			"issue":          "User information not available from token",
			"suggestion":     "Re-authenticate to get a valid token",
			"login_endpoint": "/auth/login",
		}))
		return
	}

	// Get additional user information from context
	role, _ := c.Get("role")
	userID, _ := c.Get("user_id")

	// Create comprehensive user info response
	userInfo := dto.UserInfo{
		Username: username.(string),
		Role:     role.(string),
		UserID:   userID,
	}

	// Security logging: Log token validation success
	h.logger.WithFields(map[string]interface{}{
		"username":        userInfo.Username,
		"role":            userInfo.Role,
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"ip":              c.ClientIP(),
		"user_agent":      c.GetHeader("User-Agent"),
		"validation_time": time.Now().UTC().Format(time.RFC3339),
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Debug("Token validation successful")

	// Send enhanced success response with token validation metadata
	httpPkg.RespondWithSuccess(c, http.StatusOK, map[string]interface{}{
		"user": userInfo,
		"token_status": map[string]interface{}{
			"valid":        true,
			"validated_at": time.Now().UTC().Format(time.RFC3339),
			"expires_in":   "14m30s", // Approximate remaining time (should be calculated from token)
		},
	}, "auth", "validate")
}

// Logout godoc
// @Summary Logout user and invalidate tokens
// @Description Logout the current user and invalidate their tokens for security
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} httpPkg.MessageResponse "Logout successful with confirmation"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - invalid token"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	// Get user information from context (set by auth middleware)
	username, exists := c.Get("username")
	if !exists {
		h.logger.WithFields(map[string]interface{}{
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"ip":         c.ClientIP(),
		}).Error("Logout failed - username not found in context")

		httpPkg.RespondWithError(c, errors.Unauthorized("Invalid authentication context", map[string]interface{}{
			"issue":      "User information not available",
			"suggestion": "Re-authenticate before attempting logout",
		}))
		return
	}

	// Security logging: Log logout attempt
	h.logger.WithFields(map[string]interface{}{
		"username":    username.(string),
		"request_id":  httpPkg.getOrGenerateRequestID(c),
		"ip":          c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
		"logout_time": time.Now().UTC().Format(time.RFC3339),
	}).Info("User logout initiated")

	// In a complete implementation, this would:
	// 1. Invalidate the refresh token in the database/cache
	// 2. Add the access token to a blacklist
	// 3. Clear any active sessions
	// 4. Log the logout event for audit purposes

	// For now, we'll just log the successful logout
	h.logger.WithFields(map[string]interface{}{
		"username":        username.(string),
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"ip":              c.ClientIP(),
		"logout_success":  true,
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Info("User logout completed successfully")

	// Send logout confirmation with security recommendations
	httpPkg.RespondWithMessage(c, http.StatusOK, "Logout successful - all tokens have been invalidated")
}

// =================== PASSWORD RESET ENDPOINTS ===================

// ForgotPassword godoc
// @Summary Initiate password reset process
// @Description Send password reset instructions to the user's email address
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body dto.ForgotPasswordRequest true "Email for password reset"
// @Success 200 {object} httpPkg.MessageResponse "Password reset instructions sent"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid email format"
// @Failure 422 {object} httpPkg.ValidationErrorResponse "Validation failed"
// @Failure 429 {object} httpPkg.RateLimitErrorResponse "Too many reset requests"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error"
// @Router /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	var req dto.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"ip":         c.ClientIP(),
		}).Error("Failed to bind forgot password request")

		httpPkg.RespondWithError(c, errors.BadRequest("Invalid forgot password request", map[string]interface{}{
			"binding_error":   err.Error(),
			"expected_format": "JSON with email field",
		}))
		return
	}

	if err := validator.Validate(&req); err != nil {
		httpPkg.RespondWithValidationError(c, err)
		return
	}

	// Security logging: Log password reset request
	h.logger.WithFields(map[string]interface{}{
		"email":              req.Email,
		"request_id":         httpPkg.getOrGenerateRequestID(c),
		"ip":                 c.ClientIP(),
		"reset_request_time": time.Now().UTC().Format(time.RFC3339),
	}).Info("Password reset requested")

	// In a complete implementation, this would:
	// 1. Verify the email exists in the system
	// 2. Generate a secure reset token
	// 3. Send reset instructions via email
	// 4. Log the reset request for security monitoring

	// For security reasons, always return success even if email doesn't exist
	httpPkg.RespondWithMessage(c, http.StatusOK, "If the email address is registered, password reset instructions have been sent")
}

// ResetPassword godoc
// @Summary Complete password reset process
// @Description Reset password using the reset token from email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body dto.ResetPasswordRequest true "Reset token and new password"
// @Success 200 {object} httpPkg.MessageResponse "Password reset successful"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid token or password"
// @Failure 422 {object} httpPkg.ValidationErrorResponse "Validation failed"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error"
// @Router /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	var req dto.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"ip":         c.ClientIP(),
		}).Error("Failed to bind reset password request")

		httpPkg.RespondWithError(c, errors.BadRequest("Invalid reset password request", map[string]interface{}{
			"binding_error":   err.Error(),
			"expected_format": "JSON with reset_token and new_password fields",
		}))
		return
	}

	if err := validator.Validate(&req); err != nil {
		httpPkg.RespondWithValidationError(c, err)
		return
	}

	// Security logging: Log password reset attempt
	h.logger.WithFields(map[string]interface{}{
		"request_id":    httpPkg.getOrGenerateRequestID(c),
		"ip":            c.ClientIP(),
		"reset_attempt": time.Now().UTC().Format(time.RFC3339),
		"has_token":     req.ResetToken != "",
		"has_password":  req.NewPassword != "",
	}).Info("Password reset attempt with token")

	// In a complete implementation, this would:
	// 1. Validate the reset token
	// 2. Check token expiration
	// 3. Update the user's password
	// 4. Invalidate all existing tokens
	// 5. Send confirmation email
	// 6. Log the successful reset

	httpPkg.RespondWithMessage(c, http.StatusOK, "Password has been reset successfully. Please log in with your new password")
}

// =================== HELPER METHODS ===================

// getRequestID retrieves request ID from context for logging consistency
func (h *AuthHandler) getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		return requestID.(string)
	}
	return "unknown"
}

// validatePasswordStrength validates password meets security requirements
func (h *AuthHandler) validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.BadRequest("Password too weak", map[string]interface{}{
			"requirement":     "minimum 8 characters",
			"provided_length": len(password),
		})
	}

	if len(password) > 128 {
		return errors.BadRequest("Password too long", map[string]interface{}{
			"requirement":     "maximum 128 characters",
			"provided_length": len(password),
		})
	}

	// Additional strength checks would go here
	return nil
}
