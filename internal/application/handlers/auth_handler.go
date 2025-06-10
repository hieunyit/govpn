package handlers

import (
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/usecases"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	nethttp "net/http"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authUsecase usecases.AuthUsecase
}

func NewAuthHandler(authUsecase usecases.AuthUsecase) *AuthHandler {
	return &AuthHandler{
		authUsecase: authUsecase,
	}
}

// Login godoc
// @Summary User login
// @Description Authenticate user and return JWT tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Login credentials"
// @Success 200 {object} dto.LoginResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind login request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Login request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Convert DTO to entity
	credentials := &entities.LoginCredentials{
		Username: req.Username,
		Password: req.Password,
	}

	// Authenticate user
	tokens, err := h.authUsecase.Login(c.Request.Context(), credentials)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Login failed", err))
		}
		return
	}

	// Get user info for response (this could be enhanced)
	userInfo := dto.UserInfo{
		Username: credentials.Username,
		Role:     "Admin", // This should come from the user entity
	}

	response := dto.LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User:         userInfo,
	}

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// RefreshToken godoc
// @Summary Refresh access token
// @Description Refresh access token using refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body dto.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} dto.RefreshTokenResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req dto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind refresh token request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Refresh token request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Convert DTO to entity
	refreshReq := &entities.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	}

	// Refresh tokens
	tokens, err := h.authUsecase.RefreshToken(c.Request.Context(), refreshReq)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Token refresh failed", err))
		}
		return
	}

	// This should get user info from the validated token
	userInfo := dto.UserInfo{
		Username: "", // Should be extracted from token claims
		Role:     "Admin",
	}

	response := dto.RefreshTokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User:         userInfo,
	}

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// ValidateToken godoc
// @Summary Validate access token
// @Description Validate the current access token
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} dto.UserInfo
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/validate [get]
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	// This endpoint is protected by auth middleware
	// If we reach here, the token is valid
	username, exists := c.Get("username")
	if !exists {
		RespondWithError(c, errors.Unauthorized("Invalid token", nil))
		return
	}

	role, _ := c.Get("role")

	userInfo := dto.UserInfo{
		Username: username.(string),
		Role:     role.(string),
	}

	RespondWithSuccess(c, nethttp.StatusOK, userInfo)
}

// Response helper functions are now in response_helpers.go
