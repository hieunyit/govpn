package handlers

import (
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/usecases"
	"govpn/internal/infrastructure/xmlrpc"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	nethttp "net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	userUsecase  usecases.UserUsecase
	xmlrpcClient *xmlrpc.Client
}

func NewUserHandler(userUsecase usecases.UserUsecase, xmlrpcClient *xmlrpc.Client) *UserHandler {
	return &UserHandler{
		userUsecase:  userUsecase,
		xmlrpcClient: xmlrpcClient,
	}
}

// CreateUser godoc
// @Summary Create a new user
// @Description Create a new VPN user (local or LDAP authentication)
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.CreateUserRequest true "User creation data"
// @Success 201 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Router /api/users [post]
func (h *UserHandler) CreateUser(c *gin.Context) {
	var req dto.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind create user request")
		respondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Enhanced validation for auth-specific requirements
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Create user request validation failed")
		respondWithValidationError(c, err)
		return
	}

	// Additional validation for auth method specific requirements
	if err := req.ValidateAuthSpecific(); err != nil {
		logger.Log.WithError(err).Error("Auth-specific validation failed")
		respondWithError(c, errors.BadRequest(err.Error(), err))
		return
	}

	// Normalize MAC addresses
	req.MacAddresses = validator.ConvertMAC(req.MacAddresses)

	// Convert DTO to entity
	user := &entities.User{
		Username:       req.Username,
		Email:          req.Email,
		Password:       req.Password,
		AuthMethod:     req.AuthMethod,
		UserExpiration: req.UserExpiration,
		MacAddresses:   req.MacAddresses,
		AccessControl:  req.AccessControl,
	}

	// Log the user creation attempt
	logger.Log.WithField("username", user.Username).
		WithField("authMethod", user.AuthMethod).
		WithField("email", user.Email).
		Info("Creating user")

	// Create user
	if err := h.userUsecase.CreateUser(c.Request.Context(), user); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to create user", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after user creation")
		// Don't fail the request, just log the error
	}

	logger.Log.WithField("username", user.Username).Info("User created successfully")
	respondWithMessage(c, nethttp.StatusCreated, "User created successfully")
}

// GetUser godoc
// @Summary Get user by username
// @Description Get detailed information about a user
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param username path string true "Username"
// @Success 200 {object} dto.UserResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /api/users/{username} [get]
func (h *UserHandler) GetUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		respondWithError(c, errors.BadRequest("Username is required", nil))
		return
	}

	logger.Log.WithField("username", username).Debug("Getting user")

	user, err := h.userUsecase.GetUser(c.Request.Context(), username)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to get user", err))
		}
		return
	}

	// Convert entity to DTO
	response := dto.UserResponse{
		Username:       user.Username,
		Email:          user.Email,
		AuthMethod:     user.AuthMethod,
		UserExpiration: user.UserExpiration,
		MacAddresses:   user.MacAddresses,
		MFA:            user.MFA == "true",
		Role:           user.Role,
		DenyAccess:     user.DenyAccess == "true",
		AccessControl:  user.AccessControl,
		GroupName:      user.GroupName,
	}

	respondWithSuccess(c, nethttp.StatusOK, response)
}

// UpdateUser godoc
// @Summary Update user
// @Description Update user information
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param username path string true "Username"
// @Param request body dto.UpdateUserRequest true "User update data"
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /api/users/{username} [put]
func (h *UserHandler) UpdateUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		respondWithError(c, errors.BadRequest("Username is required", nil))
		return
	}

	var req dto.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind update user request")
		respondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Update user request validation failed")
		respondWithValidationError(c, err)
		return
	}

	// Normalize MAC addresses if provided
	if len(req.MacAddresses) > 0 {
		req.MacAddresses = validator.ConvertMAC(req.MacAddresses)
	}

	// Convert DTO to entity
	user := &entities.User{
		Username:       username,
		Password:       req.Password,
		UserExpiration: req.UserExpiration,
		MacAddresses:   req.MacAddresses,
		AccessControl:  req.AccessControl,
	}

	if req.DenyAccess != nil {
		user.SetDenyAccess(*req.DenyAccess)
	}

	// Log the update attempt
	logger.Log.WithField("username", username).
		WithField("hasPassword", req.Password != "").
		WithField("macAddressCount", len(req.MacAddresses)).
		Info("Updating user")

	// Update user
	if err := h.userUsecase.UpdateUser(c.Request.Context(), user); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to update user", err))
		}
		return
	}

	// Change password if provided and user is local
	if req.Password != "" {
		if err := h.userUsecase.ChangePassword(c.Request.Context(), username, req.Password); err != nil {
			logger.Log.WithError(err).Error("Failed to change user password during update")
			// Don't fail the entire update, just log the error
		}
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after user update")
	}

	logger.Log.WithField("username", username).Info("User updated successfully")
	respondWithMessage(c, nethttp.StatusOK, "User updated successfully")
}

// DeleteUser godoc
// @Summary Delete user
// @Description Delete a user and associated resources
// @Tags Users
// @Security BearerAuth
// @Param username path string true "Username"
// @Success 200 {object} dto.MessageResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /api/users/{username} [delete]
func (h *UserHandler) DeleteUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		respondWithError(c, errors.BadRequest("Username is required", nil))
		return
	}

	logger.Log.WithField("username", username).Info("Deleting user")

	if err := h.userUsecase.DeleteUser(c.Request.Context(), username); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to delete user", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after user deletion")
	}

	logger.Log.WithField("username", username).Info("User deleted successfully")
	respondWithMessage(c, nethttp.StatusOK, "User deleted successfully")
}

// UserAction godoc
// @Summary Perform user action
// @Description Enable, disable, reset OTP, or change password for a user
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param username path string true "Username"
// @Param action path string true "Action (enable/disable/reset-otp/change-password)" Enums(enable, disable, reset-otp, change-password)
// @Param request body dto.ChangePasswordRequest false "Password change data (only for change-password action)"
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /api/users/{username}/{action} [put]
func (h *UserHandler) UserAction(c *gin.Context) {
	username := c.Param("username")
	action := c.Param("action")

	if username == "" {
		respondWithError(c, errors.BadRequest("Username is required", nil))
		return
	}

	if action == "" {
		respondWithError(c, errors.BadRequest("Action is required", nil))
		return
	}

	logger.Log.WithField("username", username).
		WithField("action", action).
		Info("Performing user action")

	var err error
	var message string

	switch action {
	case "enable":
		err = h.userUsecase.EnableUser(c.Request.Context(), username)
		message = "User enabled successfully"
	case "disable":
		err = h.userUsecase.DisableUser(c.Request.Context(), username)
		message = "User disabled successfully"
	case "reset-otp":
		err = h.userUsecase.RegenerateTOTP(c.Request.Context(), username)
		message = "User OTP reset successfully"
	case "change-password":
		var req dto.ChangePasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			respondWithError(c, errors.BadRequest("Invalid request format", err))
			return
		}

		if err := validator.Validate(&req); err != nil {
			respondWithValidationError(c, err)
			return
		}

		err = h.userUsecase.ChangePassword(c.Request.Context(), username, req.Password)
		message = "Password changed successfully"
	default:
		respondWithError(c, errors.BadRequest("Invalid action", nil))
		return
	}

	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Action failed", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after user action")
	}

	logger.Log.WithField("username", username).
		WithField("action", action).
		Info("User action completed successfully")

	respondWithMessage(c, nethttp.StatusOK, message)
}

// ListUsers godoc
// @Summary List users
// @Description Get list of users with optional filtering
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param username query string false "Filter by username"
// @Param email query string false "Filter by email"
// @Param authMethod query string false "Filter by auth method (local/ldap)"
// @Param role query string false "Filter by role (Admin/User)"
// @Param groupName query string false "Filter by group name"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} dto.UserListResponse
// @Router /api/users [get]
func (h *UserHandler) ListUsers(c *gin.Context) {
	var filter dto.UserFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		respondWithError(c, errors.BadRequest("Invalid query parameters", err))
		return
	}

	// Validate filter parameters
	if err := validator.Validate(&filter); err != nil {
		respondWithValidationError(c, err)
		return
	}

	logger.Log.WithField("filter", filter).Debug("Listing users")

	// Convert DTO filter to entity filter
	entityFilter := &entities.UserFilter{
		Username:   filter.Username,
		Email:      filter.Email,
		AuthMethod: filter.AuthMethod,
		Role:       filter.Role,
		GroupName:  filter.GroupName,
		Limit:      filter.Limit,
		Offset:     (filter.Page - 1) * filter.Limit,
	}

	users, err := h.userUsecase.ListUsers(c.Request.Context(), entityFilter)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to list users", err))
		}
		return
	}

	// Convert entities to DTOs
	userResponses := make([]dto.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = dto.UserResponse{
			Username:       user.Username,
			Email:          user.Email,
			AuthMethod:     user.AuthMethod,
			UserExpiration: user.UserExpiration,
			MacAddresses:   user.MacAddresses,
			MFA:            user.MFA == "true",
			Role:           user.Role,
			DenyAccess:     user.DenyAccess == "true",
			AccessControl:  user.AccessControl,
			GroupName:      user.GroupName,
		}
	}

	response := dto.UserListResponse{
		Users: userResponses,
		Total: len(userResponses),
		Page:  filter.Page,
		Limit: filter.Limit,
	}

	logger.Log.WithField("totalUsers", len(userResponses)).
		WithField("page", filter.Page).
		Info("Users listed successfully")

	respondWithSuccess(c, nethttp.StatusOK, response)
}

// GetUserExpirations godoc
// @Summary Get expiring users
// @Description Get list of users expiring in specified days
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param days query int false "Days ahead to check for expiration" default(0)
// @Success 200 {object} dto.UserExpirationResponse
// @Router /api/users/expirations [get]
func (h *UserHandler) GetUserExpirations(c *gin.Context) {
	daysStr := c.DefaultQuery("days", "0")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 0 {
		respondWithError(c, errors.BadRequest("Invalid days parameter", err))
		return
	}

	logger.Log.WithField("days", days).Info("Getting expiring users")

	emails, err := h.userUsecase.GetExpiringUsers(c.Request.Context(), days)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to get expiring users", err))
		}
		return
	}

	response := dto.UserExpirationResponse{
		Emails: emails,
		Count:  len(emails),
		Days:   days,
	}

	logger.Log.WithField("count", len(emails)).
		WithField("days", days).
		Info("Expiring users retrieved successfully")

	respondWithSuccess(c, nethttp.StatusOK, response)
}

// Response helper functions are now in response_helpers.go
