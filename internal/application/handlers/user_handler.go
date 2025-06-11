package handlers

import (
	"fmt"
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/usecases"
	"govpn/internal/infrastructure/xmlrpc"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	nethttp "net/http"
	"strconv"
	"strings"

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

	// CRITICAL FIX: Validate auth method specific requirements
	if err := h.validateAuthSpecificRequirements(&req); err != nil {
		logger.Log.WithError(err).Error("Auth-specific validation failed")
		respondWithError(c, errors.BadRequest(err.Error(), err))
		return
	}

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
	}

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

	// CRITICAL FIX: Get existing user first to check auth method
	existingUser, err := h.userUsecase.GetUser(c.Request.Context(), username)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to get user", err))
		}
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

	// CRITICAL FIX: Validate password update based on auth method
	if req.Password != "" {
		if existingUser.AuthMethod == "ldap" {
			logger.Log.WithField("username", username).
				WithField("authMethod", existingUser.AuthMethod).
				Error("Attempted to change password for LDAP user")
			respondWithError(c, errors.BadRequest("Password cannot be changed for LDAP users. LDAP users must change password through LDAP system.", nil))
			return
		}

		if existingUser.AuthMethod == "local" && len(req.Password) < 8 {
			respondWithError(c, errors.BadRequest("Password must be at least 8 characters", nil))
			return
		}
	}

	// Convert DTO to entity (password handled separately above)
	user := &entities.User{
		Username:       username,
		UserExpiration: req.UserExpiration,
		MacAddresses:   req.MacAddresses,
		AccessControl:  req.AccessControl,
	}

	if req.DenyAccess != nil {
		user.SetDenyAccess(*req.DenyAccess)
	}

	logger.Log.WithField("username", username).
		WithField("authMethod", existingUser.AuthMethod).
		WithField("hasPassword", req.Password != "").
		WithField("willChangePassword", req.Password != "" && existingUser.AuthMethod == "local").
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

	// CRITICAL FIX: Only change password for local users
	if req.Password != "" && existingUser.AuthMethod == "local" {
		if err := h.userUsecase.ChangePassword(c.Request.Context(), username, req.Password); err != nil {
			logger.Log.WithError(err).Error("Failed to change user password during update")
			respondWithError(c, errors.InternalServerError("Failed to update password", err))
			return
		}
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after user update")
	}

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

	respondWithMessage(c, nethttp.StatusOK, "User deleted successfully")
}

// UserAction godoc
// @Summary Perform user action
// @Description Perform actions like enable, disable, reset-otp, change-password
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param username path string true "Username"
// @Param action path string true "Action" Enums(enable, disable, reset-otp, change-password)
// @Param request body dto.ChangePasswordRequest false "Required only for change-password action"
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/users/{username}/{action} [put]
func (h *UserHandler) UserAction(c *gin.Context) {
	username := c.Param("username")
	action := c.Param("action")

	if username == "" {
		respondWithError(c, errors.BadRequest("Username is required", nil))
		return
	}

	// CRITICAL FIX: Get existing user to check auth method
	existingUser, err := h.userUsecase.GetUser(c.Request.Context(), username)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to get user", err))
		}
		return
	}

	logger.Log.WithField("username", username).
		WithField("action", action).
		WithField("authMethod", existingUser.AuthMethod).
		Info("Processing user action")

	switch action {
	case "enable":
		if err := h.userUsecase.EnableUser(c.Request.Context(), username); err != nil {
			if appErr, ok := err.(*errors.AppError); ok {
				respondWithError(c, appErr)
			} else {
				respondWithError(c, errors.InternalServerError("Failed to enable user", err))
			}
			return
		}
		respondWithMessage(c, nethttp.StatusOK, "User enabled successfully")

	case "disable":
		if err := h.userUsecase.DisableUser(c.Request.Context(), username); err != nil {
			if appErr, ok := err.(*errors.AppError); ok {
				respondWithError(c, appErr)
			} else {
				respondWithError(c, errors.InternalServerError("Failed to disable user", err))
			}
			return
		}
		respondWithMessage(c, nethttp.StatusOK, "User disabled successfully")

	case "reset-otp":
		if err := h.userUsecase.RegenerateTOTP(c.Request.Context(), username); err != nil {
			if appErr, ok := err.(*errors.AppError); ok {
				respondWithError(c, appErr)
			} else {
				respondWithError(c, errors.InternalServerError("Failed to reset OTP", err))
			}
			return
		}
		respondWithMessage(c, nethttp.StatusOK, "OTP reset successfully")

	case "change-password":
		// CRITICAL FIX: Check auth method before allowing password change
		if existingUser.AuthMethod == "ldap" {
			logger.Log.WithField("username", username).
				WithField("authMethod", existingUser.AuthMethod).
				Error("Attempted password change for LDAP user via action")
			respondWithError(c, errors.BadRequest("Password cannot be changed for LDAP users. Use LDAP system to change password.", nil))
			return
		}

		var req dto.ChangePasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.Log.WithError(err).Error("Failed to bind change password request")
			respondWithError(c, errors.BadRequest("Invalid request format", err))
			return
		}

		if err := validator.Validate(&req); err != nil {
			logger.Log.WithError(err).Error("Change password validation failed")
			respondWithValidationError(c, err)
			return
		}

		if len(req.Password) < 8 {
			respondWithError(c, errors.BadRequest("Password must be at least 8 characters", nil))
			return
		}

		if err := h.userUsecase.ChangePassword(c.Request.Context(), username, req.Password); err != nil {
			if appErr, ok := err.(*errors.AppError); ok {
				respondWithError(c, appErr)
			} else {
				respondWithError(c, errors.InternalServerError("Failed to change password", err))
			}
			return
		}

		respondWithMessage(c, nethttp.StatusOK, "Password changed successfully")

	default:
		respondWithError(c, errors.BadRequest("Invalid action. Allowed actions: enable, disable, reset-otp, change-password", nil))
		return
	}

	// Restart OpenVPN service for relevant actions
	if action == "enable" || action == "disable" || action == "change-password" {
		if err := h.xmlrpcClient.RunStart(); err != nil {
			logger.Log.WithError(err).Error("Failed to restart OpenVPN service after user action")
		}
	}
}

// ListUsers godoc
// @Summary List users
// @Description Get a paginated list of users with filtering
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param username query string false "Filter by username"
// @Param email query string false "Filter by email"
// @Param authMethod query string false "Filter by auth method" Enums(ldap, local)
// @Param role query string false "Filter by role" Enums(Admin, User)
// @Param groupName query string false "Filter by group name"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} dto.UserListResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/users [get]
func (h *UserHandler) ListUsers(c *gin.Context) {
	var filter dto.UserFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		logger.Log.WithError(err).Error("Failed to bind user filter")
		respondWithError(c, errors.BadRequest("Invalid filter parameters", err))
		return
	}

	if err := validator.Validate(&filter); err != nil {
		logger.Log.WithError(err).Error("User filter validation failed")
		respondWithValidationError(c, err)
		return
	}

	entityFilter := &entities.UserFilter{
		Username:   filter.Username,
		Email:      filter.Email,
		AuthMethod: filter.AuthMethod,
		Role:       filter.Role,
		GroupName:  filter.GroupName,
		Page:       filter.Page,
		Limit:      filter.Limit,
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

	var userResponses []dto.UserResponse
	for _, user := range users {
		userResponses = append(userResponses, dto.UserResponse{
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
		})
	}

	response := dto.UserListResponse{
		Users: userResponses,
		Total: len(userResponses),
		Page:  filter.Page,
		Limit: filter.Limit,
	}

	respondWithSuccess(c, nethttp.StatusOK, response)
}

// GetUserExpirations godoc
// @Summary Get expiring users
// @Description Get users that will expire in the specified number of days
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param days query int false "Number of days" default(7)
// @Success 200 {object} dto.UserExpirationResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/users/expirations [get]
func (h *UserHandler) GetUserExpirations(c *gin.Context) {
	daysStr := c.DefaultQuery("days", "7")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 0 {
		respondWithError(c, errors.BadRequest("Invalid days parameter", err))
		return
	}

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

	respondWithSuccess(c, nethttp.StatusOK, response)
}

// CRITICAL FIX: Validate auth method specific requirements
func (h *UserHandler) validateAuthSpecificRequirements(req *dto.CreateUserRequest) error {
	authMethod := strings.ToLower(strings.TrimSpace(req.AuthMethod))

	switch authMethod {
	case "local":
		if strings.TrimSpace(req.Password) == "" {
			return fmt.Errorf("password is required for local authentication")
		}
		if len(req.Password) < 8 {
			return fmt.Errorf("password must be at least 8 characters for local authentication")
		}
	case "ldap":
		if strings.TrimSpace(req.Password) != "" {
			logger.Log.WithField("username", req.Username).
				Warn("Password provided for LDAP user - clearing password")
			req.Password = "" // Clear password for LDAP users
		}
	default:
		return fmt.Errorf("invalid authentication method: %s. Must be 'local' or 'ldap'", req.AuthMethod)
	}

	return nil
}
