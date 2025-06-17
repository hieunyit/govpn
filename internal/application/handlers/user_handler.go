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
	"math"
	nethttp "net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

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
		GroupName:      req.GroupName,
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

	// Convert entity to DTO with enhanced fields
	response := h.convertUserToResponse(user)

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
// @Summary List users with enhanced filtering
// @Description Get a paginated list of users with comprehensive filtering options
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param username query string false "Filter by username (supports partial match)"
// @Param email query string false "Filter by email (supports partial match)"
// @Param authMethod query string false "Filter by auth method" Enums(ldap, local)
// @Param role query string false "Filter by role" Enums(Admin, User)
// @Param groupName query string false "Filter by group name"
// @Param isEnabled query boolean false "Filter by enabled status"
// @Param denyAccess query boolean false "Filter by access denial status"
// @Param mfaEnabled query boolean false "Filter by MFA status"
// @Param userExpirationAfter query string false "Users expiring after date (YYYY-MM-DD)"
// @Param userExpirationBefore query string false "Users expiring before date (YYYY-MM-DD)"
// @Param includeExpired query boolean false "Include expired users" default(true)
// @Param expiringInDays query int false "Users expiring within X days"
// @Param hasAccessControl query boolean false "Filter by access control presence"
// @Param macAddress query string false "Filter by MAC address"
// @Param searchText query string false "Search across username, email, group"
// @Param sortBy query string false "Sort field" Enums(username, email, authMethod, role, groupName, userExpiration) default(username)
// @Param sortOrder query string false "Sort order" Enums(asc, desc) default(asc)
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page (max 100)" default(20)
// @Param exactMatch query boolean false "Use exact matching instead of partial" default(false)
// @Param caseSensitive query boolean false "Case sensitive search" default(false)
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

	// Set defaults
	filter.SetDefaults()

	// Enhanced validation
	if err := validator.Validate(&filter); err != nil {
		logger.Log.WithError(err).Error("User filter validation failed")
		respondWithValidationError(c, err)
		return
	}

	// Additional validation for new filters
	if err := h.validateUserFilter(&filter); err != nil {
		respondWithError(c, errors.BadRequest("Invalid filter parameters", err))
		return
	}

	// Convert DTO filter to entity filter
	entityFilter := h.convertToEntityFilter(&filter)

	// Get users with total count
	users, totalCount, err := h.userUsecase.ListUsersWithTotal(c.Request.Context(), entityFilter)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to list users", err))
		}
		return
	}

	// Convert to response DTOs
	userResponses := make([]dto.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = h.convertUserToResponse(user)
	}

	// Calculate total pages
	totalPages := int(math.Ceil(float64(totalCount) / float64(filter.Limit)))

	// Build enhanced response with metadata
	response := dto.UserListResponse{
		Users:      userResponses,
		Total:      totalCount,
		Page:       filter.Page,
		Limit:      filter.Limit,
		TotalPages: totalPages,
		Filters:    filter,
		Metadata:   h.buildFilterMetadata(&filter),
	}

	respondWithSuccess(c, nethttp.StatusOK, response)
}

// GetUserExpirations godoc
// @Summary Get expiring users with full information
// @Description Get users that will expire in the specified number of days with complete user details
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param days query int false "Number of days to check for expiration" default(7)
// @Param includeExpired query bool false "Include already expired users" default(false)
// @Success 200 {object} dto.UserExpirationsResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/users/expirations [get]
func (h *UserHandler) GetUserExpirations(c *gin.Context) {
	daysStr := c.DefaultQuery("days", "7")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 0 {
		respondWithError(c, errors.BadRequest("Invalid days parameter", err))
		return
	}

	// ✅ NEW: Optional parameter to include expired users
	includeExpiredStr := c.DefaultQuery("includeExpired", "false")
	includeExpired, _ := strconv.ParseBool(includeExpiredStr)

	logger.Log.WithField("days", days).
		WithField("includeExpired", includeExpired).
		Info("Getting user expirations")

	// ✅ FIX: Call new method that returns full user info
	response, err := h.userUsecase.GetUserExpirations(c.Request.Context(), days)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			respondWithError(c, appErr)
		} else {
			respondWithError(c, errors.InternalServerError("Failed to get user expirations", err))
		}
		return
	}

	// ✅ NEW: Filter expired users based on includeExpired parameter
	if !includeExpired {
		filteredUsers := make([]dto.UserExpirationInfo, 0)
		for _, user := range response.Users {
			if user.ExpirationStatus != "expired" {
				filteredUsers = append(filteredUsers, user)
			}
		}
		response.Users = filteredUsers
		response.Count = len(filteredUsers)
	}

	respondWithSuccess(c, nethttp.StatusOK, response)
}

// NEW: Helper method to validate enhanced user filters
func (h *UserHandler) validateUserFilter(filter *dto.UserFilter) error {
	// Date validation
	if filter.UserExpirationAfter != nil && filter.UserExpirationBefore != nil {
		if filter.UserExpirationAfter.After(*filter.UserExpirationBefore) {
			return errors.BadRequest("userExpirationAfter cannot be after userExpirationBefore", nil)
		}
	}

	// Expiring days validation
	if filter.ExpiringInDays != nil && *filter.ExpiringInDays < 0 {
		return errors.BadRequest("expiringInDays must be non-negative", nil)
	}

	// Search text length validation
	if filter.SearchText != "" && len(filter.SearchText) < 2 {
		return errors.BadRequest("searchText must be at least 2 characters", nil)
	}

	// MAC address format validation (basic)
	if filter.MacAddress != "" {
		macPattern := `^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`
		if matched, _ := regexp.MatchString(macPattern, filter.MacAddress); !matched {
			return errors.BadRequest("Invalid MAC address format", nil)
		}
	}

	return nil
}

// NEW: Helper method to convert DTO filter to entity filter
func (h *UserHandler) convertToEntityFilter(dtoFilter *dto.UserFilter) *entities.UserFilter {
	return &entities.UserFilter{
		// Basic filters
		Username:   dtoFilter.Username,
		Email:      dtoFilter.Email,
		AuthMethod: dtoFilter.AuthMethod,
		Role:       dtoFilter.Role,
		GroupName:  dtoFilter.GroupName,

		// Status filters
		IsEnabled:  dtoFilter.IsEnabled,
		DenyAccess: dtoFilter.DenyAccess,
		MFAEnabled: dtoFilter.MFAEnabled,

		// Expiration filters
		UserExpirationAfter:  dtoFilter.UserExpirationAfter,
		UserExpirationBefore: dtoFilter.UserExpirationBefore,
		IncludeExpired:       dtoFilter.IncludeExpired,
		ExpiringInDays:       dtoFilter.ExpiringInDays,

		// Advanced filters
		HasAccessControl: dtoFilter.HasAccessControl,
		MacAddress:       dtoFilter.MacAddress,
		SearchText:       dtoFilter.SearchText,

		// Sorting & pagination
		SortBy:    dtoFilter.SortBy,
		SortOrder: dtoFilter.SortOrder,
		Page:      dtoFilter.Page,
		Limit:     dtoFilter.Limit,
		Offset:    (dtoFilter.Page - 1) * dtoFilter.Limit,

		// Search options
		ExactMatch:    dtoFilter.ExactMatch,
		CaseSensitive: dtoFilter.CaseSensitive,
	}
}

// NEW: Helper method to convert User entity to UserResponse DTO
func (h *UserHandler) convertUserToResponse(user *entities.User) dto.UserResponse {
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
		IsEnabled:      user.DenyAccess != "true",
	}

	// Calculate expiration status
	if user.UserExpiration != "" {
		// Try parsing with multiple formats
		formats := []string{"02/01/2006", "2006-01-02", "01/02/2006", "2006/01/02"}
		for _, format := range formats {
			if expDate, err := time.Parse(format, user.UserExpiration); err == nil {
				response.IsExpired = time.Now().After(expDate)
				response.DaysUntilExp = int(time.Until(expDate).Hours() / 24)
				break
			}
		}
	}

	return response
}

// NEW: Helper method to build filter metadata
func (h *UserHandler) buildFilterMetadata(filter *dto.UserFilter) dto.FilterMetadata {
	appliedFilters := []string{}

	if filter.Username != "" {
		appliedFilters = append(appliedFilters, "username")
	}
	if filter.Email != "" {
		appliedFilters = append(appliedFilters, "email")
	}
	if filter.AuthMethod != "" {
		appliedFilters = append(appliedFilters, "authMethod")
	}
	if filter.Role != "" {
		appliedFilters = append(appliedFilters, "role")
	}
	if filter.GroupName != "" {
		appliedFilters = append(appliedFilters, "groupName")
	}
	if filter.IsEnabled != nil {
		appliedFilters = append(appliedFilters, "isEnabled")
	}
	if filter.DenyAccess != nil {
		appliedFilters = append(appliedFilters, "denyAccess")
	}
	if filter.MFAEnabled != nil {
		appliedFilters = append(appliedFilters, "mfaEnabled")
	}
	if filter.UserExpirationAfter != nil {
		appliedFilters = append(appliedFilters, "userExpirationAfter")
	}
	if filter.UserExpirationBefore != nil {
		appliedFilters = append(appliedFilters, "userExpirationBefore")
	}
	if filter.IncludeExpired != nil {
		appliedFilters = append(appliedFilters, "includeExpired")
	}
	if filter.ExpiringInDays != nil {
		appliedFilters = append(appliedFilters, "expiringInDays")
	}
	if filter.HasAccessControl != nil {
		appliedFilters = append(appliedFilters, "hasAccessControl")
	}
	if filter.MacAddress != "" {
		appliedFilters = append(appliedFilters, "macAddress")
	}
	if filter.SearchText != "" {
		appliedFilters = append(appliedFilters, "searchText")
	}

	return dto.FilterMetadata{
		AppliedFilters: appliedFilters,
		SortedBy:       filter.SortBy,
		SortOrder:      filter.SortOrder,
		FilterCount:    len(appliedFilters),
	}
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
