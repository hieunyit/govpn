package handlers

import (
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/usecases"
	"govpn/internal/infrastructure/xmlrpc"
	httpPkg "govpn/internal/presentation/http"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// =================== ENHANCED USER HANDLER ===================

// UserHandler handles user-related HTTP requests with comprehensive response system and logging
type UserHandler struct {
	userUsecase  usecases.UserUsecaseInterface
	xmlrpcClient *xmlrpc.Client
	logger       logger.Logger
}

// NewUserHandler creates a new user handler with enhanced response and logging capabilities
func NewUserHandler(
	userUsecase usecases.UserUsecaseInterface,
	xmlrpcClient *xmlrpc.Client,
) *UserHandler {
	return &UserHandler{
		userUsecase:  userUsecase,
		xmlrpcClient: xmlrpcClient,
		logger:       logger.Log,
	}
}

// =================== USER CRUD OPERATIONS WITH ENHANCED RESPONSES ===================

// CreateUser godoc
// @Summary Create a new VPN user
// @Description Create a new VPN user with comprehensive validation, error handling, and structured response
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param user body dto.CreateUserRequest true "User creation data with all required fields"
// @Success 201 {object} httpPkg.SuccessResponse{data=dto.UserResponse} "User created successfully with HATEOAS links"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid input data with suggestions"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - authentication required"
// @Failure 403 {object} httpPkg.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 409 {object} httpPkg.ErrorResponse "Conflict - user already exists with conflict details"
// @Failure 422 {object} httpPkg.ValidationErrorResponse "Validation failed with field-specific errors"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /api/users [post]
func (h *UserHandler) CreateUser(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	// Parse and validate request with detailed error handling
	var req dto.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", httpPkg.getOrGenerateRequestID(c)).
			Error("Failed to bind create user request")
		httpPkg.RespondWithError(c, errors.BadRequest("Invalid request format", map[string]interface{}{
			"binding_error":   err.Error(),
			"expected_format": "JSON with username, email, password fields",
		}))
		return
	}

	// Comprehensive validation with field-specific errors
	if err := validator.Validate(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"username":   req.Username,
		}).Error("Create user request validation failed")
		httpPkg.RespondWithValidationError(c, err)
		return
	}

	// Convert DTO to entity with business logic validation
	user, err := h.convertCreateRequestToEntity(&req)
	if err != nil {
		h.logger.WithError(err).WithField("request_id", httpPkg.getOrGenerateRequestID(c)).
			Error("Failed to convert create request to entity")
		httpPkg.RespondWithError(c, err)
		return
	}

	// Log user creation attempt with context
	h.logger.WithFields(map[string]interface{}{
		"username":   req.Username,
		"email":      req.Email,
		"admin":      req.Admin,
		"request_id": httpPkg.getOrGenerateRequestID(c),
		"ip":         c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
	}).Info("Attempting to create user")

	// Check if user already exists with detailed conflict information
	existingUser, err := h.userUsecase.GetUser(c.Request.Context(), req.Username)
	if err == nil && existingUser != nil {
		h.logger.WithFields(map[string]interface{}{
			"username":         req.Username,
			"existing_user_id": existingUser.ID,
			"request_id":       httpPkg.getOrGenerateRequestID(c),
		}).Warn("User already exists")

		httpPkg.RespondWithError(c, errors.Conflict("User with this username already exists", map[string]interface{}{
			"existing_user": map[string]interface{}{
				"username":   existingUser.Username,
				"email":      existingUser.Email,
				"created_at": existingUser.CreatedAt.Format(time.RFC3339),
				"is_active":  existingUser.IsActive,
			},
			"suggestions": []string{
				"Choose a different username",
				"Update existing user instead",
				"Check if user was previously created",
			},
		}))
		return
	}

	// Create user with comprehensive error handling
	createdUser, err := h.userUsecase.CreateUser(c.Request.Context(), user)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   req.Username,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to create user")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to create user", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "user_creation",
			}))
		}
		return
	}

	// Convert entity to response DTO with all fields
	userResponse := h.convertEntityToResponse(createdUser)

	// Log successful creation with comprehensive details
	h.logger.WithFields(map[string]interface{}{
		"username":        createdUser.Username,
		"user_id":         createdUser.ID,
		"email":           createdUser.Email,
		"admin":           createdUser.Admin,
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Info("User created successfully")

	// Send enhanced created response with HATEOAS links and metadata
	httpPkg.RespondWithSuccess(c, http.StatusCreated, userResponse, "user", createdUser.Username)
}

// GetUser godoc
// @Summary Get user by username
// @Description Retrieve detailed information about a specific user with comprehensive error handling
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param username path string true "Username to retrieve" minlength(3) maxlength(32)
// @Success 200 {object} httpPkg.SuccessResponse{data=dto.UserResponse} "User retrieved successfully with HATEOAS links"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid username format"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - authentication required"
// @Failure 403 {object} httpPkg.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 404 {object} httpPkg.ErrorResponse "User not found with search suggestions"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /api/users/{username} [get]
func (h *UserHandler) GetUser(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	username := c.Param("username")

	// Validate username parameter with detailed error
	if username == "" {
		httpPkg.RespondWithError(c, errors.BadRequest("Username is required", map[string]interface{}{
			"parameter": "username",
			"location":  "path",
			"example":   "/api/users/testuser",
		}))
		return
	}

	// Basic username format validation
	if len(username) < 3 || len(username) > 32 {
		httpPkg.RespondWithError(c, errors.BadRequest("Invalid username format", map[string]interface{}{
			"username":        username,
			"min_length":      3,
			"max_length":      32,
			"provided_length": len(username),
		}))
		return
	}

	// Log retrieval attempt with context
	h.logger.WithFields(map[string]interface{}{
		"username":   username,
		"request_id": httpPkg.getOrGenerateRequestID(c),
		"ip":         c.ClientIP(),
	}).Debug("Attempting to retrieve user")

	// Get user from use case with comprehensive error handling
	user, err := h.userUsecase.GetUser(c.Request.Context(), username)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   username,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to retrieve user")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to retrieve user", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "user_retrieval",
			}))
		}
		return
	}

	// Handle user not found with helpful suggestions
	if user == nil {
		h.logger.WithFields(map[string]interface{}{
			"username":   username,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Warn("User not found")

		httpPkg.RespondWithError(c, errors.NotFound("User not found", map[string]interface{}{
			"username": username,
			"suggestions": []string{
				"Verify username spelling",
				"Check if user was deleted",
				"List all users to find correct username",
			},
			"help_links": map[string]string{
				"list_users":   "/api/users",
				"search_users": "/api/search/users",
			},
		}))
		return
	}

	// Convert entity to response DTO
	userResponse := h.convertEntityToResponse(user)

	// Log successful retrieval
	h.logger.WithFields(map[string]interface{}{
		"username":        user.Username,
		"user_id":         user.ID,
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Debug("User retrieved successfully")

	// Send enhanced success response with metadata and HATEOAS links
	httpPkg.RespondWithSuccess(c, http.StatusOK, userResponse, "user", username)
}

// ListUsers godoc
// @Summary List all users with pagination and filtering
// @Description Retrieve a paginated list of all VPN users with comprehensive filtering, sorting, and search options
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param page query int false "Page number (1-based)" minimum(1) default(1)
// @Param per_page query int false "Items per page" minimum(1) maximum(100) default(20)
// @Param sort query string false "Sort field" Enums(username, email, created_at, last_login) default(username)
// @Param order query string false "Sort order" Enums(asc, desc) default(asc)
// @Param filter query string false "Filter by status" Enums(active, inactive, expired, expiring_soon)
// @Param search query string false "Search by username or email" minlength(2)
// @Success 200 {object} httpPkg.PaginatedResponse{data=[]dto.UserResponse} "Users retrieved successfully with pagination metadata"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid query parameters with valid options"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - authentication required"
// @Failure 403 {object} httpPkg.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /api/users [get]
func (h *UserHandler) ListUsers(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	// Parse and validate query parameters with comprehensive error handling
	params, err := h.parseAndValidateListUsersParams(c)
	if err != nil {
		httpPkg.RespondWithError(c, err)
		return
	}

	// Log list request with comprehensive parameters
	h.logger.WithFields(map[string]interface{}{
		"page":       params.Page,
		"per_page":   params.PerPage,
		"sort":       params.Sort,
		"order":      params.Order,
		"filter":     params.Filter,
		"search":     params.Search,
		"request_id": httpPkg.getOrGenerateRequestID(c),
		"ip":         c.ClientIP(),
	}).Info("Listing users with parameters")

	// Get users from use case with comprehensive error handling
	users, total, err := h.userUsecase.ListUsers(c.Request.Context(), &entities.ListUsersParams{
		Page:    params.Page,
		PerPage: params.PerPage,
		Sort:    params.Sort,
		Order:   params.Order,
		Filter:  params.Filter,
		Search:  params.Search,
	})

	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"page":       params.Page,
			"per_page":   params.PerPage,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to list users")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to retrieve users", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "user_listing",
			}))
		}
		return
	}

	// Convert entities to response DTOs
	userResponses := make([]dto.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = h.convertEntityToResponse(user)
	}

	// Log successful listing with comprehensive metrics
	h.logger.WithFields(map[string]interface{}{
		"total_users":     total,
		"returned_users":  len(userResponses),
		"page":            params.Page,
		"per_page":        params.PerPage,
		"filter_applied":  params.Filter != "",
		"search_applied":  params.Search != "",
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Info("Users listed successfully")

	// Send enhanced paginated response with comprehensive metadata
	httpPkg.RespondWithPaginated(c, userResponses, params.Page, params.PerPage, total)
}

// UpdateUser godoc
// @Summary Update an existing user
// @Description Update user information with comprehensive validation and conflict detection
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param username path string true "Username to update" minlength(3) maxlength(32)
// @Param user body dto.UpdateUserRequest true "User update data with optional fields"
// @Success 200 {object} httpPkg.SuccessResponse{data=dto.UserResponse} "User updated successfully with change log"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid input data with field details"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - authentication required"
// @Failure 403 {object} httpPkg.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 404 {object} httpPkg.ErrorResponse "User not found with search suggestions"
// @Failure 409 {object} httpPkg.ErrorResponse "Conflict - email already exists with conflict details"
// @Failure 422 {object} httpPkg.ValidationErrorResponse "Validation failed with field-specific errors"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /api/users/{username} [put]
func (h *UserHandler) UpdateUser(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	username := c.Param("username")

	// Validate username parameter
	if username == "" {
		httpPkg.RespondWithError(c, errors.BadRequest("Username is required", map[string]interface{}{
			"parameter": "username",
			"location":  "path",
			"example":   "/api/users/testuser",
		}))
		return
	}

	// Parse and validate request with detailed error handling
	var req dto.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   username,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to bind update user request")

		httpPkg.RespondWithError(c, errors.BadRequest("Invalid request format", map[string]interface{}{
			"binding_error":   err.Error(),
			"expected_format": "JSON with optional email, password, admin, is_active fields",
		}))
		return
	}

	// Validate request data with field-specific errors
	if err := validator.Validate(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   username,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Update user request validation failed")
		httpPkg.RespondWithValidationError(c, err)
		return
	}

	// Log update attempt with context
	h.logger.WithFields(map[string]interface{}{
		"username":     username,
		"request_id":   httpPkg.getOrGenerateRequestID(c),
		"has_email":    req.Email != "",
		"has_password": req.Password != "",
		"ip":           c.ClientIP(),
	}).Info("Attempting to update user")

	// Check if user exists with detailed error
	existingUser, err := h.userUsecase.GetUser(c.Request.Context(), username)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   username,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to retrieve user for update")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to retrieve user for update", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "pre_update_retrieval",
			}))
		}
		return
	}

	if existingUser == nil {
		httpPkg.RespondWithError(c, errors.NotFound("User not found", map[string]interface{}{
			"username": username,
			"suggestions": []string{
				"Verify username spelling",
				"Check if user was deleted",
				"Create user instead of updating",
			},
		}))
		return
	}

	// Convert DTO to entity with validation and change tracking
	updatedUser, changes, err := h.convertUpdateRequestToEntity(&req, existingUser)
	if err != nil {
		httpPkg.RespondWithError(c, err)
		return
	}

	// Update user with comprehensive error handling
	result, err := h.userUsecase.UpdateUser(c.Request.Context(), updatedUser)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   username,
			"request_id": httpPkg.getOrGenerateRequestID(c),
			"changes":    changes,
		}).Error("Failed to update user")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to update user", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "user_update",
			}))
		}
		return
	}

	// Convert entity to response DTO
	userResponse := h.convertEntityToResponse(result)

	// Log successful update with comprehensive details
	h.logger.WithFields(map[string]interface{}{
		"username":        result.Username,
		"user_id":         result.ID,
		"changes_made":    changes,
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Info("User updated successfully")

	// Send enhanced success response with change metadata
	httpPkg.RespondWithSuccess(c, http.StatusOK, map[string]interface{}{
		"user":       userResponse,
		"changes":    changes,
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}, "user", username)
}

// DeleteUser godoc
// @Summary Delete a user
// @Description Permanently delete a VPN user and revoke access with safety checks
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param username path string true "Username to delete" minlength(3) maxlength(32)
// @Success 200 {object} httpPkg.SuccessResponse "User deleted successfully with confirmation"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid username format"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - authentication required"
// @Failure 403 {object} httpPkg.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 404 {object} httpPkg.ErrorResponse "User not found with search suggestions"
// @Failure 409 {object} httpPkg.ErrorResponse "Conflict - user has active connections with safety info"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /api/users/{username} [delete]
func (h *UserHandler) DeleteUser(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	username := c.Param("username")

	// Validate username parameter
	if username == "" {
		httpPkg.RespondWithError(c, errors.BadRequest("Username is required", map[string]interface{}{
			"parameter": "username",
			"location":  "path",
			"example":   "/api/users/testuser",
		}))
		return
	}

	// Log deletion attempt with context
	h.logger.WithFields(map[string]interface{}{
		"username":   username,
		"request_id": httpPkg.getOrGenerateRequestID(c),
		"ip":         c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
	}).Warn("Attempting to delete user")

	// Check if user exists before deletion with detailed error
	existingUser, err := h.userUsecase.GetUser(c.Request.Context(), username)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   username,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to retrieve user for deletion")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to retrieve user for deletion", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "pre_deletion_retrieval",
			}))
		}
		return
	}

	if existingUser == nil {
		httpPkg.RespondWithError(c, errors.NotFound("User not found", map[string]interface{}{
			"username": username,
			"suggestions": []string{
				"Verify username spelling",
				"Check if user was already deleted",
				"List all users to verify existence",
			},
		}))
		return
	}

	// Safety check: prevent deletion of active users
	if existingUser.IsActive {
		h.logger.WithFields(map[string]interface{}{
			"username":   username,
			"user_id":    existingUser.ID,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Warn("Attempting to delete active user")

		httpPkg.RespondWithError(c, errors.Conflict("Cannot delete active user", map[string]interface{}{
			"user_status":        "active",
			"safety_message":     "Active users may have VPN connections that could be disrupted",
			"recommended_action": "Disable user first, then delete after connections terminate",
			"disable_endpoint":   "/api/users/" + username + "/disable",
			"alternatives": []string{
				"Disable user instead of deletion",
				"Wait for user sessions to expire",
				"Force disconnect user sessions first",
			},
		}))
		return
	}

	// Delete user with comprehensive error handling
	err = h.userUsecase.DeleteUser(c.Request.Context(), username)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   username,
			"user_id":    existingUser.ID,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to delete user")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to delete user", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "user_deletion",
			}))
		}
		return
	}

	// Log successful deletion with comprehensive details
	h.logger.WithFields(map[string]interface{}{
		"username":        username,
		"user_id":         existingUser.ID,
		"user_email":      existingUser.Email,
		"was_admin":       existingUser.Admin,
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Warn("User deleted successfully")

	// Send enhanced success response with deletion confirmation
	httpPkg.RespondWithSuccess(c, http.StatusOK, map[string]interface{}{
		"deleted_user": map[string]interface{}{
			"username":   username,
			"user_id":    existingUser.ID,
			"deleted_at": time.Now().UTC().Format(time.RFC3339),
		},
		"confirmation": "User has been permanently deleted",
		"note":         "This action cannot be undone",
	}, "user", "")
}

// UserAction godoc
// @Summary Perform user actions
// @Description Perform actions on a user (enable, disable, reset_password, extend_expiry) with comprehensive validation
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param username path string true "Username to perform action on" minlength(3) maxlength(32)
// @Param action path string true "Action to perform" Enums(enable, disable, reset_password, extend_expiry)
// @Param request body dto.UserActionRequest false "Action parameters (required for some actions)"
// @Success 200 {object} httpPkg.SuccessResponse{data=dto.UserActionResponse} "Action performed successfully with result details"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid action or parameters with valid options"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - authentication required"
// @Failure 403 {object} httpPkg.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 404 {object} httpPkg.ErrorResponse "User not found with search suggestions"
// @Failure 422 {object} httpPkg.ValidationErrorResponse "Validation failed with field-specific errors"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /api/users/{username}/{action} [put]
func (h *UserHandler) UserAction(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	username := c.Param("username")
	action := c.Param("action")

	// Validate parameters with detailed errors
	if username == "" {
		httpPkg.RespondWithError(c, errors.BadRequest("Username is required", map[string]interface{}{
			"parameter": "username",
			"location":  "path",
		}))
		return
	}

	if action == "" {
		httpPkg.RespondWithError(c, errors.BadRequest("Action is required", map[string]interface{}{
			"parameter": "action",
			"location":  "path",
		}))
		return
	}

	// Validate action type with helpful suggestions
	validActions := []string{"enable", "disable", "reset_password", "extend_expiry"}
	if !h.isValidAction(action, validActions) {
		httpPkg.RespondWithError(c, errors.BadRequest("Invalid action", map[string]interface{}{
			"provided_action": action,
			"valid_actions":   validActions,
			"examples": map[string]string{
				"enable":         "/api/users/testuser/enable",
				"disable":        "/api/users/testuser/disable",
				"reset_password": "/api/users/testuser/reset_password",
				"extend_expiry":  "/api/users/testuser/extend_expiry",
			},
		}))
		return
	}

	// Parse action request if needed with detailed validation
	var req dto.UserActionRequest
	if action == "reset_password" || action == "extend_expiry" {
		if err := c.ShouldBindJSON(&req); err != nil {
			h.logger.WithError(err).WithFields(map[string]interface{}{
				"username":   username,
				"action":     action,
				"request_id": httpPkg.getOrGenerateRequestID(c),
			}).Error("Failed to bind user action request")

			httpPkg.RespondWithError(c, errors.BadRequest("Invalid request format for action", map[string]interface{}{
				"action":          action,
				"required_fields": h.getRequiredFieldsForAction(action),
				"binding_error":   err.Error(),
			}))
			return
		}

		if err := validator.Validate(&req); err != nil {
			httpPkg.RespondWithValidationError(c, err)
			return
		}
	}

	// Log action attempt with comprehensive context
	h.logger.WithFields(map[string]interface{}{
		"username":   username,
		"action":     action,
		"request_id": httpPkg.getOrGenerateRequestID(c),
		"ip":         c.ClientIP(),
		"has_params": action == "reset_password" || action == "extend_expiry",
	}).Info("Attempting user action")

	// Check if user exists with detailed error handling
	existingUser, err := h.userUsecase.GetUser(c.Request.Context(), username)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   username,
			"action":     action,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to retrieve user for action")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to retrieve user for action", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "pre_action_retrieval",
			}))
		}
		return
	}

	if existingUser == nil {
		httpPkg.RespondWithError(c, errors.NotFound("User not found", map[string]interface{}{
			"username": username,
			"action":   action,
			"suggestions": []string{
				"Verify username spelling",
				"Check if user was deleted",
				"List all users to find correct username",
			},
		}))
		return
	}

	// Perform action with comprehensive error handling and result tracking
	result, err := h.performUserAction(c, existingUser, action, &req)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"username":   username,
			"action":     action,
			"user_id":    existingUser.ID,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to perform user action")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to perform user action", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "user_action_execution",
				"action":         action,
			}))
		}
		return
	}

	// Log successful action with comprehensive details
	h.logger.WithFields(map[string]interface{}{
		"username":        username,
		"action":          action,
		"user_id":         existingUser.ID,
		"action_result":   result,
		"request_id":      httpPkg.getOrGenerateRequestID(c),
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Info("User action completed successfully")

	// Send enhanced success response with action details
	httpPkg.RespondWithSuccess(c, http.StatusOK, result, "user", username)
}

// GetUserExpirations godoc
// @Summary Get user expiration information
// @Description Retrieve expiration information for all users or specific users with filtering options
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param username query string false "Filter by specific username" minlength(3)
// @Param days_until_expiry query int false "Filter users expiring within specified days" minimum(1) maximum(365) default(30)
// @Param include_expired query bool false "Include already expired users" default(false)
// @Success 200 {object} httpPkg.SuccessResponse{data=[]dto.UserExpirationInfo} "User expirations retrieved successfully with filtering metadata"
// @Failure 400 {object} httpPkg.ErrorResponse "Bad request - invalid query parameters with valid ranges"
// @Failure 401 {object} httpPkg.ErrorResponse "Unauthorized - authentication required"
// @Failure 403 {object} httpPkg.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 500 {object} httpPkg.ErrorResponse "Internal server error with trace ID"
// @Router /api/users/expirations [get]
func (h *UserHandler) GetUserExpirations(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	// Parse and validate query parameters with detailed error handling
	params := &entities.ExpirationParams{
		Username:        c.Query("username"),
		DaysUntilExpiry: 30, // default
		IncludeExpired:  false,
	}

	// Validate and parse days_until_expiry with range checking
	if days := c.Query("days_until_expiry"); days != "" {
		if d, err := strconv.Atoi(days); err != nil {
			httpPkg.RespondWithError(c, errors.BadRequest("Invalid days_until_expiry parameter", map[string]interface{}{
				"provided_value": days,
				"expected_type":  "integer",
				"valid_range":    "1-365",
			}))
			return
		} else if d < 1 || d > 365 {
			httpPkg.RespondWithError(c, errors.BadRequest("days_until_expiry out of range", map[string]interface{}{
				"provided_value": d,
				"valid_range":    "1-365",
				"suggestion":     "Use a value between 1 and 365 days",
			}))
			return
		} else {
			params.DaysUntilExpiry = d
		}
	}

	// Parse include_expired parameter
	if includeExpired := c.Query("include_expired"); includeExpired == "true" {
		params.IncludeExpired = true
	}

	// Validate username if provided
	if params.Username != "" && (len(params.Username) < 3 || len(params.Username) > 32) {
		httpPkg.RespondWithError(c, errors.BadRequest("Invalid username format", map[string]interface{}{
			"username":   params.Username,
			"min_length": 3,
			"max_length": 32,
		}))
		return
	}

	// Log expiration request with comprehensive parameters
	h.logger.WithFields(map[string]interface{}{
		"username":          params.Username,
		"days_until_expiry": params.DaysUntilExpiry,
		"include_expired":   params.IncludeExpired,
		"request_id":        httpPkg.getOrGenerateRequestID(c),
		"ip":                c.ClientIP(),
	}).Info("Getting user expirations")

	// Get user expirations with comprehensive error handling
	expirations, err := h.userUsecase.GetUserExpirations(c.Request.Context(), params)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"params":     params,
			"request_id": httpPkg.getOrGenerateRequestID(c),
		}).Error("Failed to retrieve user expirations")

		if appErr, ok := err.(*errors.AppError); ok {
			httpPkg.RespondWithError(c, appErr)
		} else {
			httpPkg.RespondWithError(c, errors.InternalServerError("Failed to retrieve user expirations", map[string]interface{}{
				"internal_error": err.Error(),
				"context":        "user_expirations_retrieval",
			}))
		}
		return
	}

	// Convert to response DTOs with additional metadata
	expirationResponses := make([]dto.UserExpirationInfo, len(expirations))
	expiredCount := 0
	expiringCount := 0

	for i, exp := range expirations {
		expirationResponses[i] = h.convertExpirationToResponse(exp)
		if exp.IsExpired {
			expiredCount++
		} else if exp.DaysToExpiry <= 7 { // Expiring within a week
			expiringCount++
		}
	}

	// Log successful retrieval with comprehensive metrics
	h.logger.WithFields(map[string]interface{}{
		"total_expirations": len(expirationResponses),
		"expired_users":     expiredCount,
		"expiring_soon":     expiringCount,
		"filter_applied":    params.Username != "",
		"request_id":        httpPkg.getOrGenerateRequestID(c),
		"processing_time":   time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
	}).Info("User expirations retrieved successfully")

	// Send enhanced success response with comprehensive metadata
	httpPkg.RespondWithSuccess(c, http.StatusOK, map[string]interface{}{
		"expirations": expirationResponses,
		"summary": map[string]interface{}{
			"total_users":   len(expirationResponses),
			"expired_users": expiredCount,
			"expiring_soon": expiringCount,
			"filter_applied": map[string]interface{}{
				"username":          params.Username,
				"days_until_expiry": params.DaysUntilExpiry,
				"include_expired":   params.IncludeExpired,
			},
		},
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}, "user", "")
}

// =================== HELPER METHODS WITH ENHANCED VALIDATION ===================

// parseAndValidateListUsersParams parses and validates query parameters for listing users
func (h *UserHandler) parseAndValidateListUsersParams(c *gin.Context) (*entities.ListUsersParams, *errors.AppError) {
	params := &entities.ListUsersParams{
		Page:    1,
		PerPage: 20,
		Sort:    "username",
		Order:   "asc",
	}

	// Parse and validate page with detailed error
	if pageStr := c.Query("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err != nil {
			return nil, errors.BadRequest("Invalid page parameter", map[string]interface{}{
				"provided_value": pageStr,
				"expected_type":  "integer",
				"minimum":        1,
			})
		} else if page < 1 {
			return nil, errors.BadRequest("Page must be positive", map[string]interface{}{
				"provided_value": page,
				"minimum":        1,
			})
		} else {
			params.Page = page
		}
	}

	// Parse and validate per_page with limits
	if perPageStr := c.Query("per_page"); perPageStr != "" {
		if perPage, err := strconv.Atoi(perPageStr); err != nil {
			return nil, errors.BadRequest("Invalid per_page parameter", map[string]interface{}{
				"provided_value": perPageStr,
				"expected_type":  "integer",
				"valid_range":    "1-100",
			})
		} else if perPage < 1 || perPage > 100 {
			return nil, errors.BadRequest("per_page out of range", map[string]interface{}{
				"provided_value": perPage,
				"valid_range":    "1-100",
				"suggestion":     "Use a value between 1 and 100",
			})
		} else {
			params.PerPage = perPage
		}
	}

	// Parse and validate sort field
	if sort := c.Query("sort"); sort != "" {
		validSorts := []string{"username", "email", "created_at", "last_login", "expiry_date"}
		if !h.isValidSort(sort, validSorts) {
			return nil, errors.BadRequest("Invalid sort field", map[string]interface{}{
				"provided_sort": sort,
				"valid_sorts":   validSorts,
				"examples": map[string]string{
					"username":    "Sort by username alphabetically",
					"email":       "Sort by email address",
					"created_at":  "Sort by creation date",
					"last_login":  "Sort by last login time",
					"expiry_date": "Sort by expiration date",
				},
			})
		} else {
			params.Sort = sort
		}
	}

	// Parse and validate sort order
	if order := c.Query("order"); order != "" {
		if order != "asc" && order != "desc" {
			return nil, errors.BadRequest("Invalid sort order", map[string]interface{}{
				"provided_order": order,
				"valid_orders":   []string{"asc", "desc"},
				"examples": map[string]string{
					"asc":  "Ascending order (A-Z, 0-9, oldest first)",
					"desc": "Descending order (Z-A, 9-0, newest first)",
				},
			})
		} else {
			params.Order = order
		}
	}

	// Parse and validate filter
	if filter := c.Query("filter"); filter != "" {
		validFilters := []string{"active", "inactive", "expired", "expiring_soon"}
		if !h.isValidFilter(filter, validFilters) {
			return nil, errors.BadRequest("Invalid filter", map[string]interface{}{
				"provided_filter": filter,
				"valid_filters":   validFilters,
				"descriptions": map[string]string{
					"active":        "Users with active status",
					"inactive":      "Users with inactive status",
					"expired":       "Users past their expiration date",
					"expiring_soon": "Users expiring within 7 days",
				},
			})
		} else {
			params.Filter = filter
		}
	}

	// Parse and validate search with minimum length
	if search := c.Query("search"); search != "" {
		if len(search) < 2 {
			return nil, errors.BadRequest("Search term too short", map[string]interface{}{
				"provided_length": len(search),
				"minimum_length":  2,
				"suggestion":      "Use at least 2 characters for search",
			})
		}
		params.Search = search
	}

	return params, nil
}

// convertCreateRequestToEntity converts create request DTO to entity with comprehensive validation
func (h *UserHandler) convertCreateRequestToEntity(req *dto.CreateUserRequest) (*entities.User, *errors.AppError) {
	user := &entities.User{
		Username:  req.Username,
		Email:     req.Email,
		Password:  req.Password,
		Admin:     req.Admin,
		IsActive:  true, // Default to active
		CreatedAt: time.Now().UTC(),
	}

	// Validate and set expiry date if provided
	if req.ExpiryDate != "" {
		expiryTime, err := time.Parse(time.RFC3339, req.ExpiryDate)
		if err != nil {
			return nil, errors.BadRequest("Invalid expiry date format", map[string]interface{}{
				"provided_date":   req.ExpiryDate,
				"expected_format": "RFC3339 (2006-01-02T15:04:05Z07:00)",
				"example":         "2024-12-31T23:59:59Z",
			})
		}
		if expiryTime.Before(time.Now()) {
			return nil, errors.BadRequest("Expiry date cannot be in the past", map[string]interface{}{
				"provided_date": req.ExpiryDate,
				"current_time":  time.Now().UTC().Format(time.RFC3339),
			})
		}
		user.ExpiryDate = &expiryTime
	}

	// Set group if provided
	if req.Group != "" {
		user.Group = req.Group
	}

	// Validate business rules with detailed errors
	if err := h.validateUserBusinessRules(user); err != nil {
		return nil, err
	}

	return user, nil
}

// convertUpdateRequestToEntity converts update request DTO to entity with change tracking
func (h *UserHandler) convertUpdateRequestToEntity(req *dto.UpdateUserRequest, existing *entities.User) (*entities.User, map[string]interface{}, *errors.AppError) {
	// Create updated user based on existing
	user := &entities.User{
		ID:        existing.ID,
		Username:  existing.Username,  // Username cannot be changed
		CreatedAt: existing.CreatedAt, // Preserve creation time
	}

	// Track changes for logging and response
	changes := make(map[string]interface{})

	// Update fields if provided and track changes
	if req.Email != "" && req.Email != existing.Email {
		user.Email = req.Email
		changes["email"] = map[string]string{"from": existing.Email, "to": req.Email}
	} else {
		user.Email = existing.Email
	}

	if req.Password != "" {
		user.Password = req.Password
		changes["password"] = "updated"
	} else {
		user.Password = existing.Password
	}

	if req.Admin != nil && *req.Admin != existing.Admin {
		user.Admin = *req.Admin
		changes["admin"] = map[string]bool{"from": existing.Admin, "to": *req.Admin}
	} else {
		user.Admin = existing.Admin
	}

	if req.IsActive != nil && *req.IsActive != existing.IsActive {
		user.IsActive = *req.IsActive
		changes["is_active"] = map[string]bool{"from": existing.IsActive, "to": *req.IsActive}
	} else {
		user.IsActive = existing.IsActive
	}

	// Update expiry date if provided and track changes
	if req.ExpiryDate != "" {
		expiryTime, err := time.Parse(time.RFC3339, req.ExpiryDate)
		if err != nil {
			return nil, nil, errors.BadRequest("Invalid expiry date format", map[string]interface{}{
				"provided_date":   req.ExpiryDate,
				"expected_format": "RFC3339 (2006-01-02T15:04:05Z07:00)",
				"example":         "2024-12-31T23:59:59Z",
			})
		}
		if expiryTime.Before(time.Now()) {
			return nil, nil, errors.BadRequest("Expiry date cannot be in the past", map[string]interface{}{
				"provided_date": req.ExpiryDate,
				"current_time":  time.Now().UTC().Format(time.RFC3339),
			})
		}

		var oldExpiry string
		if existing.ExpiryDate != nil {
			oldExpiry = existing.ExpiryDate.Format(time.RFC3339)
		}
		newExpiry := expiryTime.Format(time.RFC3339)

		if oldExpiry != newExpiry {
			changes["expiry_date"] = map[string]string{"from": oldExpiry, "to": newExpiry}
		}

		user.ExpiryDate = &expiryTime
	} else {
		user.ExpiryDate = existing.ExpiryDate
	}

	// Update group if provided and track changes
	if req.Group != "" && req.Group != existing.Group {
		user.Group = req.Group
		changes["group"] = map[string]string{"from": existing.Group, "to": req.Group}
	} else {
		user.Group = existing.Group
	}

	user.UpdatedAt = time.Now().UTC()

	// Validate business rules
	if err := h.validateUserBusinessRules(user); err != nil {
		return nil, nil, err
	}

	return user, changes, nil
}

// convertEntityToResponse converts user entity to response DTO with all fields
func (h *UserHandler) convertEntityToResponse(user *entities.User) dto.UserResponse {
	response := dto.UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Admin:     user.Admin,
		IsActive:  user.IsActive,
		Group:     user.Group,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}

	if user.ExpiryDate != nil {
		expiryStr := user.ExpiryDate.Format(time.RFC3339)
		response.ExpiryDate = &expiryStr
	}

	if !user.UpdatedAt.IsZero() {
		updatedStr := user.UpdatedAt.Format(time.RFC3339)
		response.UpdatedAt = &updatedStr
	}

	if user.LastLogin != nil {
		lastLoginStr := user.LastLogin.Format(time.RFC3339)
		response.LastLogin = &lastLoginStr
	}

	return response
}

// convertExpirationToResponse converts expiration entity to response DTO
func (h *UserHandler) convertExpirationToResponse(exp *entities.UserExpiration) dto.UserExpirationInfo {
	response := dto.UserExpirationInfo{
		Username:     exp.Username,
		Email:        exp.Email,
		DaysToExpiry: exp.DaysToExpiry,
		IsExpired:    exp.IsExpired,
	}

	if exp.ExpiryDate != nil {
		expiryStr := exp.ExpiryDate.Format(time.RFC3339)
		response.ExpiryDate = &expiryStr
	}

	return response
}

// validateUserBusinessRules validates business rules for user with detailed errors
func (h *UserHandler) validateUserBusinessRules(user *entities.User) *errors.AppError {
	// Username validation with detailed requirements
	if len(user.Username) < 3 || len(user.Username) > 32 {
		return errors.BadRequest("Username length invalid", map[string]interface{}{
			"username":       user.Username,
			"current_length": len(user.Username),
			"required_range": "3-32 characters",
			"suggestions": []string{
				"Use alphanumeric characters",
				"Avoid special characters except underscore and dash",
				"Choose a memorable but unique username",
			},
		})
	}

	// Email validation with detailed format checking
	if user.Email != "" {
		if !h.isValidEmail(user.Email) {
			return errors.BadRequest("Invalid email format", map[string]interface{}{
				"email": user.Email,
				"requirements": []string{
					"Must contain @ symbol",
					"Must have valid domain",
					"Must follow standard email format",
				},
				"example": "user@example.com",
			})
		}
	}

	// Password validation with strength requirements
	if user.Password != "" {
		if err := h.validatePasswordStrength(user.Password); err != nil {
			return err
		}
	}

	// Expiry date validation
	if user.ExpiryDate != nil && user.ExpiryDate.Before(time.Now()) {
		return errors.BadRequest("Expiry date cannot be in the past", map[string]interface{}{
			"provided_expiry": user.ExpiryDate.Format(time.RFC3339),
			"current_time":    time.Now().UTC().Format(time.RFC3339),
		})
	}

	return nil
}

// validatePasswordStrength validates password strength with detailed requirements
func (h *UserHandler) validatePasswordStrength(password string) *errors.AppError {
	issues := []string{}

	if len(password) < 8 {
		issues = append(issues, "Password must be at least 8 characters long")
	}

	if len(password) > 128 {
		issues = append(issues, "Password must not exceed 128 characters")
	}

	// Additional password strength checks
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case char >= 32 && char <= 126: // Printable ASCII special characters
			if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')) {
				hasSpecial = true
			}
		}
	}

	if !hasUpper {
		issues = append(issues, "Password must contain at least one uppercase letter")
	}
	if !hasLower {
		issues = append(issues, "Password must contain at least one lowercase letter")
	}
	if !hasDigit {
		issues = append(issues, "Password must contain at least one digit")
	}
	if !hasSpecial {
		issues = append(issues, "Password must contain at least one special character")
	}

	if len(issues) > 0 {
		return errors.BadRequest("Password does not meet strength requirements", map[string]interface{}{
			"issues": issues,
			"requirements": []string{
				"8-128 characters long",
				"At least one uppercase letter",
				"At least one lowercase letter",
				"At least one digit",
				"At least one special character",
			},
			"example": "SecurePass123!",
		})
	}

	return nil
}

// performUserAction performs the specified action on a user with comprehensive handling
func (h *UserHandler) performUserAction(c *gin.Context, user *entities.User, action string, req *dto.UserActionRequest) (interface{}, error) {
	switch action {
	case "enable":
		return h.enableUser(c, user)
	case "disable":
		return h.disableUser(c, user)
	case "reset_password":
		return h.resetUserPassword(c, user, req.NewPassword)
	case "extend_expiry":
		return h.extendUserExpiry(c, user, req.ExpiryDate)
	default:
		return nil, errors.BadRequest("Unsupported action", map[string]interface{}{
			"action":            action,
			"supported_actions": []string{"enable", "disable", "reset_password", "extend_expiry"},
		})
	}
}

// getRequiredFieldsForAction returns required fields for specific actions
func (h *UserHandler) getRequiredFieldsForAction(action string) interface{} {
	switch action {
	case "reset_password":
		return map[string]string{
			"new_password": "New password meeting strength requirements",
		}
	case "extend_expiry":
		return map[string]string{
			"expiry_date": "New expiry date in RFC3339 format (2006-01-02T15:04:05Z07:00)",
		}
	default:
		return "No additional fields required"
	}
}

// Validation helper functions
func (h *UserHandler) isValidAction(action string, validActions []string) bool {
	for _, validAction := range validActions {
		if action == validAction {
			return true
		}
	}
	return false
}

func (h *UserHandler) isValidSort(sort string, validSorts []string) bool {
	for _, validSort := range validSorts {
		if sort == validSort {
			return true
		}
	}
	return false
}

func (h *UserHandler) isValidFilter(filter string, validFilters []string) bool {
	for _, validFilter := range validFilters {
		if filter == validFilter {
			return true
		}
	}
	return false
}

func (h *UserHandler) isValidEmail(email string) bool {
	// Basic email validation - in production, use a proper email validation library
	return len(email) > 0 &&
		len(email) <= 254 &&
		strings.Contains(email, "@") &&
		strings.Contains(email, ".") &&
		!strings.HasPrefix(email, "@") &&
		!strings.HasSuffix(email, "@") &&
		!strings.Contains(email, "..") &&
		!strings.Contains(email, " ")
}

// Action implementation methods with detailed responses
func (h *UserHandler) enableUser(c *gin.Context, user *entities.User) (*dto.UserActionResponse, error) {
	if user.IsActive {
		return nil, errors.BadRequest("User is already enabled", map[string]interface{}{
			"current_status": "active",
			"suggestion":     "User is already in active state",
		})
	}

	user.IsActive = true
	user.UpdatedAt = time.Now().UTC()

	updatedUser, err := h.userUsecase.UpdateUser(c.Request.Context(), user)
	if err != nil {
		return nil, err
	}

	return &dto.UserActionResponse{
		Action:    "enable",
		Success:   true,
		Message:   "User enabled successfully",
		User:      h.convertEntityToResponse(updatedUser),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (h *UserHandler) disableUser(c *gin.Context, user *entities.User) (*dto.UserActionResponse, error) {
	if !user.IsActive {
		return nil, errors.BadRequest("User is already disabled", map[string]interface{}{
			"current_status": "inactive",
			"suggestion":     "User is already in inactive state",
		})
	}

	user.IsActive = false
	user.UpdatedAt = time.Now().UTC()

	updatedUser, err := h.userUsecase.UpdateUser(c.Request.Context(), user)
	if err != nil {
		return nil, err
	}

	return &dto.UserActionResponse{
		Action:    "disable",
		Success:   true,
		Message:   "User disabled successfully",
		User:      h.convertEntityToResponse(updatedUser),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (h *UserHandler) resetUserPassword(c *gin.Context, user *entities.User, newPassword string) (*dto.UserActionResponse, error) {
	if newPassword == "" {
		return nil, errors.BadRequest("New password is required", map[string]interface{}{
			"field":        "new_password",
			"requirements": "Password meeting strength requirements",
		})
	}

	// Validate password strength
	if err := h.validatePasswordStrength(newPassword); err != nil {
		return nil, err
	}

	user.Password = newPassword
	user.UpdatedAt = time.Now().UTC()

	updatedUser, err := h.userUsecase.UpdateUser(c.Request.Context(), user)
	if err != nil {
		return nil, err
	}

	return &dto.UserActionResponse{
		Action:    "reset_password",
		Success:   true,
		Message:   "Password reset successfully",
		User:      h.convertEntityToResponse(updatedUser),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (h *UserHandler) extendUserExpiry(c *gin.Context, user *entities.User, newExpiryDate string) (*dto.UserActionResponse, error) {
	if newExpiryDate == "" {
		return nil, errors.BadRequest("New expiry date is required", map[string]interface{}{
			"field":   "expiry_date",
			"format":  "RFC3339 (2006-01-02T15:04:05Z07:00)",
			"example": "2024-12-31T23:59:59Z",
		})
	}

	expiryTime, err := time.Parse(time.RFC3339, newExpiryDate)
	if err != nil {
		return nil, errors.BadRequest("Invalid expiry date format", map[string]interface{}{
			"provided_date":   newExpiryDate,
			"expected_format": "RFC3339 (2006-01-02T15:04:05Z07:00)",
			"example":         "2024-12-31T23:59:59Z",
		})
	}

	if expiryTime.Before(time.Now()) {
		return nil, errors.BadRequest("Expiry date cannot be in the past", map[string]interface{}{
			"provided_date": newExpiryDate,
			"current_time":  time.Now().UTC().Format(time.RFC3339),
		})
	}

	user.ExpiryDate = &expiryTime
	user.UpdatedAt = time.Now().UTC()

	updatedUser, err := h.userUsecase.UpdateUser(c.Request.Context(), user)
	if err != nil {
		return nil, err
	}

	return &dto.UserActionResponse{
		Action:    "extend_expiry",
		Success:   true,
		Message:   "User expiry extended successfully",
		User:      h.convertEntityToResponse(updatedUser),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}
