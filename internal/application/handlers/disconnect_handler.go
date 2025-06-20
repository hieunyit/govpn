// internal/application/handlers/disconnect_handler.go
package handlers

import (
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/usecases"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type DisconnectHandler struct {
	disconnectUsecase usecases.DisconnectUsecase
}

func NewDisconnectHandler(disconnectUsecase usecases.DisconnectUsecase) *DisconnectHandler {
	return &DisconnectHandler{
		disconnectUsecase: disconnectUsecase,
	}
}

// BulkDisconnectUsers godoc
// @Summary Bulk disconnect multiple VPN users
// @Description Disconnect multiple users from VPN with business logic validation (user exists and is connected)
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.BulkDisconnectUsersRequest true "Bulk disconnect users request"
// @Success 200 {object} dto.SuccessResponse{data=dto.DisconnectResponse} "Users disconnected successfully"
// @Failure 400 {object} dto.ErrorResponse "Bad request - validation error or no valid users"
// @Failure 401 {object} dto.ErrorResponse "Unauthorized - invalid or missing authentication"
// @Failure 500 {object} dto.ErrorResponse "Internal server error - failed to disconnect users"
// @Router /api/openvpn/bulk/users/disconnect [post]
func (h *DisconnectHandler) BulkDisconnectUsers(c *gin.Context) {
	var req dto.BulkDisconnectUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind bulk disconnect users request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Bulk disconnect users request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	logger.Log.WithField("usernames", req.Usernames).
		WithField("message", req.Message).
		WithField("count", len(req.Usernames)).
		Info("Processing bulk disconnect request")

	// Execute business logic via usecase
	result, err := h.disconnectUsecase.BulkDisconnectUsers(c.Request.Context(), req.Usernames, req.Message)
	if err != nil {
		logger.Log.WithError(err).Error("Bulk disconnect usecase failed")

		// Check if this is a business logic error (no valid users)
		if result != nil && !result.Success && len(result.DisconnectedUsers) == 0 {
			RespondWithError(c, errors.BadRequest(result.Message, err))
			return
		}

		// Infrastructure or unexpected error
		RespondWithError(c, errors.InternalServerError("Failed to process bulk disconnect", err))
		return
	}

	// Convert usecase result to DTO response
	response := h.convertBulkDisconnectResult(result)

	// Determine appropriate status code
	statusCode := http.StatusOK
	if !result.Success && len(result.DisconnectedUsers) > 0 {
		statusCode = http.StatusPartialContent // 206 for partial success
	}

	logger.Log.WithField("disconnected_count", len(result.DisconnectedUsers)).
		WithField("skipped_count", len(result.SkippedUsers)).
		WithField("total_requested", result.TotalRequested).
		WithField("success", result.Success).
		Info("Bulk disconnect completed")

	RespondWithSuccess(c, statusCode, response)
}

// DisconnectUser godoc
// @Summary Disconnect a single VPN user
// @Description Disconnect a specific user from VPN with business logic validation (user exists and is connected)
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param username path string true "Username to disconnect"
// @Param request body dto.DisconnectUserRequest true "Disconnect user request"
// @Success 200 {object} dto.SuccessResponse{data=dto.DisconnectResponse} "User disconnected successfully"
// @Failure 400 {object} dto.ErrorResponse "Bad request - user not found or not connected"
// @Failure 401 {object} dto.ErrorResponse "Unauthorized - invalid or missing authentication"
// @Failure 404 {object} dto.ErrorResponse "User not found in system"
// @Failure 500 {object} dto.ErrorResponse "Internal server error - failed to disconnect user"
// @Router /api/openvpn/users/{username}/disconnect [post]
func (h *DisconnectHandler) DisconnectUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		RespondWithError(c, errors.BadRequest("Username is required", nil))
		return
	}

	var req dto.DisconnectUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind disconnect user request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Disconnect user request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	logger.Log.WithField("username", username).
		WithField("message", req.Message).
		Info("Processing single user disconnect request")

	// Execute business logic via usecase
	result, err := h.disconnectUsecase.DisconnectUser(c.Request.Context(), username, req.Message)
	if err != nil {
		logger.Log.WithError(err).WithField("username", username).Error("Disconnect user usecase failed")

		// Map business logic errors to appropriate HTTP status codes
		if result != nil && !result.Success {
			if strings.Contains(result.Error, "not found in system") {
				RespondWithError(c, errors.NotFound(result.Error, err))
				return
			} else if strings.Contains(result.Error, "not currently connected") {
				RespondWithError(c, errors.BadRequest(result.Error, err))
				return
			} else if strings.Contains(result.Error, "connection status") {
				RespondWithError(c, errors.InternalServerError(result.Error, err))
				return
			}
		}

		// Default to internal server error
		RespondWithError(c, errors.InternalServerError("Failed to disconnect user", err))
		return
	}

	// Convert usecase result to DTO response
	response := h.convertSingleDisconnectResult(result)

	logger.Log.WithField("username", username).
		WithField("success", result.Success).
		Info("Single user disconnect completed")

	RespondWithSuccess(c, http.StatusOK, response)
}

// convertBulkDisconnectResult - convert usecase result to DTO for bulk operation
func (h *DisconnectHandler) convertBulkDisconnectResult(result *usecases.BulkDisconnectResult) dto.DisconnectResponse {
	return dto.DisconnectResponse{
		Success:           result.Success,
		DisconnectedUsers: result.DisconnectedUsers,
		Message:           result.Message,
		Count:             len(result.DisconnectedUsers),
		SkippedUsers:      result.SkippedUsers,
		ValidationErrors:  h.convertUsecaseValidationErrors(result.ValidationErrors),
		TotalRequested:    &result.TotalRequested,
	}
}

// convertSingleDisconnectResult - convert usecase result to DTO for single operation
func (h *DisconnectHandler) convertSingleDisconnectResult(result *usecases.DisconnectResult) dto.DisconnectResponse {
	response := dto.DisconnectResponse{
		Success:           result.Success,
		DisconnectedUsers: []string{result.Username},
		Message:           result.Message,
		Count:             1,
	}

	// Add connection info if available
	if result.ConnectionInfo != nil {
		response.ConnectionInfo = h.convertConnectionInfo(result.ConnectionInfo)
	}

	return response
}

// convertUsecaseValidationErrors - convert usecase validation errors to DTO
func (h *DisconnectHandler) convertUsecaseValidationErrors(usecaseErrors []usecases.UserValidationError) []dto.UserValidationError {
	if len(usecaseErrors) == 0 {
		return nil
	}

	dtoErrors := make([]dto.UserValidationError, len(usecaseErrors))
	for i, err := range usecaseErrors {
		dtoErrors[i] = dto.UserValidationError{
			Username: err.Username,
			Error:    err.Error,
		}
	}
	return dtoErrors
}

// convertConnectionInfo - convert entities.ConnectedUser to DTO
func (h *DisconnectHandler) convertConnectionInfo(connInfo *entities.ConnectedUser) *dto.UserConnectionInfo {
	if connInfo == nil {
		return nil
	}

	return &dto.UserConnectionInfo{
		Username:       connInfo.Username,
		RealAddress:    connInfo.RealAddress,
		VirtualAddress: connInfo.VirtualAddress,
		ConnectedSince: connInfo.ConnectedSince,
		Country:        connInfo.Country,
	}
}
