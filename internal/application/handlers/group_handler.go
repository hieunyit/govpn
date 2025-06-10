package handlers

import (
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/usecases"
	"govpn/internal/infrastructure/xmlrpc"
	"govpn/internal/presentation/http"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	nethttp "net/http"

	"github.com/gin-gonic/gin"
)

type GroupHandler struct {
	groupUsecase usecases.GroupUsecase
	xmlrpcClient *xmlrpc.Client
}

func NewGroupHandler(groupUsecase usecases.GroupUsecase, xmlrpcClient *xmlrpc.Client) *GroupHandler {
	return &GroupHandler{
		groupUsecase: groupUsecase,
		xmlrpcClient: xmlrpcClient,
	}
}

// CreateGroup godoc
// @Summary Create a new group
// @Description Create a new VPN user group
// @Tags groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.CreateGroupRequest true "Group creation data"
// @Success 201 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /api/groups [post]
func (h *GroupHandler) CreateGroup(c *gin.Context) {
	var req dto.CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind create group request")
		http.RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Create group request validation failed")
		http.RespondWithValidationError(c, err)
		return
	}

	// Convert DTO to entity
	group := &entities.Group{
		GroupName:     req.GroupName,
		AuthMethod:    req.AuthMethod,
		AccessControl: req.AccessControl,
	}

	// Create group
	if err := h.groupUsecase.CreateGroup(c.Request.Context(), group); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			http.RespondWithError(c, appErr)
		} else {
			http.RespondWithError(c, errors.InternalServerError("Failed to create group", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after group creation")
		// Don't fail the request, just log the error
	}

	http.RespondWithMessage(c, nethttp.StatusCreated, "Group created successfully")
}

// GetGroup godoc
// @Summary Get group by name
// @Description Get detailed information about a group
// @Tags groups
// @Security BearerAuth
// @Produce json
// @Param groupName path string true "Group name"
// @Success 200 {object} dto.GroupResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/groups/{groupName} [get]
func (h *GroupHandler) GetGroup(c *gin.Context) {
	groupName := c.Param("groupName")
	if groupName == "" {
		http.RespondWithError(c, errors.BadRequest("Group name is required", nil))
		return
	}

	group, err := h.groupUsecase.GetGroup(c.Request.Context(), groupName)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			http.RespondWithError(c, appErr)
		} else {
			http.RespondWithError(c, errors.InternalServerError("Failed to get group", err))
		}
		return
	}

	// Convert entity to DTO
	response := dto.GroupResponse{
		GroupName:     group.GroupName,
		AuthMethod:    group.AuthMethod,
		MFA:           group.MFA == "true",
		Role:          group.Role,
		DenyAccess:    group.DenyAccess == "true",
		AccessControl: group.AccessControl,
	}

	http.RespondWithSuccess(c, nethttp.StatusOK, response)
}

// UpdateGroup godoc
// @Summary Update group
// @Description Update group information
// @Tags groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param groupName path string true "Group name"
// @Param request body dto.UpdateGroupRequest true "Group update data"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/groups/{groupName} [put]
func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	groupName := c.Param("groupName")
	if groupName == "" {
		http.RespondWithError(c, errors.BadRequest("Group name is required", nil))
		return
	}

	var req dto.UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind update group request")
		http.RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Update group request validation failed")
		http.RespondWithValidationError(c, err)
		return
	}

	// Convert DTO to entity
	group := &entities.Group{
		GroupName:     groupName,
		AccessControl: req.AccessControl,
	}

	if req.DenyAccess != nil {
		group.SetDenyAccess(*req.DenyAccess)
	}

	// Update group
	if err := h.groupUsecase.UpdateGroup(c.Request.Context(), group); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			http.RespondWithError(c, appErr)
		} else {
			http.RespondWithError(c, errors.InternalServerError("Failed to update group", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after group update")
	}

	http.RespondWithMessage(c, nethttp.StatusOK, "Group updated successfully")
}

// DeleteGroup godoc
// @Summary Delete group
// @Description Delete a group
// @Tags groups
// @Security BearerAuth
// @Param groupName path string true "Group name"
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/groups/{groupName} [delete]
func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	groupName := c.Param("groupName")
	if groupName == "" {
		http.RespondWithError(c, errors.BadRequest("Group name is required", nil))
		return
	}

	if err := h.groupUsecase.DeleteGroup(c.Request.Context(), groupName); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			http.RespondWithError(c, appErr)
		} else {
			http.RespondWithError(c, errors.InternalServerError("Failed to delete group", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after group deletion")
	}

	http.RespondWithMessage(c, nethttp.StatusOK, "Group deleted successfully")
}

// GroupAction godoc
// @Summary Perform group action
// @Description Enable or disable a group
// @Tags groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param groupName path string true "Group name"
// @Param action path string true "Action" Enums(enable,disable)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/groups/{groupName}/{action} [put]
func (h *GroupHandler) GroupAction(c *gin.Context) {
	groupName := c.Param("groupName")
	action := c.Param("action")

	if groupName == "" {
		http.RespondWithError(c, errors.BadRequest("Group name is required", nil))
		return
	}

	if action == "" {
		http.RespondWithError(c, errors.BadRequest("Action is required", nil))
		return
	}

	var err error
	var message string

	switch action {
	case "enable":
		err = h.groupUsecase.EnableGroup(c.Request.Context(), groupName)
		message = "Group enabled successfully"
	case "disable":
		err = h.groupUsecase.DisableGroup(c.Request.Context(), groupName)
		message = "Group disabled successfully"
	default:
		http.RespondWithError(c, errors.BadRequest("Invalid action", nil))
		return
	}

	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			http.RespondWithError(c, appErr)
		} else {
			http.RespondWithError(c, errors.InternalServerError("Action failed", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after group action")
	}

	http.RespondWithMessage(c, nethttp.StatusOK, message)
}

// ListGroups godoc
// @Summary List groups
// @Description Get list of groups with optional filtering
// @Tags groups
// @Security BearerAuth
// @Produce json
// @Param groupName query string false "Filter by group name"
// @Param authMethod query string false "Filter by auth method"
// @Param role query string false "Filter by role"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} dto.GroupListResponse
// @Router /api/groups [get]
func (h *GroupHandler) ListGroups(c *gin.Context) {
	var filter dto.GroupFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		http.RespondWithError(c, errors.BadRequest("Invalid query parameters", err))
		return
	}

	// Convert DTO filter to entity filter
	entityFilter := &entities.GroupFilter{
		GroupName:  filter.GroupName,
		AuthMethod: filter.AuthMethod,
		Role:       filter.Role,
		Limit:      filter.Limit,
		Offset:     (filter.Page - 1) * filter.Limit,
	}

	groups, err := h.groupUsecase.ListGroups(c.Request.Context(), entityFilter)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			http.RespondWithError(c, appErr)
		} else {
			http.RespondWithError(c, errors.InternalServerError("Failed to list groups", err))
		}
		return
	}

	// Convert entities to DTOs
	groupResponses := make([]dto.GroupResponse, len(groups))
	for i, group := range groups {
		groupResponses[i] = dto.GroupResponse{
			GroupName:     group.GroupName,
			AuthMethod:    group.AuthMethod,
			MFA:           group.MFA == "true",
			Role:          group.Role,
			DenyAccess:    group.DenyAccess == "true",
			AccessControl: group.AccessControl,
		}
	}

	response := dto.GroupListResponse{
		Groups: groupResponses,
		Total:  len(groupResponses),
		Page:   filter.Page,
		Limit:  filter.Limit,
	}

	http.RespondWithSuccess(c, nethttp.StatusOK, response)
}
