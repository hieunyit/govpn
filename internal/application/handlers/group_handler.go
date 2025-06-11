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
	"strings"

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
// @Tags Groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.CreateGroupRequest true "Group creation data"
// @Success 201 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Router /api/groups [post]
func (h *GroupHandler) CreateGroup(c *gin.Context) {
	var req dto.CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind create group request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Create group request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// BASIC FIX: Validate reserved group names
	if h.isReservedGroupName(req.GroupName) {
		RespondWithError(c, errors.BadRequest("Group name is reserved and cannot be used", nil))
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
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to create group", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after group creation")
		// Don't fail the request, just log the error
	}

	RespondWithMessage(c, nethttp.StatusCreated, "Group created successfully")
}

// GetGroup godoc
// @Summary Get group by name
// @Description Get detailed information about a group
// @Tags Groups
// @Security BearerAuth
// @Produce json
// @Param groupName path string true "Group name"
// @Success 200 {object} dto.GroupResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /api/groups/{groupName} [get]
func (h *GroupHandler) GetGroup(c *gin.Context) {
	groupName := c.Param("groupName")
	if groupName == "" {
		RespondWithError(c, errors.BadRequest("Group name is required", nil))
		return
	}

	group, err := h.groupUsecase.GetGroup(c.Request.Context(), groupName)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to get group", err))
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

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// UpdateGroup godoc
// @Summary Update group
// @Description Update group information
// @Tags Groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param groupName path string true "Group name"
// @Param request body dto.UpdateGroupRequest true "Group update data"
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /api/groups/{groupName} [put]
func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	groupName := c.Param("groupName")
	if groupName == "" {
		RespondWithError(c, errors.BadRequest("Group name is required", nil))
		return
	}

	// BASIC FIX: Check if group is system group
	if h.isSystemGroup(groupName) {
		RespondWithError(c, errors.BadRequest("Cannot modify system group", nil))
		return
	}

	var req dto.UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind update group request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Update group request validation failed")
		RespondWithValidationError(c, err)
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
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to update group", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after group update")
	}

	RespondWithMessage(c, nethttp.StatusOK, "Group updated successfully")
}

// DeleteGroup godoc
// @Summary Delete group
// @Description Delete a group
// @Tags Groups
// @Security BearerAuth
// @Param groupName path string true "Group name"
// @Success 200 {object} dto.MessageResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /api/groups/{groupName} [delete]
func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	groupName := c.Param("groupName")
	if groupName == "" {
		RespondWithError(c, errors.BadRequest("Group name is required", nil))
		return
	}

	// BASIC FIX: Check if group is system group
	if h.isSystemGroup(groupName) {
		RespondWithError(c, errors.BadRequest("Cannot delete system group", nil))
		return
	}

	if err := h.groupUsecase.DeleteGroup(c.Request.Context(), groupName); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to delete group", err))
		}
		return
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after group deletion")
	}

	RespondWithMessage(c, nethttp.StatusOK, "Group deleted successfully")
}

// GroupAction godoc
// @Summary Perform group action
// @Description Perform actions like enable, disable
// @Tags Groups
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param groupName path string true "Group name"
// @Param action path string true "Action" Enums(enable, disable)
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/groups/{groupName}/{action} [put]
func (h *GroupHandler) GroupAction(c *gin.Context) {
	groupName := c.Param("groupName")
	action := c.Param("action")

	if groupName == "" {
		RespondWithError(c, errors.BadRequest("Group name is required", nil))
		return
	}

	// BASIC FIX: Check if group is system group
	if h.isSystemGroup(groupName) && action == "disable" {
		RespondWithError(c, errors.BadRequest("Cannot disable system group", nil))
		return
	}

	// Validate action
	if action != "enable" && action != "disable" {
		RespondWithError(c, errors.BadRequest("Invalid action. Allowed actions: enable, disable", nil))
		return
	}

	// Get existing group to check current state
	existingGroup, err := h.groupUsecase.GetGroup(c.Request.Context(), groupName)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to get group", err))
		}
		return
	}

	switch action {
	case "enable":
		if existingGroup.DenyAccess != "true" {
			RespondWithError(c, errors.BadRequest("Group is already enabled", nil))
			return
		}

		group := &entities.Group{
			GroupName: groupName,
		}
		group.SetDenyAccess(false)

		if err := h.groupUsecase.UpdateGroup(c.Request.Context(), group); err != nil {
			if appErr, ok := err.(*errors.AppError); ok {
				RespondWithError(c, appErr)
			} else {
				RespondWithError(c, errors.InternalServerError("Failed to enable group", err))
			}
			return
		}
		RespondWithMessage(c, nethttp.StatusOK, "Group enabled successfully")

	case "disable":
		if existingGroup.DenyAccess == "true" {
			RespondWithError(c, errors.BadRequest("Group is already disabled", nil))
			return
		}

		group := &entities.Group{
			GroupName: groupName,
		}
		group.SetDenyAccess(true)

		if err := h.groupUsecase.UpdateGroup(c.Request.Context(), group); err != nil {
			if appErr, ok := err.(*errors.AppError); ok {
				RespondWithError(c, appErr)
			} else {
				RespondWithError(c, errors.InternalServerError("Failed to disable group", err))
			}
			return
		}
		RespondWithMessage(c, nethttp.StatusOK, "Group disabled successfully")
	}

	// Restart OpenVPN service
	if err := h.xmlrpcClient.RunStart(); err != nil {
		logger.Log.WithError(err).Error("Failed to restart OpenVPN service after group action")
	}
}

// ListGroups godoc
// @Summary List groups
// @Description Get a paginated list of groups with filtering
// @Tags Groups
// @Security BearerAuth
// @Produce json
// @Param groupName query string false "Filter by group name"
// @Param authMethod query string false "Filter by auth method" Enums(ldap, local)
// @Param role query string false "Filter by role"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} dto.GroupListResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/groups [get]
func (h *GroupHandler) ListGroups(c *gin.Context) {
	var filter dto.GroupFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		logger.Log.WithError(err).Error("Failed to bind group filter")
		RespondWithError(c, errors.BadRequest("Invalid filter parameters", err))
		return
	}

	// Validate filter
	if err := validator.Validate(&filter); err != nil {
		logger.Log.WithError(err).Error("Group filter validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Convert DTO filter to entity filter
	entityFilter := &entities.GroupFilter{
		GroupName:  filter.GroupName,
		AuthMethod: filter.AuthMethod,
		Role:       filter.Role,
		Page:       filter.Page,
		Limit:      filter.Limit,
	}

	groups, err := h.groupUsecase.ListGroups(c.Request.Context(), entityFilter)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to list groups", err))
		}
		return
	}

	// Convert entities to DTOs
	var groupResponses []dto.GroupResponse
	for _, group := range groups {
		groupResponses = append(groupResponses, dto.GroupResponse{
			GroupName:     group.GroupName,
			AuthMethod:    group.AuthMethod,
			MFA:           group.MFA == "true",
			Role:          group.Role,
			DenyAccess:    group.DenyAccess == "true",
			AccessControl: group.AccessControl,
		})
	}

	response := dto.GroupListResponse{
		Groups: groupResponses,
		Total:  len(groupResponses),
		Page:   filter.Page,
		Limit:  filter.Limit,
	}

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// BASIC FIX: Helper functions to validate group names
func (h *GroupHandler) isReservedGroupName(groupName string) bool {
	reservedNames := []string{"__DEFAULT__", "admin", "root", "system", "default"}
	for _, reserved := range reservedNames {
		if strings.EqualFold(groupName, reserved) {
			return true
		}
	}
	return false
}

func (h *GroupHandler) isSystemGroup(groupName string) bool {
	systemGroups := []string{"__DEFAULT__", "admin", "system"}
	for _, systemGroup := range systemGroups {
		if strings.EqualFold(groupName, systemGroup) {
			return true
		}
	}
	return false
}
