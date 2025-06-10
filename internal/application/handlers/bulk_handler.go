package handlers

import (
	"govpn/internal/application/dto"
	"govpn/internal/domain/usecases"
	"govpn/internal/infrastructure/xmlrpc"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	nethttp "net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type BulkHandler struct {
	bulkUsecase  usecases.BulkUsecase
	xmlrpcClient *xmlrpc.Client
}

func NewBulkHandler(bulkUsecase usecases.BulkUsecase, xmlrpcClient *xmlrpc.Client) *BulkHandler {
	return &BulkHandler{
		bulkUsecase:  bulkUsecase,
		xmlrpcClient: xmlrpcClient,
	}
}

// =================== BULK USER OPERATIONS ===================

// BulkCreateUsers godoc
// @Summary Bulk create users
// @Description Create multiple users at once
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.BulkCreateUsersRequest true "Bulk user creation data"
// @Success 201 {object} dto.BulkCreateUsersResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 413 {object} dto.ErrorResponse "Request too large"
// @Router /api/bulk/users/create [post]
func (h *BulkHandler) BulkCreateUsers(c *gin.Context) {
	var req dto.BulkCreateUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind bulk create users request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Bulk create users request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	logger.Log.WithField("userCount", len(req.Users)).Info("Processing bulk user creation")

	// Process bulk creation
	response, err := h.bulkUsecase.BulkCreateUsers(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Bulk user creation failed", err))
		}
		return
	}

	// Restart OpenVPN service if any users were created
	if response.Success > 0 {
		if err := h.xmlrpcClient.RunStart(); err != nil {
			logger.Log.WithError(err).Error("Failed to restart OpenVPN service after bulk user creation")
		}
	}

	logger.Log.WithField("success", response.Success).
		WithField("failed", response.Failed).
		Info("Bulk user creation completed")

	RespondWithSuccess(c, nethttp.StatusCreated, response)
}

// BulkUserActions godoc
// @Summary Bulk user actions
// @Description Perform actions on multiple users (enable/disable/reset-otp)
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.BulkUserActionsRequest true "Bulk user actions data"
// @Success 200 {object} dto.BulkActionResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/bulk/users/actions [post]
func (h *BulkHandler) BulkUserActions(c *gin.Context) {
	var req dto.BulkUserActionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind bulk user actions request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Bulk user actions request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	logger.Log.WithField("userCount", len(req.Usernames)).
		WithField("action", req.Action).
		Info("Processing bulk user actions")

	// Process bulk actions
	response, err := h.bulkUsecase.BulkUserActions(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Bulk user actions failed", err))
		}
		return
	}

	// Restart OpenVPN service if any actions were successful
	if response.Success > 0 {
		if err := h.xmlrpcClient.RunStart(); err != nil {
			logger.Log.WithError(err).Error("Failed to restart OpenVPN service after bulk user actions")
		}
	}

	logger.Log.WithField("success", response.Success).
		WithField("failed", response.Failed).
		WithField("action", req.Action).
		Info("Bulk user actions completed")

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// BulkExtendUsers godoc
// @Summary Bulk extend user expiration
// @Description Extend expiration date for multiple users
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.BulkUserExtendRequest true "Bulk user extension data"
// @Success 200 {object} dto.BulkActionResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/bulk/users/extend [post]
func (h *BulkHandler) BulkExtendUsers(c *gin.Context) {
	var req dto.BulkUserExtendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind bulk extend users request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Bulk extend users request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	logger.Log.WithField("userCount", len(req.Usernames)).
		WithField("newExpiration", req.NewExpiration).
		Info("Processing bulk user extension")

	// Process bulk extension
	response, err := h.bulkUsecase.BulkExtendUsers(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Bulk user extension failed", err))
		}
		return
	}

	// Restart OpenVPN service if any extensions were successful
	if response.Success > 0 {
		if err := h.xmlrpcClient.RunStart(); err != nil {
			logger.Log.WithError(err).Error("Failed to restart OpenVPN service after bulk user extension")
		}
	}

	logger.Log.WithField("success", response.Success).
		WithField("failed", response.Failed).
		Info("Bulk user extension completed")

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// ImportUsers godoc
// @Summary Import users from file
// @Description Import users from CSV, JSON, or XLSX file
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Users file (CSV/JSON/XLSX)"
// @Param format formData string false "File format" Enums(csv, json, xlsx)
// @Param dryRun formData boolean false "Dry run mode (validate only)"
// @Param override formData boolean false "Override existing users"
// @Success 200 {object} dto.ImportResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 413 {object} dto.ErrorResponse "File too large"
// @Router /api/bulk/users/import [post]
func (h *BulkHandler) ImportUsers(c *gin.Context) {
	// Parse multipart form
	if err := c.Request.ParseMultipartForm(32 << 20); err != nil { // 32MB max
		logger.Log.WithError(err).Error("Failed to parse multipart form")
		RespondWithError(c, errors.BadRequest("Failed to parse form data", err))
		return
	}

	var req dto.ImportUsersRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind import users request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Import users request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Auto-detect format if not provided
	if req.Format == "" {
		req.Format = h.detectFileFormat(req.File.Filename)
	}

	dryRunStr := c.PostForm("dryRun")
	req.DryRun, _ = strconv.ParseBool(dryRunStr)

	overrideStr := c.PostForm("override")
	req.Override, _ = strconv.ParseBool(overrideStr)

	logger.Log.WithField("filename", req.File.Filename).
		WithField("format", req.Format).
		WithField("dryRun", req.DryRun).
		WithField("override", req.Override).
		Info("Processing user import")

	// Process file import
	response, err := h.bulkUsecase.ImportUsers(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("User import failed", err))
		}
		return
	}

	// Restart OpenVPN service if users were actually created (not dry run)
	if !req.DryRun && response.SuccessCount > 0 {
		if err := h.xmlrpcClient.RunStart(); err != nil {
			logger.Log.WithError(err).Error("Failed to restart OpenVPN service after user import")
		}
	}

	logger.Log.WithField("total", response.Total).
		WithField("valid", response.ValidRecords).
		WithField("processed", response.ProcessedRecords).
		WithField("success", response.SuccessCount).
		Info("User import completed")

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// =================== BULK GROUP OPERATIONS ===================

// BulkCreateGroups godoc
// @Summary Bulk create groups
// @Description Create multiple groups at once
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.BulkCreateGroupsRequest true "Bulk group creation data"
// @Success 201 {object} dto.BulkCreateGroupsResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/bulk/groups/create [post]
func (h *BulkHandler) BulkCreateGroups(c *gin.Context) {
	var req dto.BulkCreateGroupsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind bulk create groups request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Bulk create groups request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	logger.Log.WithField("groupCount", len(req.Groups)).Info("Processing bulk group creation")

	// Process bulk creation
	response, err := h.bulkUsecase.BulkCreateGroups(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Bulk group creation failed", err))
		}
		return
	}

	// Restart OpenVPN service if any groups were created
	if response.Success > 0 {
		if err := h.xmlrpcClient.RunStart(); err != nil {
			logger.Log.WithError(err).Error("Failed to restart OpenVPN service after bulk group creation")
		}
	}

	logger.Log.WithField("success", response.Success).
		WithField("failed", response.Failed).
		Info("Bulk group creation completed")

	RespondWithSuccess(c, nethttp.StatusCreated, response)
}

// BulkGroupActions godoc
// @Summary Bulk group actions
// @Description Perform actions on multiple groups (enable/disable)
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.BulkGroupActionsRequest true "Bulk group actions data"
// @Success 200 {object} dto.BulkGroupActionResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/bulk/groups/actions [post]
func (h *BulkHandler) BulkGroupActions(c *gin.Context) {
	var req dto.BulkGroupActionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind bulk group actions request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Bulk group actions request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	logger.Log.WithField("groupCount", len(req.GroupNames)).
		WithField("action", req.Action).
		Info("Processing bulk group actions")

	// Process bulk actions
	response, err := h.bulkUsecase.BulkGroupActions(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Bulk group actions failed", err))
		}
		return
	}

	// Restart OpenVPN service if any actions were successful
	if response.Success > 0 {
		if err := h.xmlrpcClient.RunStart(); err != nil {
			logger.Log.WithError(err).Error("Failed to restart OpenVPN service after bulk group actions")
		}
	}

	logger.Log.WithField("success", response.Success).
		WithField("failed", response.Failed).
		WithField("action", req.Action).
		Info("Bulk group actions completed")

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// ImportGroups godoc
// @Summary Import groups from file
// @Description Import groups from CSV, JSON, or XLSX file
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Groups file (CSV/JSON/XLSX)"
// @Param format formData string false "File format" Enums(csv, json, xlsx)
// @Param dryRun formData boolean false "Dry run mode (validate only)"
// @Param override formData boolean false "Override existing groups"
// @Success 200 {object} dto.ImportResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/bulk/groups/import [post]
func (h *BulkHandler) ImportGroups(c *gin.Context) {
	// Parse multipart form
	if err := c.Request.ParseMultipartForm(16 << 20); err != nil { // 16MB max for groups
		logger.Log.WithError(err).Error("Failed to parse multipart form")
		RespondWithError(c, errors.BadRequest("Failed to parse form data", err))
		return
	}

	var req dto.ImportGroupsRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind import groups request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Import groups request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Auto-detect format if not provided
	if req.Format == "" {
		req.Format = h.detectFileFormat(req.File.Filename)
	}

	dryRunStr := c.PostForm("dryRun")
	req.DryRun, _ = strconv.ParseBool(dryRunStr)

	overrideStr := c.PostForm("override")
	req.Override, _ = strconv.ParseBool(overrideStr)

	logger.Log.WithField("filename", req.File.Filename).
		WithField("format", req.Format).
		WithField("dryRun", req.DryRun).
		WithField("override", req.Override).
		Info("Processing group import")

	// Process file import
	response, err := h.bulkUsecase.ImportGroups(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Group import failed", err))
		}
		return
	}

	// Restart OpenVPN service if groups were actually created (not dry run)
	if !req.DryRun && response.SuccessCount > 0 {
		if err := h.xmlrpcClient.RunStart(); err != nil {
			logger.Log.WithError(err).Error("Failed to restart OpenVPN service after group import")
		}
	}

	logger.Log.WithField("total", response.Total).
		WithField("valid", response.ValidRecords).
		WithField("processed", response.ProcessedRecords).
		WithField("success", response.SuccessCount).
		Info("Group import completed")

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// =================== EXPORT TEMPLATES ===================

// ExportUserTemplate godoc
// @Summary Export user template
// @Description Download template file for user import
// @Tags Bulk Operations
// @Security BearerAuth
// @Produce application/octet-stream
// @Param format query string false "Template format" Enums(csv, xlsx) default(csv)
// @Success 200 {file} file "User template file"
// @Router /api/bulk/users/template [get]
func (h *BulkHandler) ExportUserTemplate(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")

	filename, content, err := h.bulkUsecase.GenerateUserTemplate(format)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to generate template", err))
		}
		return
	}

	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", h.getContentType(format))
	c.Data(nethttp.StatusOK, h.getContentType(format), content)
}

// ExportGroupTemplate godoc
// @Summary Export group template
// @Description Download template file for group import
// @Tags Bulk Operations
// @Security BearerAuth
// @Produce application/octet-stream
// @Param format query string false "Template format" Enums(csv, xlsx) default(csv)
// @Success 200 {file} file "Group template file"
// @Router /api/bulk/groups/template [get]
func (h *BulkHandler) ExportGroupTemplate(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")

	filename, content, err := h.bulkUsecase.GenerateGroupTemplate(format)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to generate template", err))
		}
		return
	}

	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", h.getContentType(format))
	c.Data(nethttp.StatusOK, h.getContentType(format), content)
}

// =================== HELPER METHODS ===================

func (h *BulkHandler) detectFileFormat(filename string) string {
	if len(filename) < 4 {
		return "csv"
	}

	ext := filename[len(filename)-4:]
	switch ext {
	case ".csv":
		return "csv"
	case "json":
		return "json"
	case "xlsx":
		return "xlsx"
	default:
		return "csv"
	}
}

func (h *BulkHandler) getContentType(format string) string {
	switch format {
	case "csv":
		return "text/csv"
	case "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case "json":
		return "application/json"
	default:
		return "text/csv"
	}
}
