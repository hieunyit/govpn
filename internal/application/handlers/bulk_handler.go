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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// =================== ENHANCED BULK HANDLER ===================

// BulkHandler handles bulk operations with comprehensive response system, detailed logging, and advanced error handling
type BulkHandler struct {
	bulkUsecase  usecases.BulkUsecaseInterface
	xmlrpcClient *xmlrpc.Client
	logger       logger.Logger
}

// NewBulkHandler creates a new bulk handler with enhanced response and logging capabilities
func NewBulkHandler(
	bulkUsecase usecases.BulkUsecaseInterface,
	xmlrpcClient *xmlrpc.Client,
) *BulkHandler {
	return &BulkHandler{
		bulkUsecase:  bulkUsecase,
		xmlrpcClient: xmlrpcClient,
		logger:       logger.Log,
	}
}

// =================== BULK USER OPERATIONS ===================

// BulkCreateUsers godoc
// @Summary Create multiple users in batch
// @Description Create multiple VPN users at once with comprehensive validation and detailed progress tracking
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.BulkCreateUsersRequest true "Bulk user creation data with validation options"
// @Success 200 {object} dto.BatchOperationResponse{data=dto.BulkCreateUsersResponse} "Bulk creation completed with detailed results"
// @Success 202 {object} dto.AcceptedResponse "Bulk creation accepted for asynchronous processing"
// @Failure 400 {object} dto.ErrorResponse "Bad request - invalid input data with field validation details"
// @Failure 401 {object} dto.ErrorResponse "Unauthorized - authentication required"
// @Failure 403 {object} dto.ErrorResponse "Forbidden - insufficient permissions for bulk operations"
// @Failure 422 {object} dto.ValidationErrorResponse "Validation failed with detailed field errors"
// @Failure 500 {object} dto.ErrorResponse "Internal server error with comprehensive error tracking"
// @Router /api/bulk/users/create [post]
func (h *BulkHandler) BulkCreateUsers(c *gin.Context) {
	// Set start time for comprehensive performance tracking
	c.Set("start_time", time.Now())

	// Parse and validate bulk creation request with detailed error handling
	var req dto.BulkCreateUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": getOrGenerateRequestID(c),
			"ip":         c.ClientIP(),
			"user_agent": c.GetHeader("User-Agent"),
		}).Error("Failed to bind bulk create users request")

		RespondWithError(c, errors.BadRequest("Invalid bulk creation request format", map[string]interface{}{
			"binding_error":   err.Error(),
			"expected_format": "JSON with users array and optional settings",
			"example": map[string]interface{}{
				"users": []map[string]interface{}{
					{"username": "user1", "email": "user1@example.com", "password": "SecurePass123!"},
					{"username": "user2", "email": "user2@example.com", "password": "SecurePass456!"},
				},
				"dry_run":       false,
				"stop_on_error": false,
			},
		}))
		return
	}

	// Comprehensive validation with detailed field checking
	if err := validator.Validate(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": getOrGenerateRequestID(c),
			"user_count": len(req.Users),
		}).Error("Bulk create users request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Business rule validation for bulk operations
	if len(req.Users) == 0 {
		RespondWithError(c, errors.BadRequest("No users provided for bulk creation", map[string]interface{}{
			"users_count":      0,
			"minimum_required": 1,
			"maximum_allowed":  100,
		}))
		return
	}

	if len(req.Users) > 100 {
		RespondWithError(c, errors.BadRequest("Too many users for bulk creation", map[string]interface{}{
			"users_count":     len(req.Users),
			"maximum_allowed": 100,
			"suggestion":      "Split into smaller batches of 100 or fewer users",
		}))
		return
	}

	// Generate job ID for tracking bulk operation
	jobID := "bulk_create_" + uuid.New().String()

	// Log bulk creation attempt with comprehensive context
	h.logger.WithFields(map[string]interface{}{
		"job_id":        jobID,
		"user_count":    len(req.Users),
		"dry_run":       req.DryRun,
		"stop_on_error": req.StopOnError,
		"request_id":    getOrGenerateRequestID(c),
		"ip":            c.ClientIP(),
		"user_agent":    c.GetHeader("User-Agent"),
	}).Info("Bulk user creation initiated")

	// Convert DTOs to entities with validation
	users := make([]*entities.User, len(req.Users))
	validationErrors := []dto.ImportValidationError{}

	for i, userReq := range req.Users {
		user, validationErr := h.convertCreateUserRequestToEntity(&userReq, i+1)
		if validationErr != nil {
			validationErrors = append(validationErrors, *validationErr)
			if req.StopOnError {
				RespondWithError(c, errors.BadRequest("Validation failed for user data", map[string]interface{}{
					"failed_at_row":     i + 1,
					"validation_errors": validationErrors,
					"stop_on_error":     true,
				}))
				return
			}
			continue
		}
		users[i] = user
	}

	// Handle validation errors in non-strict mode
	if len(validationErrors) > 0 && !req.StopOnError {
		h.logger.WithFields(map[string]interface{}{
			"job_id":            jobID,
			"validation_errors": len(validationErrors),
			"valid_users":       len(users) - len(validationErrors),
		}).Warn("Some users failed validation but continuing with valid users")
	}

	// Perform bulk creation with comprehensive error tracking
	result, err := h.bulkUsecase.BulkCreateUsers(c.Request.Context(), &entities.BulkCreateUsersParams{
		Users:       users,
		DryRun:      req.DryRun,
		StopOnError: req.StopOnError,
		JobID:       jobID,
	})

	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"job_id":     jobID,
			"user_count": len(req.Users),
			"request_id": getOrGenerateRequestID(c),
		}).Error("Bulk user creation failed")

		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Bulk user creation failed", map[string]interface{}{
				"job_id":         jobID,
				"internal_error": err.Error(),
				"context":        "bulk_user_creation",
			}))
		}
		return
	}

	// Convert result to response DTO with comprehensive metadata
	response := h.convertBulkCreateUsersResultToResponse(result, validationErrors)

	// Log successful completion with detailed metrics
	h.logger.WithFields(map[string]interface{}{
		"job_id":            jobID,
		"total_users":       result.Total,
		"successful_users":  result.SuccessCount,
		"failed_users":      result.FailureCount,
		"validation_errors": len(validationErrors),
		"processing_time":   time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
		"dry_run":           req.DryRun,
		"request_id":        getOrGenerateRequestID(c),
	}).Info("Bulk user creation completed")

	// Send comprehensive response with detailed results
	if req.DryRun {
		RespondWithSuccessAndResource(c, nethttp.StatusOK, map[string]interface{}{
			"job_id":          jobID,
			"dry_run_results": response,
			"message":         "Dry run completed successfully - no users were actually created",
			"next_steps":      "Review results and submit without dry_run flag to create users",
		}, "bulk", jobID)
	} else {
		RespondWithBulkOperation(c, jobID, result.Total, result.SuccessCount, result.FailureCount,
			time.Since(c.MustGet("start_time").(time.Time)), response)
	}
}

// ImportUsers godoc
// @Summary Import users from file
// @Description Import users from CSV, Excel, or JSON file with comprehensive validation and progress tracking
// @Tags Bulk Operations
// @Security BearerAuth
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "User data file (CSV, XLSX, or JSON)"
// @Param format formData string false "File format" Enums(csv, xlsx, json) default(csv)
// @Param dry_run formData bool false "Dry run mode - validate only without creating" default(false)
// @Param stop_on_error formData bool false "Stop processing on first error" default(false)
// @Param override formData bool false "Override existing users with same username" default(false)
// @Success 200 {object} dto.BatchOperationResponse{data=dto.ImportResponse} "Import completed with detailed results"
// @Success 202 {object} dto.AcceptedResponse "Import accepted for asynchronous processing"
// @Failure 400 {object} dto.ErrorResponse "Bad request - invalid file or parameters with detailed validation"
// @Failure 401 {object} dto.ErrorResponse "Unauthorized - authentication required"
// @Failure 403 {object} dto.ErrorResponse "Forbidden - insufficient permissions for file import"
// @Failure 413 {object} dto.ErrorResponse "File too large with size limits and suggestions"
// @Failure 422 {object} dto.ValidationErrorResponse "File validation failed with format requirements"
// @Failure 500 {object} dto.ErrorResponse "Internal server error with comprehensive error tracking"
// @Router /api/bulk/users/import [post]
func (h *BulkHandler) ImportUsers(c *gin.Context) {
	// Set start time for comprehensive performance tracking
	c.Set("start_time", time.Now())

	// Parse multipart form with comprehensive error handling
	var req dto.ImportUsersRequest
	if err := c.ShouldBind(&req); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"request_id": getOrGenerateRequestID(c),
			"ip":         c.ClientIP(),
		}).Error("Failed to bind import users request")

		RespondWithError(c, errors.BadRequest("Invalid import request format", map[string]interface{}{
			"binding_error":   err.Error(),
			"expected_format": "multipart/form-data with file and optional parameters",
			"required_fields": []string{"file"},
			"optional_fields": []string{"format", "dry_run", "stop_on_error", "override"},
		}))
		return
	}

	// Validate file upload with detailed checks
	if req.File == nil {
		RespondWithError(c, errors.BadRequest("No file uploaded", map[string]interface{}{
			"required":          "file",
			"supported_formats": []string{"CSV", "Excel (XLSX)", "JSON"},
			"max_file_size":     "10MB",
			"example_headers":   []string{"username", "email", "password", "admin", "group"},
		}))
		return
	}

	// Validate file size with detailed limits
	const maxFileSize = 10 << 20 // 10MB
	if req.File.Size > maxFileSize {
		RespondWithError(c, errors.BadRequest("File too large", map[string]interface{}{
			"file_size_bytes": req.File.Size,
			"max_size_bytes":  maxFileSize,
			"file_size_mb":    float64(req.File.Size) / (1024 * 1024),
			"max_size_mb":     10,
			"suggestions": []string{
				"Split large files into smaller chunks",
				"Remove unnecessary columns",
				"Compress the file if possible",
			},
		}))
		return
	}

	// Detect and validate file format with comprehensive format checking
	detectedFormat := h.detectFileFormat(req.File.Filename)
	if req.Format == "" {
		req.Format = detectedFormat
	}

	validFormats := []string{"csv", "xlsx", "json"}
	if !h.isValidFormat(req.Format, validFormats) {
		RespondWithError(c, errors.BadRequest("Unsupported file format", map[string]interface{}{
			"detected_format":   detectedFormat,
			"provided_format":   req.Format,
			"supported_formats": validFormats,
			"file_extension":    h.getFileExtension(req.File.Filename),
			"format_requirements": map[string]string{
				"csv":  "Comma-separated values with headers",
				"xlsx": "Excel workbook with data in first sheet",
				"json": "JSON array of user objects",
			},
		}))
		return
	}

	// Generate job ID for tracking import operation
	jobID := "import_users_" + uuid.New().String()

	// Log import attempt with comprehensive context
	h.logger.WithFields(map[string]interface{}{
		"job_id":        jobID,
		"file_name":     req.File.Filename,
		"file_size":     req.File.Size,
		"file_format":   req.Format,
		"dry_run":       req.DryRun,
		"stop_on_error": req.StopOnError,
		"override":      req.Override,
		"request_id":    getOrGenerateRequestID(c),
		"ip":            c.ClientIP(),
	}).Info("User import from file initiated")

	// Process file import with comprehensive error handling
	result, err := h.bulkUsecase.ImportUsers(c.Request.Context(), &entities.ImportUsersParams{
		File:        req.File,
		Format:      req.Format,
		DryRun:      req.DryRun,
		StopOnError: req.StopOnError,
		Override:    req.Override,
		JobID:       jobID,
	})

	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"job_id":      jobID,
			"file_name":   req.File.Filename,
			"file_format": req.Format,
			"request_id":  getOrGenerateRequestID(c),
		}).Error("User import from file failed")

		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("User import failed", map[string]interface{}{
				"job_id":         jobID,
				"file_name":      req.File.Filename,
				"internal_error": err.Error(),
				"context":        "file_import_processing",
			}))
		}
		return
	}

	// Convert result to response DTO with comprehensive metadata
	response := h.convertImportResultToResponse(result)

	// Log successful completion with detailed metrics
	h.logger.WithFields(map[string]interface{}{
		"job_id":            jobID,
		"file_name":         req.File.Filename,
		"total_records":     result.Total,
		"valid_records":     result.ValidRecords,
		"invalid_records":   result.InvalidRecords,
		"processed_records": result.ProcessedRecords,
		"success_count":     result.SuccessCount,
		"failure_count":     result.FailureCount,
		"processing_time":   time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
		"dry_run":           req.DryRun,
		"request_id":        getOrGenerateRequestID(c),
	}).Info("User import from file completed")

	// Send comprehensive response with detailed results
	if req.DryRun {
		RespondWithSuccessAndResource(c, nethttp.StatusOK, map[string]interface{}{
			"job_id":          jobID,
			"dry_run_results": response,
			"message":         "Dry run completed successfully - no users were actually imported",
			"file_analysis": map[string]interface{}{
				"file_name":    req.File.Filename,
				"file_size":    req.File.Size,
				"format":       req.Format,
				"total_rows":   result.Total,
				"valid_rows":   result.ValidRecords,
				"invalid_rows": result.InvalidRecords,
			},
			"next_steps": "Review results and submit without dry_run flag to import users",
		}, "import", jobID)
	} else {
		RespondWithBulkOperation(c, jobID, result.Total, result.SuccessCount, result.FailureCount,
			time.Since(c.MustGet("start_time").(time.Time)), response)
	}
}

// ExportUserTemplate godoc
// @Summary Download user import template
// @Description Download a template file for user import with sample data and format specifications
// @Tags Bulk Operations
// @Security BearerAuth
// @Produce application/octet-stream
// @Param format query string false "Template format" Enums(csv, xlsx, json) default(csv)
// @Param include_sample query bool false "Include sample data in template" default(true)
// @Success 200 {file} file "Template file downloaded successfully"
// @Failure 400 {object} dto.ErrorResponse "Bad request - invalid format parameter"
// @Failure 401 {object} dto.ErrorResponse "Unauthorized - authentication required"
// @Failure 500 {object} dto.ErrorResponse "Internal server error - template generation failed"
// @Router /api/bulk/users/template [get]
func (h *BulkHandler) ExportUserTemplate(c *gin.Context) {
	// Set start time for performance tracking
	c.Set("start_time", time.Now())

	// Parse and validate query parameters
	format := c.DefaultQuery("format", "csv")
	includeSampleStr := c.DefaultQuery("include_sample", "true")
	includeSample := includeSampleStr == "true"

	// Validate format parameter
	validFormats := []string{"csv", "xlsx", "json"}
	if !h.isValidFormat(format, validFormats) {
		RespondWithError(c, errors.BadRequest("Invalid template format", map[string]interface{}{
			"provided_format": format,
			"valid_formats":   validFormats,
			"default_format":  "csv",
			"format_descriptions": map[string]string{
				"csv":  "Comma-separated values (most common)",
				"xlsx": "Excel workbook format",
				"json": "JSON array format",
			},
		}))
		return
	}

	// Log template generation request
	h.logger.WithFields(map[string]interface{}{
		"format":         format,
		"include_sample": includeSample,
		"request_id":     getOrGenerateRequestID(c),
		"ip":             c.ClientIP(),
	}).Info("User template generation requested")

	// Generate template with comprehensive error handling
	content, filename, err := h.bulkUsecase.GenerateUserTemplate(c.Request.Context(), &entities.TemplateParams{
		Format:        format,
		IncludeSample: includeSample,
		ResourceType:  "users",
	})

	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"format":     format,
			"request_id": getOrGenerateRequestID(c),
		}).Error("Failed to generate user template")

		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to generate template", map[string]interface{}{
				"format":         format,
				"internal_error": err.Error(),
				"context":        "template_generation",
			}))
		}
		return
	}

	// Log successful template generation
	h.logger.WithFields(map[string]interface{}{
		"format":          format,
		"filename":        filename,
		"content_size":    len(content),
		"include_sample":  includeSample,
		"processing_time": time.Since(c.MustGet("start_time").(time.Time)).Milliseconds(),
		"request_id":      getOrGenerateRequestID(c),
	}).Info("User template generated successfully")

	// Set appropriate headers for file download
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", h.getContentType(format))
	c.Header("Content-Length", strconv.Itoa(len(content)))
	c.Header("X-Generated-At", time.Now().UTC().Format(time.RFC3339))
	c.Header("X-Template-Type", "user_import")
	c.Header("X-Format", format)
	c.Header("X-Include-Sample", strconv.FormatBool(includeSample))

	// Send file content
	c.Data(nethttp.StatusOK, h.getContentType(format), content)
}

// =================== HELPER METHODS ===================

// convertCreateUserRequestToEntity converts create user request to entity with detailed validation
func (h *BulkHandler) convertCreateUserRequestToEntity(req *dto.CreateUserRequest, rowNumber int) (*entities.User, *dto.ImportValidationError) {
	// Validate required fields
	if req.Username == "" {
		return nil, &dto.ImportValidationError{
			Row:     rowNumber,
			Field:   "username",
			Value:   "",
			Message: "Username is required",
		}
	}

	if req.Email == "" {
		return nil, &dto.ImportValidationError{
			Row:     rowNumber,
			Field:   "email",
			Value:   "",
			Message: "Email is required",
		}
	}

	if req.Password == "" {
		return nil, &dto.ImportValidationError{
			Row:     rowNumber,
			Field:   "password",
			Value:   "",
			Message: "Password is required",
		}
	}

	// Validate field formats and constraints
	if len(req.Username) < 3 || len(req.Username) > 32 {
		return nil, &dto.ImportValidationError{
			Row:     rowNumber,
			Field:   "username",
			Value:   req.Username,
			Message: "Username must be between 3 and 32 characters",
		}
	}

	if !h.isValidEmail(req.Email) {
		return nil, &dto.ImportValidationError{
			Row:     rowNumber,
			Field:   "email",
			Value:   req.Email,
			Message: "Invalid email format",
		}
	}

	if len(req.Password) < 8 {
		return nil, &dto.ImportValidationError{
			Row:     rowNumber,
			Field:   "password",
			Value:   "***",
			Message: "Password must be at least 8 characters long",
		}
	}

	// Create user entity
	user := &entities.User{
		Username:  req.Username,
		Email:     req.Email,
		Password:  req.Password,
		Admin:     req.Admin,
		IsActive:  true,
		Group:     req.Group,
		CreatedAt: time.Now().UTC(),
	}

	// Handle expiry date if provided
	if req.ExpiryDate != "" {
		expiryTime, err := time.Parse(time.RFC3339, req.ExpiryDate)
		if err != nil {
			return nil, &dto.ImportValidationError{
				Row:     rowNumber,
				Field:   "expiry_date",
				Value:   req.ExpiryDate,
				Message: "Invalid expiry date format. Use RFC3339 format (2006-01-02T15:04:05Z07:00)",
			}
		}
		user.ExpiryDate = &expiryTime
	}

	return user, nil
}

// convertBulkCreateUsersResultToResponse converts bulk creation result to response DTO
func (h *BulkHandler) convertBulkCreateUsersResultToResponse(result *entities.BulkCreateUsersResult, validationErrors []dto.ImportValidationError) *dto.BulkCreateUsersResponse {
	response := &dto.BulkCreateUsersResponse{
		Total:        result.Total,
		SuccessCount: result.SuccessCount,
		FailureCount: result.FailureCount,
		DryRun:       result.DryRun,
		CreatedUsers: make([]dto.UserResponse, len(result.CreatedUsers)),
		FailedUsers:  make([]dto.FailedUserCreation, len(result.FailedUsers)),
	}

	// Convert created users
	for i, user := range result.CreatedUsers {
		response.CreatedUsers[i] = h.convertUserEntityToResponse(user)
	}

	// Convert failed users
	for i, failed := range result.FailedUsers {
		response.FailedUsers[i] = dto.FailedUserCreation{
			Username: failed.Username,
			Email:    failed.Email,
			Error:    failed.Error,
			Reason:   failed.Reason,
		}
	}

	// Add validation errors if any
	response.ValidationErrors = validationErrors

	return response
}

// convertImportResultToResponse converts import result to response DTO
func (h *BulkHandler) convertImportResultToResponse(result *entities.ImportUsersResult) *dto.ImportResponse {
	return &dto.ImportResponse{
		Total:            result.Total,
		ValidRecords:     result.ValidRecords,
		InvalidRecords:   result.InvalidRecords,
		ProcessedRecords: result.ProcessedRecords,
		SuccessCount:     result.SuccessCount,
		FailureCount:     result.FailureCount,
		DryRun:           result.DryRun,
		ValidationErrors: result.ValidationErrors,
		Results:          result.Results,
	}
}

// convertUserEntityToResponse converts user entity to response DTO
func (h *BulkHandler) convertUserEntityToResponse(user *entities.User) dto.UserResponse {
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

	return response
}

// detectFileFormat detects file format from filename
func (h *BulkHandler) detectFileFormat(filename string) string {
	if len(filename) < 4 {
		return "csv"
	}

	extension := strings.ToLower(filename[len(filename)-4:])
	switch extension {
	case ".csv":
		return "csv"
	case ".xlsx", ".xls":
		return "xlsx"
	case ".json":
		return "json"
	default:
		return "csv"
	}
}

// getFileExtension extracts file extension from filename
func (h *BulkHandler) getFileExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) > 1 {
		return "." + strings.ToLower(parts[len(parts)-1])
	}
	return ""
}

// getContentType returns appropriate content type for file format
func (h *BulkHandler) getContentType(format string) string {
	switch format {
	case "csv":
		return "text/csv"
	case "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case "json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

// isValidFormat checks if the provided format is in the valid formats list
func (h *BulkHandler) isValidFormat(format string, validFormats []string) bool {
	for _, validFormat := range validFormats {
		if format == validFormat {
			return true
		}
	}
	return false
}

// isValidEmail validates email format (basic validation)
func (h *BulkHandler) isValidEmail(email string) bool {
	return len(email) > 0 &&
		len(email) <= 254 &&
		strings.Contains(email, "@") &&
		strings.Contains(email, ".") &&
		!strings.HasPrefix(email, "@") &&
		!strings.HasSuffix(email, "@") &&
		!strings.Contains(email, "..") &&
		!strings.Contains(email, " ")
}

// getOrGenerateRequestID gets or generates request ID for logging
func getOrGenerateRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		return requestID.(string)
	}

	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		return requestID
	}

	return "req_" + uuid.New().String()
}

// =================== ADDITIONAL BULK OPERATIONS (PLACEHOLDER IMPLEMENTATIONS) ===================

// BulkUserActions performs bulk actions on multiple users
func (h *BulkHandler) BulkUserActions(c *gin.Context) {
	RespondWithMessage(c, nethttp.StatusNotImplemented, "Bulk user actions endpoint implementation needed")
}

// BulkExtendUsers extends expiry dates for multiple users
func (h *BulkHandler) BulkExtendUsers(c *gin.Context) {
	RespondWithMessage(c, nethttp.StatusNotImplemented, "Bulk extend users endpoint implementation needed")
}

// ExportUsers exports users to file
func (h *BulkHandler) ExportUsers(c *gin.Context) {
	RespondWithMessage(c, nethttp.StatusNotImplemented, "Export users endpoint implementation needed")
}

// BulkCreateGroups creates multiple groups in batch
func (h *BulkHandler) BulkCreateGroups(c *gin.Context) {
	RespondWithMessage(c, nethttp.StatusNotImplemented, "Bulk create groups endpoint implementation needed")
}

// BulkGroupActions performs bulk actions on multiple groups
func (h *BulkHandler) BulkGroupActions(c *gin.Context) {
	RespondWithMessage(c, nethttp.StatusNotImplemented, "Bulk group actions endpoint implementation needed")
}

// ImportGroups imports groups from file
func (h *BulkHandler) ImportGroups(c *gin.Context) {
	RespondWithMessage(c, nethttp.StatusNotImplemented, "Import groups endpoint implementation needed")
}

// ExportGroupTemplate downloads group import template
func (h *BulkHandler) ExportGroupTemplate(c *gin.Context) {
	RespondWithMessage(c, nethttp.StatusNotImplemented, "Export group template endpoint implementation needed")
}

// ExportGroups exports groups to file
func (h *BulkHandler) ExportGroups(c *gin.Context) {
	RespondWithMessage(c, nethttp.StatusNotImplemented, "Export groups endpoint implementation needed")
}
