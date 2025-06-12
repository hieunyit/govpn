package handlers

import (
	httpPkg "govpn/internal/presentation/http"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// =================== ENHANCED RESPONSE HELPERS ===================

// Common response helper functions for all handlers with comprehensive logging and structured responses

// RespondWithSuccess sends a successful response with enhanced metadata, HATEOAS links, and performance tracking
func RespondWithSuccess(c *gin.Context, status int, data interface{}) {
	// Use the enhanced response system from the http package
	httpPkg.RespondWithSuccess(c, status, data, "", "")
}

// RespondWithSuccessAndResource sends a successful response with resource-specific HATEOAS links
func RespondWithSuccessAndResource(c *gin.Context, status int, data interface{}, resourceType, resourceID string) {
	httpPkg.RespondWithSuccess(c, status, data, resourceType, resourceID)
}

// RespondWithMessage sends a message-only response with enhanced logging
func RespondWithMessage(c *gin.Context, status int, message string) {
	httpPkg.RespondWithMessage(c, status, message)
}

// RespondWithPaginated sends a paginated response with comprehensive metadata and navigation links
func RespondWithPaginated(c *gin.Context, data interface{}, page, perPage, total int) {
	httpPkg.RespondWithPaginated(c, data, page, perPage, total)
}

// RespondWithError sends an error response with comprehensive error details and suggestions
func RespondWithError(c *gin.Context, err *errors.AppError) {
	httpPkg.RespondWithError(c, err)
}

// RespondWithValidationError sends a validation error response with field-specific details
func RespondWithValidationError(c *gin.Context, err error) {
	httpPkg.RespondWithValidationError(c, err)
}

// =================== ENHANCED ERROR RESPONSE HELPERS ===================

// RespondWithBadRequest sends a bad request error response with detailed context
func RespondWithBadRequest(c *gin.Context, message string, details interface{}) {
	httpPkg.RespondWithError(c, errors.BadRequest(message, details))
}

// RespondWithUnauthorized sends an unauthorized error response with authentication guidance
func RespondWithUnauthorized(c *gin.Context, message string, details interface{}) {
	httpPkg.RespondWithError(c, errors.Unauthorized(message, details))
}

// RespondWithForbidden sends a forbidden error response with authorization guidance
func RespondWithForbidden(c *gin.Context, message string, details interface{}) {
	httpPkg.RespondWithError(c, errors.Forbidden(message, details))
}

// RespondWithNotFound sends a not found error response with search suggestions
func RespondWithNotFound(c *gin.Context, message string, details interface{}) {
	httpPkg.RespondWithError(c, errors.NotFound(message, details))
}

// RespondWithConflict sends a conflict error response with resolution guidance
func RespondWithConflict(c *gin.Context, message string, details interface{}) {
	httpPkg.RespondWithError(c, errors.Conflict(message, details))
}

// RespondWithInternalServerError sends an internal server error response with support information
func RespondWithInternalServerError(c *gin.Context, message string, details interface{}) {
	httpPkg.RespondWithError(c, errors.InternalServerError(message, details))
}

// =================== SPECIALIZED RESPONSE HELPERS ===================

// RespondWithCreated sends a 201 Created response with location header and resource links
func RespondWithCreated(c *gin.Context, data interface{}, resourceType, resourceID string) {
	startTime, exists := c.Get("start_time")
	var duration time.Duration
	if exists {
		duration = time.Since(startTime.(time.Time))
	}

	// Log creation success with comprehensive context
	logger.Log.WithFields(map[string]interface{}{
		"status":        http.StatusCreated,
		"resource_type": resourceType,
		"resource_id":   resourceID,
		"response_time": duration.Milliseconds(),
		"request_id":    httpPkg.getOrGenerateRequestID(c),
		"ip":            c.ClientIP(),
	}).Info("Resource created successfully")

	httpPkg.RespondWithSuccess(c, http.StatusCreated, data, resourceType, resourceID)
}

// RespondWithUpdated sends a 200 OK response for successful updates with change tracking
func RespondWithUpdated(c *gin.Context, data interface{}, changes map[string]interface{}, resourceType, resourceID string) {
	startTime, exists := c.Get("start_time")
	var duration time.Duration
	if exists {
		duration = time.Since(startTime.(time.Time))
	}

	// Log update success with change details
	logger.Log.WithFields(map[string]interface{}{
		"status":        http.StatusOK,
		"resource_type": resourceType,
		"resource_id":   resourceID,
		"changes_made":  changes,
		"response_time": duration.Milliseconds(),
		"request_id":    httpPkg.getOrGenerateRequestID(c),
		"ip":            c.ClientIP(),
	}).Info("Resource updated successfully")

	responseData := map[string]interface{}{
		"resource":   data,
		"changes":    changes,
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}

	httpPkg.RespondWithSuccess(c, http.StatusOK, responseData, resourceType, resourceID)
}

// RespondWithDeleted sends a 200 OK response for successful deletions with confirmation
func RespondWithDeleted(c *gin.Context, resourceType, resourceID string, deletedData interface{}) {
	startTime, exists := c.Get("start_time")
	var duration time.Duration
	if exists {
		duration = time.Since(startTime.(time.Time))
	}

	// Log deletion success with comprehensive context
	logger.Log.WithFields(map[string]interface{}{
		"status":        http.StatusOK,
		"resource_type": resourceType,
		"resource_id":   resourceID,
		"response_time": duration.Milliseconds(),
		"request_id":    httpPkg.getOrGenerateRequestID(c),
		"ip":            c.ClientIP(),
	}).Warn("Resource deleted successfully")

	responseData := map[string]interface{}{
		"deleted_resource": deletedData,
		"confirmation":     "Resource has been permanently deleted",
		"deleted_at":       time.Now().UTC().Format(time.RFC3339),
		"note":             "This action cannot be undone",
	}

	httpPkg.RespondWithSuccess(c, http.StatusOK, responseData, resourceType, "")
}

// =================== BULK OPERATION RESPONSE HELPERS ===================

// RespondWithBulkOperation sends a response for bulk operations with comprehensive results
func RespondWithBulkOperation(c *gin.Context, jobID string, total, successful, failed int, processingTime time.Duration, results interface{}) {
	startTime, exists := c.Get("start_time")
	var duration time.Duration
	if exists {
		duration = time.Since(startTime.(time.Time))
	}

	// Log bulk operation completion with detailed metrics
	logger.Log.WithFields(map[string]interface{}{
		"job_id":           jobID,
		"total_items":      total,
		"successful_items": successful,
		"failed_items":     failed,
		"success_rate":     float64(successful) / float64(total) * 100,
		"processing_time":  processingTime.Milliseconds(),
		"response_time":    duration.Milliseconds(),
		"request_id":       httpPkg.getOrGenerateRequestID(c),
	}).Info("Bulk operation completed")

	responseData := map[string]interface{}{
		"job_id":          jobID,
		"total":           total,
		"successful":      successful,
		"failed":          failed,
		"skipped":         total - successful - failed,
		"success_rate":    float64(successful) / float64(total) * 100,
		"processing_time": processingTime.String(),
		"results":         results,
		"completed_at":    time.Now().UTC().Format(time.RFC3339),
	}

	if failed > 0 {
		responseData["download_url"] = "/api/jobs/" + jobID + "/results"
		responseData["note"] = "Some items failed to process. Check the results for details."
	}

	httpPkg.RespondWithSuccess(c, http.StatusOK, responseData, "bulk", jobID)
}

// RespondWithFileUpload sends a response for successful file uploads
func RespondWithFileUpload(c *gin.Context, fileName string, fileSize int64, processingID string) {
	responseData := map[string]interface{}{
		"file_name":     fileName,
		"file_size":     fileSize,
		"uploaded_at":   time.Now().UTC().Format(time.RFC3339),
		"processing_id": processingID,
		"status":        "uploaded",
		"next_step":     "File is being processed. Check processing status using the processing_id.",
	}

	logger.Log.WithFields(map[string]interface{}{
		"file_name":     fileName,
		"file_size":     fileSize,
		"processing_id": processingID,
		"request_id":    httpPkg.getOrGenerateRequestID(c),
		"ip":            c.ClientIP(),
	}).Info("File uploaded successfully")

	httpPkg.RespondWithSuccess(c, http.StatusOK, responseData, "file", processingID)
}

// RespondWithFileExport sends a response for successful file exports
func RespondWithFileExport(c *gin.Context, downloadURL, fileName string, recordCount int) {
	responseData := map[string]interface{}{
		"download_url": downloadURL,
		"file_name":    fileName,
		"record_count": recordCount,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"expires_at":   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"format":       "csv", // Could be dynamic
		"instructions": "Click the download_url to download the file. Link expires in 24 hours.",
	}

	logger.Log.WithFields(map[string]interface{}{
		"download_url": downloadURL,
		"file_name":    fileName,
		"record_count": recordCount,
		"request_id":   httpPkg.getOrGenerateRequestID(c),
	}).Info("File export generated successfully")

	httpPkg.RespondWithSuccess(c, http.StatusOK, responseData, "export", fileName)
}

// =================== SEARCH RESPONSE HELPERS ===================

// RespondWithSearchResults sends a response for search operations with facets and suggestions
func RespondWithSearchResults(c *gin.Context, results interface{}, total int, query string, facets map[string]interface{}, suggestions []string) {
	responseData := map[string]interface{}{
		"results":     results,
		"total":       total,
		"query":       query,
		"facets":      facets,
		"suggestions": suggestions,
		"search_time": time.Now().UTC().Format(time.RFC3339),
	}

	if total == 0 {
		responseData["message"] = "No results found for your search query"
		responseData["help"] = []string{
			"Try different search terms",
			"Check spelling",
			"Use broader search criteria",
			"Remove some filters",
		}
	}

	logger.Log.WithFields(map[string]interface{}{
		"query":           query,
		"total_results":   total,
		"has_facets":      len(facets) > 0,
		"has_suggestions": len(suggestions) > 0,
		"request_id":      httpPkg.getOrGenerateRequestID(c),
	}).Info("Search completed")

	httpPkg.RespondWithSuccess(c, http.StatusOK, responseData, "search", "")
}

// =================== ACTION RESPONSE HELPERS ===================

// RespondWithActionResult sends a response for action operations (enable, disable, etc.)
func RespondWithActionResult(c *gin.Context, action string, success bool, message string, resourceData interface{}) {
	responseData := map[string]interface{}{
		"action":    action,
		"success":   success,
		"message":   message,
		"resource":  resourceData,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	status := http.StatusOK
	if !success {
		status = http.StatusBadRequest
	}

	logger.Log.WithFields(map[string]interface{}{
		"action":     action,
		"success":    success,
		"message":    message,
		"request_id": httpPkg.getOrGenerateRequestID(c),
	}).Info("Action completed")

	httpPkg.RespondWithSuccess(c, status, responseData, "action", action)
}

// =================== AUTHENTICATION RESPONSE HELPERS ===================

// RespondWithAuthSuccess sends a response for successful authentication with security context
func RespondWithAuthSuccess(c *gin.Context, tokenData interface{}, userInfo interface{}) {
	responseData := map[string]interface{}{
		"tokens":    tokenData,
		"user":      userInfo,
		"issued_at": time.Now().UTC().Format(time.RFC3339),
		"security": map[string]interface{}{
			"token_type":        "Bearer",
			"secure_connection": c.GetHeader("X-Forwarded-Proto") == "https",
			"ip_address":        c.ClientIP(),
		},
	}

	logger.Log.WithFields(map[string]interface{}{
		"event":      "authentication_success",
		"ip":         c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"request_id": httpPkg.getOrGenerateRequestID(c),
	}).Info("Authentication successful")

	httpPkg.RespondWithSuccess(c, http.StatusOK, responseData, "auth", "login")
}

// RespondWithAuthError sends a response for authentication errors with security guidance
func RespondWithAuthError(c *gin.Context, errorCode, message string, securityDetails interface{}) {
	authError := errors.Unauthorized(message, map[string]interface{}{
		"error_code":       errorCode,
		"security_details": securityDetails,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"help": []string{
			"Verify your credentials",
			"Check if your account is locked",
			"Contact support if issues persist",
		},
	})

	logger.Log.WithFields(map[string]interface{}{
		"event":      "authentication_failed",
		"error_code": errorCode,
		"ip":         c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"request_id": httpPkg.getOrGenerateRequestID(c),
	}).Warn("Authentication failed")

	httpPkg.RespondWithError(c, authError)
}

// =================== VALIDATION HELPERS ===================

// RespondWithValidationErrors sends detailed validation error responses
func RespondWithValidationErrors(c *gin.Context, fieldErrors map[string]string, generalMessage string) {
	validationError := map[string]interface{}{
		"message":      generalMessage,
		"field_errors": fieldErrors,
		"error_count":  len(fieldErrors),
		"help": []string{
			"Fix the validation errors listed above",
			"Ensure all required fields are provided",
			"Check field formats and constraints",
		},
	}

	logger.Log.WithFields(map[string]interface{}{
		"validation_errors": len(fieldErrors),
		"failed_fields":     getFieldNames(fieldErrors),
		"request_id":        httpPkg.getOrGenerateRequestID(c),
	}).Warn("Validation failed")

	httpPkg.RespondWithError(c, errors.BadRequest("Validation failed", validationError))
}

// =================== UTILITY FUNCTIONS ===================

// getFieldNames extracts field names from error map for logging
func getFieldNames(fieldErrors map[string]string) []string {
	var names []string
	for field := range fieldErrors {
		names = append(names, field)
	}
	return names
}

// calculateResponseTime calculates response time from start time in context
func calculateResponseTime(c *gin.Context) time.Duration {
	if startTime, exists := c.Get("start_time"); exists {
		return time.Since(startTime.(time.Time))
	}
	return 0
}

// addSecurityHeaders adds security-related headers to responses
func addSecurityHeaders(c *gin.Context) {
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("X-XSS-Protection", "1; mode=block")
}

// =================== LEGACY COMPATIBILITY ===================

// Maintain backward compatibility with existing code while providing enhanced functionality

// respondWithSuccess - lowercase version for internal package use (legacy compatibility)
func respondWithSuccess(c *gin.Context, status int, data interface{}) {
	RespondWithSuccess(c, status, data)
}

// respondWithMessage - lowercase version for internal package use (legacy compatibility)
func respondWithMessage(c *gin.Context, status int, message string) {
	RespondWithMessage(c, status, message)
}

// respondWithError - lowercase version for internal package use (legacy compatibility)
func respondWithError(c *gin.Context, err *errors.AppError) {
	RespondWithError(c, err)
}

// respondWithValidationError - lowercase version for internal package use (legacy compatibility)
func respondWithValidationError(c *gin.Context, err error) {
	RespondWithValidationError(c, err)
}
