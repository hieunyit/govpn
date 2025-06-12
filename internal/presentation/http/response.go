package http

import (
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// =================== STANDARDIZED RESPONSE SYSTEM ===================

// BaseResponse provides common metadata for all API responses
type BaseResponse struct {
	Timestamp string `json:"timestamp" example:"2024-01-01T12:00:00Z"`         // RFC3339 timestamp
	RequestID string `json:"request_id" example:"req_123e4567-e89b-12d3-a456"` // Unique request identifier
	Version   string `json:"version" example:"1.1.0"`                          // API version
	Path      string `json:"path" example:"/api/users"`                        // Request path
	Method    string `json:"method" example:"POST"`                            // HTTP method
}

// SuccessResponse represents a successful API response with HATEOAS links
type SuccessResponse struct {
	BaseResponse
	Success struct {
		Status   int           `json:"status" example:"200"`                             // HTTP status code
		Data     interface{}   `json:"data,omitempty"`                                   // Response data
		Message  string        `json:"message,omitempty" example:"Operation successful"` // Success message
		Links    []HATEOASLink `json:"links,omitempty"`                                  // HATEOAS navigation links
		Metadata interface{}   `json:"metadata,omitempty"`                               // Additional metadata
	} `json:"success"`
}

// ErrorResponse represents an error API response with detailed information
type ErrorResponse struct {
	BaseResponse
	Error struct {
		Code        string      `json:"code" example:"BAD_REQUEST"`                                   // Error code
		Message     string      `json:"message" example:"Invalid request format"`                     // Human-readable message
		Status      int         `json:"status" example:"400"`                                         // HTTP status code
		Details     interface{} `json:"details,omitempty"`                                            // Detailed error info
		Severity    string      `json:"severity" example:"error"`                                     // error, warning, info
		Suggestions []string    `json:"suggestions,omitempty"`                                        // Fix suggestions
		HelpURL     string      `json:"help_url,omitempty" example:"https://docs.api.com/errors/400"` // Documentation link
		TraceID     string      `json:"trace_id,omitempty" example:"trace_123e4567"`                  // Error trace ID
	} `json:"error"`
}

// ValidationErrorResponse for validation errors with field-specific details
type ValidationErrorResponse struct {
	BaseResponse
	Error struct {
		Code        string            `json:"code" example:"VALIDATION_ERROR"`
		Message     string            `json:"message" example:"Validation failed"`
		Status      int               `json:"status" example:"422"`
		Fields      map[string]string `json:"fields"` // Field-specific errors
		Suggestions []string          `json:"suggestions,omitempty"`
		HelpURL     string            `json:"help_url,omitempty"`
		TraceID     string            `json:"trace_id,omitempty"`
	} `json:"error"`
}

// PaginatedResponse for paginated data with comprehensive metadata
type PaginatedResponse struct {
	BaseResponse
	Success struct {
		Status     int                `json:"status" example:"200"`
		Data       interface{}        `json:"data"`            // Array of items
		Links      []HATEOASLink      `json:"links,omitempty"` // Navigation links
		Pagination PaginationMetadata `json:"pagination"`      // Pagination details
	} `json:"success"`
}

// PaginationMetadata contains comprehensive pagination information
type PaginationMetadata struct {
	Page        int  `json:"page" example:"1"`                // Current page (1-based)
	PerPage     int  `json:"per_page" example:"20"`           // Items per page
	Total       int  `json:"total" example:"150"`             // Total items
	TotalPages  int  `json:"total_pages" example:"8"`         // Total pages
	HasNext     bool `json:"has_next" example:"true"`         // Has next page
	HasPrevious bool `json:"has_previous" example:"false"`    // Has previous page
	NextPage    *int `json:"next_page,omitempty" example:"2"` // Next page number
	PrevPage    *int `json:"prev_page,omitempty"`             // Previous page number
	FirstPage   int  `json:"first_page" example:"1"`          // First page number
	LastPage    int  `json:"last_page" example:"8"`           // Last page number
}

// HATEOASLink represents a hypermedia link
type HATEOASLink struct {
	Rel    string `json:"rel" example:"self"`                         // Relationship
	Href   string `json:"href" example:"/api/users/testuser"`         // URL
	Method string `json:"method" example:"GET"`                       // HTTP method
	Title  string `json:"title,omitempty" example:"Get user details"` // Human-readable title
}

// =================== RESPONSE HELPER FUNCTIONS ===================

// getOrGenerateRequestID retrieves or generates a request ID
func getOrGenerateRequestID(c *gin.Context) string {
	if requestID := c.GetString("request_id"); requestID != "" {
		return requestID
	}

	// Try to get from header
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		c.Set("request_id", requestID)
		return requestID
	}

	// Generate new UUID
	requestID := "req_" + uuid.New().String()
	c.Set("request_id", requestID)
	return requestID
}

// createBaseResponse creates base response with request metadata
func createBaseResponse(c *gin.Context) BaseResponse {
	return BaseResponse{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getOrGenerateRequestID(c),
		Version:   "1.1.0", // Should come from config
		Path:      c.Request.URL.Path,
		Method:    c.Request.Method,
	}
}

// createHATEOASLinks generates navigation links for the resource
func createHATEOASLinks(c *gin.Context, resourceType, resourceID string) []HATEOASLink {
	var links []HATEOASLink

	switch resourceType {
	case "user":
		if resourceID != "" {
			links = append(links,
				HATEOASLink{Rel: "self", Href: "/api/users/" + resourceID, Method: "GET", Title: "Get user details"},
				HATEOASLink{Rel: "update", Href: "/api/users/" + resourceID, Method: "PUT", Title: "Update user"},
				HATEOASLink{Rel: "delete", Href: "/api/users/" + resourceID, Method: "DELETE", Title: "Delete user"},
			)
		}
		links = append(links,
			HATEOASLink{Rel: "collection", Href: "/api/users", Method: "GET", Title: "List all users"},
			HATEOASLink{Rel: "create", Href: "/api/users", Method: "POST", Title: "Create new user"},
		)

	case "group":
		if resourceID != "" {
			links = append(links,
				HATEOASLink{Rel: "self", Href: "/api/groups/" + resourceID, Method: "GET", Title: "Get group details"},
				HATEOASLink{Rel: "update", Href: "/api/groups/" + resourceID, Method: "PUT", Title: "Update group"},
				HATEOASLink{Rel: "delete", Href: "/api/groups/" + resourceID, Method: "DELETE", Title: "Delete group"},
			)
		}
		links = append(links,
			HATEOASLink{Rel: "collection", Href: "/api/groups", Method: "GET", Title: "List all groups"},
			HATEOASLink{Rel: "create", Href: "/api/groups", Method: "POST", Title: "Create new group"},
		)
	}

	return links
}

// calculatePagination calculates pagination metadata
func calculatePagination(page, perPage, total int) PaginationMetadata {
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}

	metadata := PaginationMetadata{
		Page:        page,
		PerPage:     perPage,
		Total:       total,
		TotalPages:  totalPages,
		HasNext:     page < totalPages,
		HasPrevious: page > 1,
		FirstPage:   1,
		LastPage:    totalPages,
	}

	if metadata.HasNext {
		nextPage := page + 1
		metadata.NextPage = &nextPage
	}

	if metadata.HasPrevious {
		prevPage := page - 1
		metadata.PrevPage = &prevPage
	}

	return metadata
}

// generateTraceID creates a unique trace ID for error tracking
func generateTraceID() string {
	return "trace_" + uuid.New().String()
}

// logRequestResponse logs request and response details with performance metrics
func logRequestResponse(c *gin.Context, responseType string, status int, err error) {
	startTime, exists := c.Get("start_time")
	var duration time.Duration
	if exists {
		duration = time.Since(startTime.(time.Time))
	}

	requestID := getOrGenerateRequestID(c)

	logFields := map[string]interface{}{
		"request_id":    requestID,
		"method":        c.Request.Method,
		"path":          c.Request.URL.Path,
		"status":        status,
		"response_type": responseType,
		"response_time": duration.Milliseconds(),
		"user_agent":    c.GetHeader("User-Agent"),
		"ip":            c.ClientIP(),
	}

	// Add user context if available
	if username, exists := c.Get("username"); exists {
		logFields["username"] = username
	}

	if role, exists := c.Get("role"); exists {
		logFields["role"] = role
	}

	if err != nil {
		logFields["error"] = err.Error()
		if appErr, ok := err.(*errors.AppError); ok {
			logFields["error_code"] = appErr.Code
		}
		logger.Log.WithFields(logFields).Error("API response with error")
	} else {
		logger.Log.WithFields(logFields).Info("API response successful")
	}

	// Log performance warning for slow requests
	if duration > time.Second*5 {
		logger.Log.WithFields(logFields).Warn("Slow API response detected")
	}
}

// =================== ENHANCED RESPONSE FUNCTIONS ===================

// RespondWithSuccess sends a successful response with enhanced metadata and HATEOAS links
func RespondWithSuccess(c *gin.Context, status int, data interface{}, resourceType, resourceID string) {
	response := SuccessResponse{
		BaseResponse: createBaseResponse(c),
	}

	response.Success.Status = status
	response.Success.Data = data
	response.Success.Links = createHATEOASLinks(c, resourceType, resourceID)

	// Add performance metadata
	startTime, exists := c.Get("start_time")
	if exists {
		response.Success.Metadata = map[string]interface{}{
			"response_time_ms": time.Since(startTime.(time.Time)).Milliseconds(),
		}
	}

	// Log successful response
	logRequestResponse(c, "success", status, nil)

	c.JSON(status, response)
}

// RespondWithMessage sends a message-only response
func RespondWithMessage(c *gin.Context, status int, message string) {
	response := SuccessResponse{
		BaseResponse: createBaseResponse(c),
	}

	response.Success.Status = status
	response.Success.Message = message

	// Log message response
	logRequestResponse(c, "message", status, nil)

	c.JSON(status, response)
}

// RespondWithPaginated sends a paginated response
func RespondWithPaginated(c *gin.Context, data interface{}, page, perPage, total int) {
	response := PaginatedResponse{
		BaseResponse: createBaseResponse(c),
	}

	response.Success.Status = http.StatusOK
	response.Success.Data = data
	response.Success.Pagination = calculatePagination(page, perPage, total)

	// Create pagination navigation links
	basePath := c.Request.URL.Path
	var links []HATEOASLink

	// Self link
	links = append(links, HATEOASLink{
		Rel:    "self",
		Href:   basePath + "?page=" + string(rune(page)) + "&per_page=" + string(rune(perPage)),
		Method: "GET",
		Title:  "Current page",
	})

	// Previous/Next links
	if response.Success.Pagination.HasPrevious {
		links = append(links, HATEOASLink{
			Rel:    "prev",
			Href:   basePath + "?page=" + string(rune(page-1)) + "&per_page=" + string(rune(perPage)),
			Method: "GET",
			Title:  "Previous page",
		})
	}

	if response.Success.Pagination.HasNext {
		links = append(links, HATEOASLink{
			Rel:    "next",
			Href:   basePath + "?page=" + string(rune(page+1)) + "&per_page=" + string(rune(perPage)),
			Method: "GET",
			Title:  "Next page",
		})
	}

	response.Success.Links = links

	// Log paginated response
	logger.Log.WithFields(map[string]interface{}{
		"request_id":  getOrGenerateRequestID(c),
		"total_items": total,
		"page":        page,
		"per_page":    perPage,
		"total_pages": response.Success.Pagination.TotalPages,
	}).Info("Paginated API response")

	c.JSON(http.StatusOK, response)
}

// RespondWithError sends an error response with enhanced error details
func RespondWithError(c *gin.Context, err *errors.AppError) {
	traceID := generateTraceID()

	response := ErrorResponse{
		BaseResponse: createBaseResponse(c),
	}

	response.Error.Code = err.Code
	response.Error.Message = err.Message
	response.Error.Status = err.Status
	response.Error.Details = err.Details
	response.Error.TraceID = traceID

	// Add error severity and suggestions based on status code
	switch {
	case err.Status >= 500:
		response.Error.Severity = "critical"
		response.Error.Suggestions = []string{"Retry the request", "Contact support if problem persists"}
		response.Error.HelpURL = "https://docs.api.com/errors/500"
	case err.Status >= 400:
		response.Error.Severity = "error"
		if err.Status == 400 {
			response.Error.Suggestions = []string{"Check request format and syntax", "Verify all required fields are present"}
			response.Error.HelpURL = "https://docs.api.com/errors/400"
		} else if err.Status == 401 {
			response.Error.Suggestions = []string{"Provide valid authentication token", "Check token expiration"}
			response.Error.HelpURL = "https://docs.api.com/authentication"
		} else if err.Status == 403 {
			response.Error.Suggestions = []string{"Contact administrator for permissions", "Verify user role requirements"}
			response.Error.HelpURL = "https://docs.api.com/authorization"
		} else if err.Status == 404 {
			response.Error.Suggestions = []string{"Verify resource identifier", "Check if resource was deleted"}
			response.Error.HelpURL = "https://docs.api.com/resources"
		} else if err.Status == 409 {
			response.Error.Suggestions = []string{"Check resource current state", "Resolve conflicts before retrying"}
			response.Error.HelpURL = "https://docs.api.com/conflicts"
		}
	default:
		response.Error.Severity = "warning"
	}

	// Log error response
	logRequestResponse(c, "error", err.Status, err)

	c.JSON(err.Status, response)
}

// RespondWithValidationError sends a validation error response
func RespondWithValidationError(c *gin.Context, err error) {
	traceID := generateTraceID()

	response := ValidationErrorResponse{
		BaseResponse: createBaseResponse(c),
	}

	response.Error.Code = "VALIDATION_ERROR"
	response.Error.Message = "Validation failed"
	response.Error.Status = http.StatusUnprocessableEntity
	response.Error.Fields = extractValidationErrors(err)
	response.Error.Suggestions = []string{"Check field validation requirements", "Verify data formats", "Review field constraints"}
	response.Error.HelpURL = "https://docs.api.com/validation"
	response.Error.TraceID = traceID

	// Log validation error with field details
	logger.Log.WithFields(map[string]interface{}{
		"request_id":    getOrGenerateRequestID(c),
		"error":         err.Error(),
		"failed_fields": getFieldNames(response.Error.Fields),
		"trace_id":      traceID,
	}).Warn("Validation error in API request")

	c.JSON(http.StatusUnprocessableEntity, response)
}

// =================== BACKWARD COMPATIBILITY FUNCTIONS ===================

// Keep existing function names for backward compatibility but enhance them

// RespondWithBadRequest sends a bad request error response
func RespondWithBadRequest(c *gin.Context, message string) {
	RespondWithError(c, errors.BadRequest(message, nil))
}

// RespondWithUnauthorized sends an unauthorized error response
func RespondWithUnauthorized(c *gin.Context, message string) {
	RespondWithError(c, errors.Unauthorized(message, nil))
}

// RespondWithForbidden sends a forbidden error response
func RespondWithForbidden(c *gin.Context, message string) {
	RespondWithError(c, errors.Forbidden(message, nil))
}

// RespondWithConflict sends a conflict error response
func RespondWithConflict(c *gin.Context, message string) {
	RespondWithError(c, errors.Conflict(message, nil))
}

// =================== HELPER FUNCTIONS ===================

// extractValidationErrors extracts field-specific validation errors
func extractValidationErrors(err error) map[string]string {
	fieldErrors := make(map[string]string)

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, fieldError := range validationErrors {
			fieldName := strings.ToLower(fieldError.Field())
			fieldErrors[fieldName] = formatValidationError(fieldError)
		}
	} else {
		fieldErrors["general"] = err.Error()
	}

	return fieldErrors
}

// formatValidationError formats a validation error into human-readable message
func formatValidationError(fieldError validator.FieldError) string {
	field := fieldError.Field()
	tag := fieldError.Tag()
	param := fieldError.Param()

	switch tag {
	case "required":
		return field + " is required"
	case "email":
		return field + " must be a valid email address"
	case "min":
		return field + " must be at least " + param + " characters"
	case "max":
		return field + " must not exceed " + param + " characters"
	case "oneof":
		return field + " must be one of: " + param
	default:
		return field + " failed " + tag + " validation"
	}
}

// getFieldNames extracts field names from validation errors for logging
func getFieldNames(fields map[string]string) []string {
	var names []string
	for field := range fields {
		names = append(names, field)
	}
	return names
}
