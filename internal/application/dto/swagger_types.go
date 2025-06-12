package dto

// =================== ENHANCED SWAGGER RESPONSE TYPES ===================

// BaseResponse provides common metadata for all API responses
type BaseResponse struct {
	Timestamp string `json:"timestamp" example:"2024-01-01T12:00:00Z"`         // RFC3339 timestamp
	RequestID string `json:"request_id" example:"req_123e4567-e89b-12d3-a456"` // Unique request identifier
	Version   string `json:"version" example:"1.1.0"`                          // API version
	Path      string `json:"path" example:"/api/users"`                        // Request path
	Method    string `json:"method" example:"POST"`                            // HTTP method
}

// HATEOASLink represents a hypermedia link for API navigation
type HATEOASLink struct {
	Rel    string `json:"rel" example:"self"`                         // Relationship type
	Href   string `json:"href" example:"/api/users/testuser"`         // URL
	Method string `json:"method" example:"GET"`                       // HTTP method
	Title  string `json:"title,omitempty" example:"Get user details"` // Human-readable title
}

// =================== SUCCESS RESPONSE TYPES ===================

// SuccessResponse represents a successful API response with enhanced metadata
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

// CreatedResponse for 201 Created responses with location information
type CreatedResponse struct {
	BaseResponse
	Success struct {
		Status   int           `json:"status" example:"201"`
		Data     interface{}   `json:"data"` // Created resource data
		Message  string        `json:"message" example:"Resource created successfully"`
		Links    []HATEOASLink `json:"links,omitempty"`                                  // Navigation links
		Location string        `json:"location,omitempty" example:"/api/users/testuser"` // Resource location
	} `json:"success"`
}

// AcceptedResponse for 202 Accepted responses (async operations)
type AcceptedResponse struct {
	BaseResponse
	Success struct {
		Status              int           `json:"status" example:"202"`
		Message             string        `json:"message" example:"Request accepted for processing"`
		JobID               string        `json:"job_id" example:"job_123e4567"` // Async job identifier
		Links               []HATEOASLink `json:"links,omitempty"`               // Status checking links
		EstimatedCompletion string        `json:"estimated_completion,omitempty" example:"2024-01-01T12:05:00Z"`
	} `json:"success"`
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	BaseResponse
	Success struct {
		Status  int    `json:"status" example:"200"`
		Message string `json:"message" example:"Operation completed successfully"`
	} `json:"success"`
}

// =================== PAGINATED RESPONSE TYPES ===================

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

// =================== ERROR RESPONSE TYPES ===================

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
		Code        string              `json:"code" example:"VALIDATION_ERROR"`
		Message     string              `json:"message" example:"Validation failed"`
		Status      int                 `json:"status" example:"422"`
		Fields      map[string]string   `json:"fields"`                // Field-specific errors
		Constraints map[string][]string `json:"constraints,omitempty"` // Validation constraints
		Suggestions []string            `json:"suggestions,omitempty"` // Fix suggestions
		HelpURL     string              `json:"help_url,omitempty" example:"https://docs.api.com/validation"`
		TraceID     string              `json:"trace_id,omitempty" example:"trace_123e4567"`
	} `json:"error"`
}

// ConflictErrorResponse for 409 Conflict errors
type ConflictErrorResponse struct {
	BaseResponse
	Error struct {
		Code          string      `json:"code" example:"RESOURCE_CONFLICT"`
		Message       string      `json:"message" example:"Resource already exists"`
		Status        int         `json:"status" example:"409"`
		ConflictsWith interface{} `json:"conflicts_with,omitempty"` // What it conflicts with
		Suggestions   []string    `json:"suggestions,omitempty"`    // Resolution suggestions
		HelpURL       string      `json:"help_url,omitempty" example:"https://docs.api.com/conflicts"`
		TraceID       string      `json:"trace_id,omitempty" example:"trace_123e4567"`
	} `json:"error"`
}

// UnauthorizedErrorResponse for 401 Unauthorized errors
type UnauthorizedErrorResponse struct {
	BaseResponse
	Error struct {
		Code        string   `json:"code" example:"UNAUTHORIZED"`
		Message     string   `json:"message" example:"Authentication required"`
		Status      int      `json:"status" example:"401"`
		AuthScheme  string   `json:"auth_scheme,omitempty" example:"Bearer"`
		Suggestions []string `json:"suggestions,omitempty"`
		HelpURL     string   `json:"help_url,omitempty" example:"https://docs.api.com/authentication"`
		TraceID     string   `json:"trace_id,omitempty" example:"trace_123e4567"`
	} `json:"error"`
}

// ForbiddenErrorResponse for 403 Forbidden errors
type ForbiddenErrorResponse struct {
	BaseResponse
	Error struct {
		Code         string   `json:"code" example:"FORBIDDEN"`
		Message      string   `json:"message" example:"Insufficient permissions"`
		Status       int      `json:"status" example:"403"`
		RequiredRole string   `json:"required_role,omitempty" example:"Admin"`
		CurrentRole  string   `json:"current_role,omitempty" example:"User"`
		Suggestions  []string `json:"suggestions,omitempty"`
		HelpURL      string   `json:"help_url,omitempty" example:"https://docs.api.com/authorization"`
		TraceID      string   `json:"trace_id,omitempty" example:"trace_123e4567"`
	} `json:"error"`
}

// NotFoundErrorResponse for 404 Not Found errors
type NotFoundErrorResponse struct {
	BaseResponse
	Error struct {
		Code         string   `json:"code" example:"RESOURCE_NOT_FOUND"`
		Message      string   `json:"message" example:"Resource not found"`
		Status       int      `json:"status" example:"404"`
		ResourceType string   `json:"resource_type,omitempty" example:"user"`
		ResourceID   string   `json:"resource_id,omitempty" example:"testuser"`
		Suggestions  []string `json:"suggestions,omitempty"`
		HelpURL      string   `json:"help_url,omitempty" example:"https://docs.api.com/resources"`
		TraceID      string   `json:"trace_id,omitempty" example:"trace_123e4567"`
	} `json:"error"`
}

// RateLimitErrorResponse for 429 Too Many Requests
type RateLimitErrorResponse struct {
	BaseResponse
	Error struct {
		Code       string `json:"code" example:"RATE_LIMIT_EXCEEDED"`
		Message    string `json:"message" example:"Rate limit exceeded"`
		Status     int    `json:"status" example:"429"`
		RetryAfter int    `json:"retry_after" example:"60"`                  // Seconds to wait
		Limit      int    `json:"limit" example:"1000"`                      // Rate limit per window
		Remaining  int    `json:"remaining" example:"0"`                     // Requests remaining
		ResetTime  string `json:"reset_time" example:"2024-01-01T12:01:00Z"` // When limit resets
		Window     int    `json:"window" example:"3600"`                     // Window in seconds
		TraceID    string `json:"trace_id,omitempty" example:"trace_123e4567"`
	} `json:"error"`
}

// ServerErrorResponse for 5xx server errors
type ServerErrorResponse struct {
	BaseResponse
	Error struct {
		Code      string `json:"code" example:"INTERNAL_SERVER_ERROR"`
		Message   string `json:"message" example:"An unexpected error occurred"`
		Status    int    `json:"status" example:"500"`
		Severity  string `json:"severity" example:"critical"`          // critical, high, medium, low
		Incident  string `json:"incident,omitempty" example:"INC-001"` // Incident ID
		Support   string `json:"support,omitempty" example:"support@company.com"`
		TraceID   string `json:"trace_id,omitempty" example:"trace_123e4567"`
		Reference string `json:"reference,omitempty" example:"REF-123456"` // Support reference
	} `json:"error"`
}

// =================== HEALTH CHECK RESPONSE ===================

// HealthResponse represents health check response with system status
type HealthResponse struct {
	BaseResponse
	Success struct {
		Status int `json:"status" example:"200"`
		Data   struct {
			Status      string            `json:"status" example:"healthy"`
			Service     string            `json:"service" example:"govpn-api"`
			Version     string            `json:"version" example:"1.1.0"`
			Uptime      string            `json:"uptime" example:"72h30m15s"`
			Checks      map[string]string `json:"checks,omitempty"` // Component health status
			Environment string            `json:"environment" example:"production"`
			Region      string            `json:"region,omitempty" example:"us-east-1"`
			Timestamp   string            `json:"timestamp" example:"2024-01-01T12:00:00Z"`
		} `json:"data"`
	} `json:"success"`
}

// =================== BATCH OPERATION RESPONSE ===================

// BatchOperationResponse for bulk operations with comprehensive results
type BatchOperationResponse struct {
	BaseResponse
	Success struct {
		Status int `json:"status" example:"200"`
		Data   struct {
			JobID          string      `json:"job_id" example:"job_123e4567"`
			Total          int         `json:"total" example:"100"`            // Total items to process
			Processed      int         `json:"processed" example:"95"`         // Items processed
			Successful     int         `json:"successful" example:"90"`        // Successfully processed
			Failed         int         `json:"failed" example:"5"`             // Failed to process
			Skipped        int         `json:"skipped" example:"5"`            // Skipped items
			ProcessingTime string      `json:"processing_time" example:"2.5s"` // Total processing time
			Results        interface{} `json:"results,omitempty"`              // Detailed results
			FailedItems    interface{} `json:"failed_items,omitempty"`         // Failed item details
			DownloadURL    string      `json:"download_url,omitempty" example:"/api/jobs/job_123e4567/results"`
			Summary        interface{} `json:"summary,omitempty"` // Operation summary
		} `json:"data"`
		Links []HATEOASLink `json:"links,omitempty"` // Job status and result links
	} `json:"success"`
}

// =================== USER-SPECIFIC RESPONSE TYPES ===================

// UserActionResponse for user action operations
type UserActionResponse struct {
	Action    string       `json:"action" example:"enable"`                     // Action performed
	Success   bool         `json:"success" example:"true"`                      // Operation success
	Message   string       `json:"message" example:"User enabled successfully"` // Result message
	User      UserResponse `json:"user"`                                        // Updated user data
	Timestamp string       `json:"timestamp" example:"2024-01-01T12:00:00Z"`    // Action timestamp
}

// UserExpirationInfo for user expiration data
type UserExpirationInfo struct {
	Username     string  `json:"username" example:"testuser"`                          // Username
	Email        string  `json:"email" example:"test@example.com"`                     // User email
	ExpiryDate   *string `json:"expiry_date,omitempty" example:"2024-12-31T23:59:59Z"` // Expiration date
	DaysToExpiry int     `json:"days_to_expiry" example:"30"`                          // Days until expiration
	IsExpired    bool    `json:"is_expired" example:"false"`                           // Whether already expired
	Status       string  `json:"status,omitempty" example:"expiring_soon"`             // Expiration status
}

// =================== ENHANCED API INFO RESPONSE ===================

// APIInfoResponse provides comprehensive API information
type APIInfoResponse struct {
	BaseResponse
	Success struct {
		Status int `json:"status" example:"200"`
		Data   struct {
			Name        string `json:"name" example:"GoVPN API Enhanced"`
			Version     string `json:"version" example:"1.1.0"`
			Description string `json:"description" example:"OpenVPN Access Server Management API with Bulk Operations and Advanced Search"`

			// Feature information
			Features map[string]interface{} `json:"features"`

			// Available endpoints
			Endpoints map[string]interface{} `json:"endpoints"`

			// Rate limiting information
			RateLimits map[string]interface{} `json:"rate_limits"`

			// Documentation and support
			Documentation string            `json:"documentation" example:"/swagger/index.html"`
			Support       map[string]string `json:"support"`

			// Environment information
			Environment string `json:"environment" example:"production"`
			Region      string `json:"region,omitempty" example:"us-east-1"`
		} `json:"data"`
	} `json:"success"`
}

// =================== METRICS AND MONITORING RESPONSES ===================

// MetricsResponse for system metrics
type MetricsResponse struct {
	BaseResponse
	Success struct {
		Status int `json:"status" example:"200"`
		Data   struct {
			RequestsTotal     int64                  `json:"requests_total" example:"150000"`
			RequestsPerSecond float64                `json:"requests_per_second" example:"25.5"`
			ResponseTimes     map[string]interface{} `json:"response_times"` // p50, p95, p99, avg
			ErrorRates        map[string]interface{} `json:"error_rates"`    // 4xx, 5xx rates
			ActiveConnections int                    `json:"active_connections" example:"245"`
			MemoryUsage       map[string]interface{} `json:"memory_usage"` // used, total, percentage
			CPUUsage          map[string]interface{} `json:"cpu_usage"`    // percentage, cores
			Timestamp         string                 `json:"timestamp" example:"2024-01-01T12:00:00Z"`
		} `json:"data"`
	} `json:"success"`
}

// =================== SEARCH RESPONSE TYPES ===================

// SearchResponse for search operations with facets and suggestions
type SearchResponse struct {
	BaseResponse
	Success struct {
		Status int `json:"status" example:"200"`
		Data   struct {
			Results     interface{}            `json:"results"`               // Search results
			Total       int                    `json:"total" example:"42"`    // Total matching results
			Facets      map[string]interface{} `json:"facets,omitempty"`      // Search facets
			Suggestions []string               `json:"suggestions,omitempty"` // Search suggestions
			Query       string                 `json:"query" example:"test"`  // Original search query
			Filters     map[string]interface{} `json:"filters,omitempty"`     // Applied filters
		} `json:"data"`
		Pagination PaginationMetadata `json:"pagination,omitempty"` // Pagination if applicable
		Links      []HATEOASLink      `json:"links,omitempty"`      // Navigation links
	} `json:"success"`
}

// =================== FILE OPERATION RESPONSES ===================

// FileUploadResponse for file upload operations
type FileUploadResponse struct {
	BaseResponse
	Success struct {
		Status int `json:"status" example:"200"`
		Data   struct {
			FileName     string `json:"file_name" example:"users.csv"`
			FileSize     int64  `json:"file_size" example:"2048"`
			FileType     string `json:"file_type" example:"text/csv"`
			UploadedAt   string `json:"uploaded_at" example:"2024-01-01T12:00:00Z"`
			ProcessingID string `json:"processing_id,omitempty" example:"proc_123e4567"`
		} `json:"data"`
		Links []HATEOASLink `json:"links,omitempty"` // Processing status links
	} `json:"success"`
}

// FileExportResponse for file export operations
type FileExportResponse struct {
	BaseResponse
	Success struct {
		Status int `json:"status" example:"200"`
		Data   struct {
			DownloadURL string `json:"download_url" example:"/api/downloads/export_123e4567.csv"`
			FileName    string `json:"file_name" example:"users_export_2024-01-01.csv"`
			FileSize    int64  `json:"file_size" example:"4096"`
			Format      string `json:"format" example:"csv"`
			ExpiresAt   string `json:"expires_at" example:"2024-01-02T12:00:00Z"`
			RecordCount int    `json:"record_count" example:"150"`
			GeneratedAt string `json:"generated_at" example:"2024-01-01T12:00:00Z"`
		} `json:"data"`
		Links []HATEOASLink `json:"links,omitempty"` // Download links
	} `json:"success"`
}

// =================== JOB STATUS RESPONSE ===================

// JobStatusResponse for tracking asynchronous operations
type JobStatusResponse struct {
	BaseResponse
	Success struct {
		Status int `json:"status" example:"200"`
		Data   struct {
			JobID       string                 `json:"job_id" example:"job_123e4567"`
			Status      string                 `json:"status" example:"completed"` // pending, running, completed, failed
			Progress    int                    `json:"progress" example:"100"`     // Percentage complete
			StartedAt   string                 `json:"started_at" example:"2024-01-01T12:00:00Z"`
			CompletedAt *string                `json:"completed_at,omitempty" example:"2024-01-01T12:05:00Z"`
			Duration    *string                `json:"duration,omitempty" example:"5m30s"`
			Result      interface{}            `json:"result,omitempty"`   // Job result data
			Error       *string                `json:"error,omitempty"`    // Error message if failed
			Metadata    map[string]interface{} `json:"metadata,omitempty"` // Additional job metadata
		} `json:"data"`
		Links []HATEOASLink `json:"links,omitempty"` // Result and cancellation links
	} `json:"success"`
}
