package dto

// Swagger response types for documentation

// SuccessResponse represents a successful API response
type SuccessResponse struct {
	Success struct {
		Status  int         `json:"status" example:"200"`
		Data    interface{} `json:"data,omitempty"`
		Message string      `json:"message,omitempty" example:"Operation successful"`
	} `json:"success"`
}

// ErrorResponse represents an error API response
type ErrorResponse struct {
	Error struct {
		Code    string `json:"code" example:"BAD_REQUEST"`
		Message string `json:"message" example:"Invalid request format"`
		Status  int    `json:"status" example:"400"`
	} `json:"error"`
}

// ValidationErrorResponse represents a validation error response
type ValidationErrorResponse struct {
	Error struct {
		Code    string            `json:"code" example:"VALIDATION_ERROR"`
		Message string            `json:"message" example:"Validation failed"`
		Status  int               `json:"status" example:"400"`
		Fields  map[string]string `json:"fields"`
	} `json:"error"`
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	Success struct {
		Status  int    `json:"status" example:"200"`
		Message string `json:"message" example:"Operation completed successfully"`
	} `json:"success"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Success struct {
		Status int `json:"status" example:"200"`
		Data   struct {
			Status    string `json:"status" example:"healthy"`
			Timestamp string `json:"timestamp" example:"2024-01-01T00:00:00Z"`
			Service   string `json:"service" example:"govpn-api"`
		} `json:"data"`
	} `json:"success"`
}
