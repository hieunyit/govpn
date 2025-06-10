package http

import (
	"govpn/pkg/errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// Response structures
type SuccessResponse struct {
	Success struct {
		Status  int         `json:"status"`
		Data    interface{} `json:"data,omitempty"`
		Message string      `json:"message,omitempty"`
	} `json:"success"`
}

type ErrorResponse struct {
	Error struct {
		Code    string      `json:"code"`
		Message string      `json:"message"`
		Status  int         `json:"status"`
		Details interface{} `json:"details,omitempty"`
	} `json:"error"`
}

type ValidationErrorResponse struct {
	Error struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Status  int               `json:"status"`
		Fields  map[string]string `json:"fields"`
	} `json:"error"`
}

// RespondWithSuccess sends a successful response
func RespondWithSuccess(c *gin.Context, status int, data interface{}) {
	response := SuccessResponse{}
	response.Success.Status = status
	response.Success.Data = data

	c.JSON(status, response)
}

// RespondWithMessage sends a successful response with message
func RespondWithMessage(c *gin.Context, status int, message string) {
	response := SuccessResponse{}
	response.Success.Status = status
	response.Success.Message = message

	c.JSON(status, response)
}

// RespondWithError sends an error response
func RespondWithError(c *gin.Context, err *errors.AppError) {
	response := ErrorResponse{}
	response.Error.Code = err.Code
	response.Error.Message = err.Message
	response.Error.Status = err.Status

	c.JSON(err.Status, response)
}

// RespondWithValidationError sends a validation error response
func RespondWithValidationError(c *gin.Context, err error) {
	response := ValidationErrorResponse{}
	response.Error.Code = "VALIDATION_ERROR"
	response.Error.Message = "Validation failed"
	response.Error.Status = http.StatusBadRequest
	response.Error.Fields = make(map[string]string)

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, validationError := range validationErrors {
			field := strings.ToLower(validationError.Field())
			tag := validationError.Tag()

			switch tag {
			case "required":
				response.Error.Fields[field] = field + " is required"
			case "email":
				response.Error.Fields[field] = field + " must be a valid email address"
			case "min":
				response.Error.Fields[field] = field + " is too short"
			case "max":
				response.Error.Fields[field] = field + " is too long"
			case "username":
				response.Error.Fields[field] = field + " can only contain lowercase letters, numbers, dots and underscores"
			case "date":
				response.Error.Fields[field] = field + " must be a future date in format DD/MM/YYYY"
			case "hex16":
				response.Error.Fields[field] = field + " must be 16 hexadecimal characters"
			case "oneof":
				response.Error.Fields[field] = field + " has invalid value"
			case "ipv4":
				response.Error.Fields[field] = field + " must be a valid IPv4 address"
			case "cidrv4":
				response.Error.Fields[field] = field + " must be valid CIDR notation"
			case "ipv4_protocol":
				response.Error.Fields[field] = field + " must be valid IP:protocol format"
			default:
				response.Error.Fields[field] = field + " is invalid"
			}
		}
	} else {
		response.Error.Fields["general"] = err.Error()
	}

	c.JSON(http.StatusBadRequest, response)
}

// RespondWithInternalError sends an internal server error response
func RespondWithInternalError(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "INTERNAL_SERVER_ERROR"
	response.Error.Message = message
	response.Error.Status = http.StatusInternalServerError

	c.JSON(http.StatusInternalServerError, response)
}

// RespondWithNotFound sends a not found error response
func RespondWithNotFound(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "NOT_FOUND"
	response.Error.Message = message
	response.Error.Status = http.StatusNotFound

	c.JSON(http.StatusNotFound, response)
}

// RespondWithBadRequest sends a bad request error response
func RespondWithBadRequest(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "BAD_REQUEST"
	response.Error.Message = message
	response.Error.Status = http.StatusBadRequest

	c.JSON(http.StatusBadRequest, response)
}

// RespondWithUnauthorized sends an unauthorized error response
func RespondWithUnauthorized(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "UNAUTHORIZED"
	response.Error.Message = message
	response.Error.Status = http.StatusUnauthorized

	c.JSON(http.StatusUnauthorized, response)
}

// RespondWithForbidden sends a forbidden error response
func RespondWithForbidden(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "FORBIDDEN"
	response.Error.Message = message
	response.Error.Status = http.StatusForbidden

	c.JSON(http.StatusForbidden, response)
}

// RespondWithConflict sends a conflict error response
func RespondWithConflict(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "CONFLICT"
	response.Error.Message = message
	response.Error.Status = http.StatusConflict

	c.JSON(http.StatusConflict, response)
}
