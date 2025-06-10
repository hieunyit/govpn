package response

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

// Success sends a successful response
func Success(c *gin.Context, status int, data interface{}) {
	response := SuccessResponse{}
	response.Success.Status = status
	response.Success.Data = data

	c.JSON(status, response)
}

// Message sends a successful response with message
func Message(c *gin.Context, status int, message string) {
	response := SuccessResponse{}
	response.Success.Status = status
	response.Success.Message = message

	c.JSON(status, response)
}

// Error sends an error response
func Error(c *gin.Context, err *errors.AppError) {
	response := ErrorResponse{}
	response.Error.Code = err.Code
	response.Error.Message = err.Message
	response.Error.Status = err.Status

	c.JSON(err.Status, response)
}

// ValidationError sends a validation error response
func ValidationError(c *gin.Context, err error) {
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

// InternalError sends an internal server error response
func InternalError(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "INTERNAL_SERVER_ERROR"
	response.Error.Message = message
	response.Error.Status = http.StatusInternalServerError

	c.JSON(http.StatusInternalServerError, response)
}

// NotFound sends a not found error response
func NotFound(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "NOT_FOUND"
	response.Error.Message = message
	response.Error.Status = http.StatusNotFound

	c.JSON(http.StatusNotFound, response)
}

// BadRequest sends a bad request error response
func BadRequest(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "BAD_REQUEST"
	response.Error.Message = message
	response.Error.Status = http.StatusBadRequest

	c.JSON(http.StatusBadRequest, response)
}

// Unauthorized sends an unauthorized error response
func Unauthorized(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "UNAUTHORIZED"
	response.Error.Message = message
	response.Error.Status = http.StatusUnauthorized

	c.JSON(http.StatusUnauthorized, response)
}

// Forbidden sends a forbidden error response
func Forbidden(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "FORBIDDEN"
	response.Error.Message = message
	response.Error.Status = http.StatusForbidden

	c.JSON(http.StatusForbidden, response)
}

// Conflict sends a conflict error response
func Conflict(c *gin.Context, message string) {
	response := ErrorResponse{}
	response.Error.Code = "CONFLICT"
	response.Error.Message = message
	response.Error.Status = http.StatusConflict

	c.JSON(http.StatusConflict, response)
}
