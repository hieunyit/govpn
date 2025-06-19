package handlers

import (
	"govpn/pkg/errors"
	nethttp "net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// Common response helper functions for all handlers

func RespondWithSuccess(c *gin.Context, status int, data interface{}) {
	c.JSON(status, gin.H{
		"success": gin.H{
			"status": status,
			"data":   data,
		},
	})
}

func RespondWithMessage(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{
		"success": gin.H{
			"status":  status,
			"message": message,
		},
	})
}

func RespondWithError(c *gin.Context, err *errors.AppError) {
	errorBody := gin.H{
		"code":    err.Code,
		"message": err.Message,
		"status":  err.Status,
	}
	if err.Details != "" {
		errorBody["details"] = err.Details
	}

	c.JSON(err.Status, gin.H{"error": errorBody})
}

func RespondWithValidationError(c *gin.Context, err error) {
	fields := make(map[string]string)
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, validationError := range validationErrors {
			field := strings.ToLower(validationError.Field())
			tag := validationError.Tag()

			switch tag {
			case "required":
				fields[field] = field + " is required"
			case "email":
				fields[field] = field + " must be a valid email address"
			case "min":
				fields[field] = field + " is too short"
			case "max":
				fields[field] = field + " is too long"
			case "username":
				fields[field] = field + " can only contain lowercase letters, numbers, dots and underscores"
			case "date":
				fields[field] = field + " must be a future date in format DD/MM/YYYY"
			case "hex16":
				fields[field] = field + " must be 16 hexadecimal characters"
			case "oneof":
				fields[field] = field + " has invalid value"
			case "ipv4":
				fields[field] = field + " must be a valid IPv4 address"
			case "cidrv4":
				fields[field] = field + " must be valid CIDR notation"
			case "ipv4_protocol":
				fields[field] = field + " must be valid IP:protocol format"
			default:
				fields[field] = field + " is invalid"
			}
		}
	} else {
		fields["general"] = err.Error()
	}

	c.JSON(nethttp.StatusBadRequest, gin.H{
		"error": gin.H{
			"code":    "VALIDATION_ERROR",
			"message": "Validation failed",
			"status":  nethttp.StatusBadRequest,
			"fields":  fields,
		},
	})
}

// Lowercase versions for internal package use
func respondWithSuccess(c *gin.Context, status int, data interface{}) {
	RespondWithSuccess(c, status, data)
}

func respondWithMessage(c *gin.Context, status int, message string) {
	RespondWithMessage(c, status, message)
}

func respondWithError(c *gin.Context, err *errors.AppError) {
	RespondWithError(c, err)
}

func respondWithValidationError(c *gin.Context, err error) {
	RespondWithValidationError(c, err)
}
