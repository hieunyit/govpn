package handlers

import (
	"govpn/pkg/errors"
	nethttp "net/http"

	"github.com/gin-gonic/gin"
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
	c.JSON(err.Status, gin.H{
		"error": gin.H{
			"code":    err.Code,
			"message": err.Message,
			"status":  err.Status,
		},
	})
}

func RespondWithValidationError(c *gin.Context, err error) {
	c.JSON(nethttp.StatusBadRequest, gin.H{
		"error": gin.H{
			"code":    "VALIDATION_ERROR",
			"message": "Validation failed",
			"status":  nethttp.StatusBadRequest,
			"details": err.Error(),
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
