package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type ValidationMiddleware struct{}

func NewValidationMiddleware() *ValidationMiddleware {
	return &ValidationMiddleware{}
}

// StrictJSONBinding middleware prevents extra fields in JSON requests
// This fixes the issue where APIs accept extra fields outside of DTO definition
func (vm *ValidationMiddleware) StrictJSONBinding() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only apply to JSON requests
		contentType := c.GetHeader("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			c.Next()
			return
		}

		// Skip GET and DELETE requests
		if c.Request.Method == "GET" || c.Request.Method == "DELETE" {
			c.Next()
			return
		}

		// Read body
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": gin.H{
					"code":    "INVALID_REQUEST",
					"message": "Failed to read request body",
					"status":  http.StatusBadRequest,
				},
			})
			c.Abort()
			return
		}

		// Reset body for downstream handlers
		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		// Skip empty bodies
		if len(body) == 0 {
			c.Next()
			return
		}

		// Parse JSON with DisallowUnknownFields to reject extra fields
		var rawJSON map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&rawJSON); err != nil {
			if strings.Contains(err.Error(), "unknown field") {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": gin.H{
						"code":    "UNKNOWN_FIELDS",
						"message": "Request contains unknown fields not allowed by the API",
						"status":  http.StatusBadRequest,
					},
				})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": gin.H{
						"code":    "INVALID_JSON",
						"message": "Invalid JSON format",
						"status":  http.StatusBadRequest,
					},
				})
			}
			c.Abort()
			return
		}

		c.Next()
	}
}
