package handlers

import (
	"net/http"
	"time"

	"govpn/internal/infrastructure/redis"
	"govpn/pkg/logger"

	"github.com/gin-gonic/gin"
)

type CacheHandler struct {
	cache *redis.Client
}

func NewCacheHandler(cache *redis.Client) *CacheHandler {
	return &CacheHandler{
		cache: cache,
	}
}

// GetCacheStatus returns cache status
// @Summary Get cache status
// @Description Get Redis cache status
// @Tags Cache
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/cache/status [get]
// @Security BearerAuth
func (h *CacheHandler) GetCacheStatus(c *gin.Context) {
	logger.Log.Info("Getting cache status")

	if !h.cache.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{
			"enabled":   false,
			"status":    "disabled",
			"message":   "Redis cache is disabled",
			"timestamp": time.Now(),
		})
		return
	}

	// Test Redis connection
	err := h.cache.Ping()
	status := "healthy"
	if err != nil {
		status = "unhealthy"
		logger.Log.WithError(err).Error("Redis ping failed")
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled":   true,
		"status":    status,
		"error":     err,
		"timestamp": time.Now(),
	})
}

// FlushCache flushes all cache data
// @Summary Flush cache
// @Description Clear all cached data
// @Tags Cache
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/cache/flush [delete]
// @Security BearerAuth
func (h *CacheHandler) FlushCache(c *gin.Context) {
	logger.Log.Info("Flushing cache")

	if !h.cache.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{
			"success":   true,
			"message":   "Cache is disabled, no data to flush",
			"timestamp": time.Now(),
		})
		return
	}

	if err := h.cache.FlushAll(); err != nil {
		logger.Log.WithError(err).Error("Failed to flush cache")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to flush cache",
			"details": err.Error(),
		})
		return
	}

	logger.Log.Info("Cache flushed successfully")
	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"message":   "Cache flushed successfully",
		"timestamp": time.Now(),
	})
}
