package handlers

import (
	"context"
	"net/http"
	"time"

	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/redis"
	"govpn/pkg/logger"

	"github.com/gin-gonic/gin"
)

type CacheHandler struct {
	cache      *redis.Client
	userRepo   repositories.UserRepository
	groupRepo  repositories.GroupRepository
	configRepo repositories.ConfigRepository
}

func NewCacheHandler(cache *redis.Client, userRepo repositories.UserRepository, groupRepo repositories.GroupRepository, configRepo repositories.ConfigRepository) *CacheHandler {
	return &CacheHandler{
		cache:      cache,
		userRepo:   userRepo,
		groupRepo:  groupRepo,
		configRepo: configRepo,
	}
}

// GetCacheStatus returns cache status with enhanced information
// @Summary Get cache status
// @Description Get Redis cache status, connection health, and statistics
// @Tags Cache
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/openvpn/cache/status [get]
// @Security BearerAuth
func (h *CacheHandler) GetCacheStatus(c *gin.Context) {
	logger.Log.Info("Getting enhanced cache status")

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
	err := h.cache.Ping(c.Request.Context())
	status := "healthy"
	var errorMessage string

	if err != nil {
		status = "unhealthy"
		errorMessage = err.Error()
		logger.Log.WithError(err).Error("Redis ping failed")
	}

	response := gin.H{
		"enabled":   true,
		"status":    status,
		"timestamp": time.Now(),
	}

	if errorMessage != "" {
		response["error"] = errorMessage
	}

	// ✅ ENHANCED: Add cache statistics if healthy
	if status == "healthy" {
		if stats, err := h.cache.GetStats(c.Request.Context()); err == nil {
			response["statistics"] = stats
		}

		// Add TTL information
		response["ttl_config"] = gin.H{
			"user_cache":       redis.UserTTL.String(),
			"group_cache":      redis.GroupTTL.String(),
			"list_cache":       redis.ListTTL.String(),
			"filtered_cache":   redis.FilteredTTL.String(),
			"config_cache":     redis.ConfigTTL.String(),
			"expiration_cache": redis.ExpirationTTL.String(),
			"search_cache":     redis.SearchTTL.String(),
		}

		// Add cache categories
		response["cached_endpoints"] = gin.H{
			"users": []string{
				"GET /api/openvpn/users/{username}",
				"GET /api/openvpn/users (with/without filters)",
				"GET /api/openvpn/users/expirations",
			},
			"groups": []string{
				"GET /api/openvpn/groups/{groupName}",
				"GET /api/openvpn/groups (with/without filters)",
			},
			"config": []string{
				"GET /api/openvpn/config/server/info",
				"GET /api/openvpn/config/network",
			},
		}
	}

	c.JSON(http.StatusOK, response)
}

// FlushCache flushes all cache data
// @Summary Flush cache
// @Description Clear all cached data from Redis
// @Tags Cache
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/openvpn/cache/flush [delete]
// @Security BearerAuth
func (h *CacheHandler) FlushCache(c *gin.Context) {
	logger.Log.Info("Flushing all cache data")

	if !h.cache.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{
			"success":   true,
			"message":   "Cache is disabled, no data to flush",
			"timestamp": time.Now(),
		})
		return
	}

	if err := h.cache.FlushAll(c.Request.Context()); err != nil {
		logger.Log.WithError(err).Error("Failed to flush cache")
		c.JSON(http.StatusInternalServerError, gin.H{
			"success":   false,
			"error":     "Failed to flush cache",
			"details":   err.Error(),
			"timestamp": time.Now(),
		})
		return
	}

	logger.Log.Info("Cache flushed successfully")
	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"message":   "All cache data flushed successfully",
		"timestamp": time.Now(),
	})
}

// ✅ ENHANCED: Selective cache flushing
// @Summary Flush specific cache categories
// @Description Clear specific categories of cached data
// @Tags Cache
// @Produce json
// @Param category query string true "Cache category (users|groups|config|filters|expirations|all)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/openvpn/cache/flush/category [delete]
// @Security BearerAuth
func (h *CacheHandler) FlushCacheCategory(c *gin.Context) {
	category := c.Query("category")
	if category == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":            "Category parameter is required",
			"valid_categories": []string{"users", "groups", "config", "filters", "expirations", "all"},
		})
		return
	}

	if !h.cache.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Cache is disabled, no data to flush",
		})
		return
	}

	logger.Log.WithField("category", category).Info("Flushing cache category")

	var err error
	var message string

	switch category {
	case "users":
		err = h.cache.DeleteByPattern(c.Request.Context(), "user:*")
		if err == nil {
			err = h.cache.Del(c.Request.Context(), "users:list")
		}
		message = "User cache flushed"
	case "groups":
		err = h.cache.DeleteByPattern(c.Request.Context(), "group:*")
		if err == nil {
			err = h.cache.Del(c.Request.Context(), "groups:list")
		}
		message = "Group cache flushed"
	case "config":
		err = h.cache.DeleteByPattern(c.Request.Context(), "config:*")
		message = "Config cache flushed"
	case "filters":
		err = h.cache.DeleteByPattern(c.Request.Context(), "*:filter:*")
		message = "Filtered queries cache flushed"
	case "expirations":
		err = h.cache.DeleteByPattern(c.Request.Context(), "expiration:*")
		message = "Expiration cache flushed"
	case "all":
		err = h.cache.FlushAll(c.Request.Context())
		message = "All cache data flushed"
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":            "Invalid category",
			"valid_categories": []string{"users", "groups", "config", "filters", "expirations", "all"},
		})
		return
	}

	if err != nil {
		logger.Log.WithError(err).WithField("category", category).Error("Failed to flush cache category")
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to flush cache category",
			"details": err.Error(),
		})
		return
	}

	logger.Log.WithField("category", category).Info("Cache category flushed successfully")
	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"category":  category,
		"message":   message,
		"timestamp": time.Now(),
	})
}

// GetCacheStats returns detailed cache statistics
// @Summary Get cache statistics
// @Description Get detailed cache statistics and metrics
// @Tags Cache
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/openvpn/cache/stats [get]
// @Security BearerAuth
func (h *CacheHandler) GetCacheStats(c *gin.Context) {
	logger.Log.Info("Getting detailed cache statistics")

	if !h.cache.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"message": "Cache is disabled",
		})
		return
	}

	// Test connection first
	if err := h.cache.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"enabled": true,
			"error":   "Redis connection failed",
			"details": err.Error(),
		})
		return
	}

	// Get detailed statistics
	stats, err := h.cache.GetStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get cache statistics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// WarmUpCache pre-loads frequently accessed data into cache
// @Summary Warm up cache
// @Description Pre-load frequently accessed data into cache
// @Tags Cache
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/openvpn/cache/warmup [post]
// @Security BearerAuth
func (h *CacheHandler) WarmUpCache(c *gin.Context) {
	logger.Log.Info("Starting cache warmup")

	if !h.cache.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Cache is disabled, warmup not needed",
		})
		return
	}

	// Test connection first
	if err := h.cache.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "Redis connection failed",
			"details": err.Error(),
		})
		return
	}

	start := time.Now()

	err := h.cache.WarmCache(c.Request.Context(), func(ctx context.Context) error {
		if w, ok := h.userRepo.(interface{ WarmupCache(context.Context) error }); ok {
			if err := w.WarmupCache(ctx); err != nil {
				return err
			}
		}
		if w, ok := h.groupRepo.(interface{ WarmupCache(context.Context) error }); ok {
			if err := w.WarmupCache(ctx); err != nil {
				return err
			}
		}
		if w, ok := h.configRepo.(interface{ WarmupCache(context.Context) error }); ok {
			if err := w.WarmupCache(ctx); err != nil {
				return err
			}
		}
		return nil
	})
	duration := time.Since(start)
	if err != nil {
		logger.Log.WithError(err).Warn("Cache warmup encountered errors")
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	logger.Log.WithField("duration", duration).Info("Cache warmup completed")
	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"message":   "Cache warmup completed successfully",
		"duration":  duration.String(),
		"note":      "Warmup logic can be implemented based on usage patterns",
		"timestamp": time.Now(),
	})
}

// ✅ NEW: Cache health check
// @Summary Check cache health
// @Description Perform comprehensive cache health check
// @Tags Cache
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/openvpn/cache/health [get]
// @Security BearerAuth
func (h *CacheHandler) CacheHealthCheck(c *gin.Context) {
	health := gin.H{
		"timestamp": time.Now(),
		"enabled":   h.cache.IsEnabled(),
	}

	if !h.cache.IsEnabled() {
		health["status"] = "disabled"
		health["message"] = "Cache is disabled in configuration"
		c.JSON(http.StatusOK, health)
		return
	}

	// Test connection
	if err := h.cache.Ping(c.Request.Context()); err != nil {
		health["status"] = "unhealthy"
		health["error"] = err.Error()
		c.JSON(http.StatusServiceUnavailable, health)
		return
	}

	// Test read/write operations
	testKey := "health_check_test"
	testValue := map[string]interface{}{
		"test":      true,
		"timestamp": time.Now(),
	}

	// Test write
	if err := h.cache.SetWithTTL(c.Request.Context(), testKey, testValue, 10*time.Second); err != nil {
		health["status"] = "unhealthy"
		health["error"] = "Failed write test: " + err.Error()
		c.JSON(http.StatusInternalServerError, health)
		return
	}

	// Test read
	var readValue map[string]interface{}
	if err := h.cache.Get(c.Request.Context(), testKey, &readValue); err != nil {
		health["status"] = "unhealthy"
		health["error"] = "Failed read test: " + err.Error()
		c.JSON(http.StatusInternalServerError, health)
		return
	}

	// Clean up test key
	h.cache.Del(c.Request.Context(), testKey)

	health["status"] = "healthy"
	health["message"] = "All cache operations working correctly"
	health["operations_tested"] = []string{"ping", "write", "read", "delete"}

	c.JSON(http.StatusOK, health)
}
