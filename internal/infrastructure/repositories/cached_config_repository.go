package repositories

import (
	"context"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/redis"
	"govpn/pkg/logger"

	redisLib "github.com/redis/go-redis/v9"
)

type CachedConfigRepository struct {
	repo  repositories.ConfigRepository
	cache *redis.Client
}

func NewCachedConfigRepository(repo repositories.ConfigRepository, cache *redis.Client) repositories.ConfigRepository {
	return &CachedConfigRepository{
		repo:  repo,
		cache: cache,
	}
}

// ✅ NEW: GetServerInfo with caching
func (r *CachedConfigRepository) GetServerInfo(ctx context.Context) (*entities.ServerInfo, error) {
	// Try cache first
	cacheKey := r.cache.GenerateConfigKey("server_info")
	var cachedInfo entities.ServerInfo

	if err := r.cache.Get(ctx, cacheKey, &cachedInfo); err == nil {
		logger.Log.Debug("Server info retrieved from cache")
		return &cachedInfo, nil
	} else if err != redisLib.Nil {
		logger.Log.WithError(err).Warn("Cache error getting server info")
	}

	// Cache miss - get from repository
	serverInfo, err := r.repo.GetServerInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Cache the result with long TTL (config data rarely changes)
	if cacheErr := r.cache.SetWithTTL(ctx, cacheKey, serverInfo, redis.ConfigTTL); cacheErr != nil {
		logger.Log.WithError(cacheErr).Warn("Failed to cache server info")
	} else {
		logger.Log.WithField("ttl", redis.ConfigTTL).Debug("Server info cached")
	}

	return serverInfo, nil
}

// ✅ NEW: GetNetworkConfig with caching
func (r *CachedConfigRepository) GetNetworkConfig(ctx context.Context) (*entities.NetworkConfig, error) {
	// Try cache first
	cacheKey := r.cache.GenerateConfigKey("network_config")
	var cachedConfig entities.NetworkConfig

	if err := r.cache.Get(ctx, cacheKey, &cachedConfig); err == nil {
		logger.Log.Debug("Network config retrieved from cache")
		return &cachedConfig, nil
	} else if err != redisLib.Nil {
		logger.Log.WithError(err).Warn("Cache error getting network config")
	}

	// Cache miss - get from repository
	networkConfig, err := r.repo.GetNetworkConfig(ctx)
	if err != nil {
		return nil, err
	}

	// Cache the result with long TTL (config data rarely changes)
	if cacheErr := r.cache.SetWithTTL(ctx, cacheKey, networkConfig, redis.ConfigTTL); cacheErr != nil {
		logger.Log.WithError(cacheErr).Warn("Failed to cache network config")
	} else {
		logger.Log.WithField("ttl", redis.ConfigTTL).Debug("Network config cached")
	}

	return networkConfig, nil
}

// ✅ NEW: GetAllConfig with caching
func (r *CachedConfigRepository) GetAllConfig(ctx context.Context) (map[string]string, error) {
	// Try cache first
	cacheKey := r.cache.GenerateConfigKey("all_config")
	var cachedConfig map[string]string

	if err := r.cache.Get(ctx, cacheKey, &cachedConfig); err == nil {
		logger.Log.Debug("All config retrieved from cache")
		return cachedConfig, nil
	} else if err != redisLib.Nil {
		logger.Log.WithError(err).Warn("Cache error getting all config")
	}

	// Cache miss - get from repository
	allConfig, err := r.repo.GetAllConfig(ctx)
	if err != nil {
		return nil, err
	}

	// Cache the result with long TTL (config data rarely changes)
	if cacheErr := r.cache.SetWithTTL(ctx, cacheKey, allConfig, redis.ConfigTTL); cacheErr != nil {
		logger.Log.WithError(cacheErr).Warn("Failed to cache all config")
	} else {
		logger.Log.WithField("ttl", redis.ConfigTTL).Debug("All config cached")
	}

	return allConfig, nil
}

// ✅ NEW: Config cache invalidation helpers

// InvalidateServerInfoCache clears server info cache
func (r *CachedConfigRepository) InvalidateServerInfoCache(ctx context.Context) error {
	cacheKey := r.cache.GenerateConfigKey("server_info")
	return r.cache.Del(ctx, cacheKey)
}

// InvalidateNetworkConfigCache clears network config cache
func (r *CachedConfigRepository) InvalidateNetworkConfigCache(ctx context.Context) error {
	cacheKey := r.cache.GenerateConfigKey("network_config")
	return r.cache.Del(ctx, cacheKey)
}

// InvalidateAllConfigCache clears all config cache
func (r *CachedConfigRepository) InvalidateAllConfigCache(ctx context.Context) error {
	// Clear all config-related caches
	return r.cache.DeleteByPattern(ctx, "config:*")
}

// ✅ NEW: Warm up config cache
func (r *CachedConfigRepository) WarmupCache(ctx context.Context) error {
	logger.Log.Info("Starting config cache warmup")

	// Pre-load server info
	if _, err := r.GetServerInfo(ctx); err != nil {
		logger.Log.WithError(err).Warn("Failed to warm up server info cache")
	}

	// Pre-load network config
	if _, err := r.GetNetworkConfig(ctx); err != nil {
		logger.Log.WithError(err).Warn("Failed to warm up network config cache")
	}

	// Pre-load all config
	if _, err := r.GetAllConfig(ctx); err != nil {
		logger.Log.WithError(err).Warn("Failed to warm up all config cache")
	}

	logger.Log.Info("Config cache warmup completed")
	return nil
}
