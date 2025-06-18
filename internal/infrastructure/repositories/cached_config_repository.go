package repositories

import (
	"context"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/redis"
	"govpn/pkg/logger"
	"time"

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

// ✅ ENHANCED: GetServerInfo with caching + async updates
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

	// 🔥 Async caching with long TTL (config data rarely changes)
	r.cache.SetAsync(ctx, cacheKey, serverInfo, redis.ConfigTTL)
	logger.Log.WithField("ttl", redis.ConfigTTL).Debug("Server info cached")

	return serverInfo, nil
}

// ✅ ENHANCED: GetNetworkConfig with caching + async updates
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

	// 🔥 Async caching with long TTL (config data rarely changes)
	r.cache.SetAsync(ctx, cacheKey, networkConfig, redis.ConfigTTL)
	logger.Log.WithField("ttl", redis.ConfigTTL).Debug("Network config cached")

	return networkConfig, nil
}

// ✅ ENHANCED: GetAllConfig with caching + async updates
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

	// 🔥 Async caching with long TTL (config data rarely changes)
	r.cache.SetAsync(ctx, cacheKey, allConfig, redis.ConfigTTL)
	logger.Log.WithField("ttl", redis.ConfigTTL).Debug("All config cached")

	return allConfig, nil
}

// 🔥 NEW: Config cache invalidation helpers

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
	// 🔥 Use async pattern deletion to avoid blocking
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := r.cache.DeleteByPattern(ctx, "config:*"); err != nil {
			logger.Log.WithError(err).Warn("Failed to delete config cache by pattern")
		}
	}()

	return nil
}

// 🔥 NEW: Cache warming for configs
func (r *CachedConfigRepository) WarmupCache(ctx context.Context) error {
	logger.Log.Info("Starting config cache warmup")

	// 🔥 Pre-load frequently accessed configs in parallel
	errChan := make(chan error, 3)

	// Pre-load server info
	go func() {
		_, err := r.GetServerInfo(ctx)
		errChan <- err
	}()

	// Pre-load network config
	go func() {
		_, err := r.GetNetworkConfig(ctx)
		errChan <- err
	}()

	// Pre-load all config
	go func() {
		_, err := r.GetAllConfig(ctx)
		errChan <- err
	}()

	// Wait for all warmup operations
	for i := 0; i < 3; i++ {
		if err := <-errChan; err != nil {
			logger.Log.WithError(err).Warn("Config cache warmup error (non-critical)")
		}
	}

	logger.Log.Info("Config cache warmup completed")
	return nil
}
