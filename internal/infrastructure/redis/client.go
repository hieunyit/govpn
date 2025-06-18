package redis

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"govpn/pkg/config"
	"govpn/pkg/logger"
	"time"

	"github.com/redis/go-redis/v9"
)

// TTL constants for different data types
const (
	// Individual records - moderate TTL
	UserTTL  = 10 * time.Minute
	GroupTTL = 10 * time.Minute

	// Lists without filters - shorter TTL for consistency
	ListTTL = 5 * time.Minute

	// ✅ NEW: Filtered queries - short TTL due to many combinations
	FilteredTTL = 2 * time.Minute

	// ✅ NEW: Config data - long TTL as it rarely changes
	ConfigTTL = 30 * time.Minute

	// ✅ NEW: Time-sensitive data - very short TTL
	ExpirationTTL = 20 * time.Minute

	// ✅ NEW: Search results - short TTL
	SearchTTL = 3 * time.Minute
)

type Client struct {
	rdb     *redis.Client
	enabled bool
	ttl     time.Duration // Default TTL
}

func NewClient(cfg config.RedisConfig) (*Client, error) {
	client := &Client{
		enabled: cfg.Enabled,
		ttl:     cfg.TTL, // Default TTL from config
	}

	if !cfg.Enabled {
		logger.Log.Info("Redis is disabled")
		return client, nil
	}

	logger.Log.WithField("host", cfg.Host).
		WithField("port", cfg.Port).
		Info("Connecting to Redis")

	client.rdb = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.Database,
		PoolSize: cfg.PoolSize,
	})

	// Test connection
	if err := client.Ping(context.Background()); err != nil {
		logger.Log.WithError(err).Error("Failed to connect to Redis")
		return nil, err
	}

	logger.Log.Info("Successfully connected to Redis")
	return client, nil
}

func (c *Client) Ping(ctx context.Context) error {
	if !c.enabled || c.rdb == nil {
		return nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return c.rdb.Ping(ctxWithTimeout).Err()
}

// ✅ ENHANCED: Set with custom TTL
func (c *Client) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if !c.enabled || c.rdb == nil {
		logger.Log.Debug("Redis is disabled, skipping SetWithTTL operation")
		return nil
	}

	data, err := json.Marshal(value)
	if err != nil {
		logger.Log.WithError(err).WithField("key", key).Error("Failed to marshal data for Redis")
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = c.rdb.Set(ctxWithTimeout, key, data, ttl).Err()
	if err != nil {
		logger.Log.WithError(err).WithField("key", key).Error("Failed to set data in Redis")
		return fmt.Errorf("failed to set data in Redis: %w", err)
	}

	logger.Log.WithField("key", key).WithField("ttl", ttl).Debug("Data cached successfully with custom TTL")
	return nil
}

// Original Set method (uses default TTL)
func (c *Client) Set(ctx context.Context, key string, value interface{}) error {
	return c.SetWithTTL(ctx, key, value, c.ttl)
}

func (c *Client) Get(ctx context.Context, key string, dest interface{}) error {
	if !c.enabled || c.rdb == nil {
		return redis.Nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	data, err := c.rdb.Get(ctxWithTimeout, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			logger.Log.WithField("key", key).Debug("Cache miss")
		} else {
			logger.Log.WithError(err).WithField("key", key).Error("Failed to get data from Redis")
		}
		return err
	}

	err = json.Unmarshal(data, dest)
	if err != nil {
		logger.Log.WithError(err).WithField("key", key).Error("Failed to unmarshal data from Redis")
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	logger.Log.WithField("key", key).Debug("Cache hit")
	return nil
}

func (c *Client) Del(ctx context.Context, key string) error {
	if !c.enabled || c.rdb == nil {
		logger.Log.Debug("Redis is disabled, skipping Del operation")
		return nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	deleted, err := c.rdb.Del(ctxWithTimeout, key).Result()
	if err != nil {
		logger.Log.WithError(err).WithField("key", key).Error("Failed to delete key from Redis")
		return fmt.Errorf("failed to delete key from Redis: %w", err)
	}

	if deleted > 0 {
		logger.Log.WithField("key", key).Debug("Key deleted from cache")
	} else {
		logger.Log.WithField("key", key).Debug("Key not found in cache")
	}
	return nil
}

func (c *Client) FlushAll(ctx context.Context) error {
	if !c.enabled || c.rdb == nil {
		logger.Log.Debug("Redis is disabled, skipping FlushAll operation")
		return nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := c.rdb.FlushDB(ctxWithTimeout).Err()
	if err != nil {
		logger.Log.WithError(err).Error("Failed to flush Redis database")
		return fmt.Errorf("failed to flush Redis database: %w", err)
	}

	logger.Log.Info("Redis database flushed successfully")
	return nil
}

func (c *Client) DelMultiple(ctx context.Context, keys ...string) error {
	if !c.enabled || c.rdb == nil || len(keys) == 0 {
		return nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	deleted, err := c.rdb.Del(ctxWithTimeout, keys...).Result()
	if err != nil {
		logger.Log.WithError(err).WithField("keys", keys).Error("Failed to delete multiple keys from Redis")
		return fmt.Errorf("failed to delete multiple keys: %w", err)
	}

	logger.Log.WithField("deleted_count", deleted).WithField("requested_count", len(keys)).Debug("Multiple keys deleted from cache")
	return nil
}

func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	if !c.enabled || c.rdb == nil {
		return false, nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	exists, err := c.rdb.Exists(ctxWithTimeout, key).Result()
	if err != nil {
		logger.Log.WithError(err).WithField("key", key).Error("Failed to check key existence in Redis")
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}

	return exists == 1, nil
}

// ✅ NEW: Helper methods for cache key generation

// GenerateFilterKey generates a consistent cache key for filtered queries
func (c *Client) GenerateFilterKey(prefix string, filters interface{}) string {
	// Convert filters to JSON and hash it for consistent key
	filterJSON, err := json.Marshal(filters)
	if err != nil {
		logger.Log.WithError(err).Warn("Failed to marshal filters for cache key")
		return fmt.Sprintf("%s:filter:error", prefix)
	}

	// Create MD5 hash of filter JSON for shorter, consistent keys
	hash := md5.Sum(filterJSON)
	hashStr := fmt.Sprintf("%x", hash)[:12] // Use first 12 chars for brevity

	return fmt.Sprintf("%s:filter:%s", prefix, hashStr)
}

// GenerateConfigKey generates cache key for config data
func (c *Client) GenerateConfigKey(configType string) string {
	return fmt.Sprintf("config:%s", configType)
}

// GenerateExpirationKey generates cache key for expiration data
func (c *Client) GenerateExpirationKey(days int, includeExpired bool) string {
	return fmt.Sprintf("expiration:days:%d:expired:%t", days, includeExpired)
}

// ✅ NEW: Batch operations for pattern-based deletion

// DeleteByPattern deletes all keys matching a pattern
func (c *Client) DeleteByPattern(ctx context.Context, pattern string) error {
	if !c.enabled || c.rdb == nil {
		return nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Get all keys matching pattern
	keys, err := c.rdb.Keys(ctxWithTimeout, pattern).Result()
	if err != nil {
		logger.Log.WithError(err).WithField("pattern", pattern).Error("Failed to get keys by pattern")
		return fmt.Errorf("failed to get keys by pattern: %w", err)
	}

	if len(keys) == 0 {
		logger.Log.WithField("pattern", pattern).Debug("No keys found matching pattern")
		return nil
	}

	// Delete all matching keys
	deleted, err := c.rdb.Del(ctxWithTimeout, keys...).Result()
	if err != nil {
		logger.Log.WithError(err).WithField("pattern", pattern).Error("Failed to delete keys by pattern")
		return fmt.Errorf("failed to delete keys by pattern: %w", err)
	}

	logger.Log.WithField("pattern", pattern).
		WithField("deleted_count", deleted).
		Debug("Keys deleted by pattern")
	return nil
}

// ✅ NEW: Cache warming helper
func (c *Client) WarmCache(ctx context.Context, warmupFunc func(context.Context) error) error {
	if !c.enabled {
		return nil
	}

	logger.Log.Info("Starting cache warmup")
	start := time.Now()

	if err := warmupFunc(ctx); err != nil {
		logger.Log.WithError(err).Error("Cache warmup failed")
		return err
	}

	duration := time.Since(start)
	logger.Log.WithField("duration", duration).Info("Cache warmup completed")
	return nil
}

func (c *Client) Close() error {
	if c.rdb != nil {
		return c.rdb.Close()
	}
	return nil
}

func (c *Client) IsEnabled() bool {
	return c.enabled && c.rdb != nil
}

// ✅ NEW: Cache statistics
func (c *Client) GetStats(ctx context.Context) (map[string]interface{}, error) {
	if !c.enabled || c.rdb == nil {
		return map[string]interface{}{
			"enabled": false,
		}, nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Get basic Redis info
	info, err := c.rdb.Info(ctxWithTimeout, "memory", "keyspace").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get Redis info: %w", err)
	}

	// Count keys by pattern
	userKeys, _ := c.rdb.Keys(ctxWithTimeout, "user:*").Result()
	groupKeys, _ := c.rdb.Keys(ctxWithTimeout, "group:*").Result()
	configKeys, _ := c.rdb.Keys(ctxWithTimeout, "config:*").Result()
	filterKeys, _ := c.rdb.Keys(ctxWithTimeout, "*:filter:*").Result()

	stats := map[string]interface{}{
		"enabled": true,
		"info":    info,
		"key_counts": map[string]int{
			"users":   len(userKeys),
			"groups":  len(groupKeys),
			"config":  len(configKeys),
			"filters": len(filterKeys),
		},
		"ttl_settings": map[string]string{
			"user_ttl":       UserTTL.String(),
			"group_ttl":      GroupTTL.String(),
			"list_ttl":       ListTTL.String(),
			"filtered_ttl":   FilteredTTL.String(),
			"config_ttl":     ConfigTTL.String(),
			"expiration_ttl": ExpirationTTL.String(),
		},
	}

	return stats, nil
}
