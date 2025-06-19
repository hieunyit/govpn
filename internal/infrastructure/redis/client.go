package redis

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"govpn/pkg/config"
	"govpn/pkg/logger"
	"sync"
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

	// 🔥 Simple performance enhancements
	writeQueue   chan writeOperation
	workers      int
	asyncEnabled bool           // 🔥 Flag để enable/disable async operations khi có vấn đề
	stopChan     chan struct{}  // signal channel to stop monitorQueue
	wg           sync.WaitGroup // wait group to ensure workers exit cleanly
	metrics      struct {
		hits   int64
		misses int64
		errors int64
		mu     sync.RWMutex
	}
}

type writeOperation struct {
	operation string
	key       string
	value     interface{}
	ttl       time.Duration
	ctx       context.Context
	retry     int
}

// KeyValue represents a value to be cached with its TTL.
type KeyValue struct {
	Key   string
	Value interface{}
	TTL   time.Duration
}

func NewClient(cfg config.RedisConfig) (*Client, error) {
	client := &Client{
		enabled:      cfg.Enabled,
		ttl:          cfg.TTL,                         // Default TTL from config
		workers:      5,                               // 🔥 Background workers for async operations
		writeQueue:   make(chan writeOperation, 1000), // 🔥 Buffer for async operations
		asyncEnabled: true,                            // 🔥 Enable async operations by default
		stopChan:     make(chan struct{}),
	}

	if !cfg.Enabled {
		logger.Log.Info("Redis is disabled")
		return client, nil
	}

	logger.Log.WithField("host", cfg.Host).
		WithField("port", cfg.Port).
		WithField("pool_size", cfg.PoolSize).
		Info("Connecting to Redis")

	// 🔥 Enhanced Redis options với timeout dài hơn để tránh context canceled
	client.rdb = redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.Database,
		PoolSize:     cfg.PoolSize,           // 🔥 Sử dụng pool size từ config
		MinIdleConns: max(cfg.PoolSize/3, 5), // 🔥 Keep minimum idle connections
		MaxRetries:   3,                      // 🔥 Retry failed operations
		DialTimeout:  10 * time.Second,       // 🔥 Tăng connection timeout từ 5s -> 10s
		ReadTimeout:  8 * time.Second,        // 🔥 Tăng read timeout từ 3s -> 8s
		WriteTimeout: 8 * time.Second,        // 🔥 Tăng write timeout từ 3s -> 8s
		PoolTimeout:  10 * time.Second,       // 🔥 Tăng pool timeout từ 4s -> 10s
	})

	// 🔥 Start background workers for async operations
	client.startAsyncWorkers()

	// 🔥 Start queue monitor
	client.wg.Add(1)
	go func() {
		defer client.wg.Done()
		client.monitorQueue()
	}()

	// Test connection
	if err := client.Ping(context.Background()); err != nil {
		logger.Log.WithError(err).Error("Failed to connect to Redis")
		return nil, err
	}

	logger.Log.Info("Successfully connected to Redis")
	return client, nil
}

// Helper function for Go versions that don't have max builtin
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// 🔥 Start background workers for async operations
func (c *Client) startAsyncWorkers() {
	for i := 0; i < c.workers; i++ {
		c.wg.Add(1)
		go func(workerID int) {
			defer c.wg.Done()
			for op := range c.writeQueue {
				c.processAsyncOperation(op, workerID)
			}
		}(i)
	}
}

// 🔥 Monitor queue health and log warnings
func (c *Client) monitorQueue() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			queueLen := len(c.writeQueue)
			queueCap := cap(c.writeQueue)
			usage := float64(queueLen) / float64(queueCap) * 100

			if usage > 80 {
				logger.Log.WithField("queue_len", queueLen).
					WithField("queue_cap", queueCap).
					WithField("usage", fmt.Sprintf("%.1f%%", usage)).
					Warn("Redis async queue is nearly full")
			} else if usage > 50 {
				logger.Log.WithField("queue_len", queueLen).
					WithField("usage", fmt.Sprintf("%.1f%%", usage)).
					Info("Redis async queue usage is moderate")
			}
		case <-c.stopChan:
			logger.Log.Debug("Stopping Redis queue monitor")
			return
		}
	}
}

// 🔥 Process async operations with better context handling
func (c *Client) processAsyncOperation(op writeOperation, workerID int) {
	// 🔥 Tạo context riêng với timeout dài hơn cho async operations
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var err error

	switch op.operation {
	case "set":
		err = c.setWithTTL(ctx, op.key, op.value, op.ttl)
	case "del":
		err = c.del(ctx, op.key)
	}

	if err != nil {
		c.incrementErrors()

		// 🔥 Better error handling for async operations
		if err == context.Canceled || err == context.DeadlineExceeded {
			logger.Log.WithField("worker", workerID).
				WithField("key", op.key).
				WithField("operation", op.operation).
				Warn("Async operation timeout/canceled")
		}

		// 🔥 Simple retry logic with longer delays
		if op.retry < 2 {
			retryDelay := time.Duration(op.retry+1) * 2 * time.Second // 🔥 Tăng delay
			time.Sleep(retryDelay)

			op.retry++
			select {
			case c.writeQueue <- op:
				logger.Log.WithField("worker", workerID).
					WithField("key", op.key).
					WithField("retry", op.retry).
					Debug("Retrying async operation")
			default:
				logger.Log.WithField("worker", workerID).
					WithField("key", op.key).
					Warn("Write queue full, dropping retry operation")
			}
		} else {
			logger.Log.WithField("worker", workerID).
				WithField("key", op.key).
				WithField("operation", op.operation).
				Error("Async operation failed after retries")
		}
	}
}

func (c *Client) Ping(ctx context.Context) error {
	if !c.enabled || c.rdb == nil {
		return nil
	}

	// 🔥 Tăng timeout cho ping
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := c.rdb.Ping(ctxWithTimeout).Err()
	if err != nil && (err == context.Canceled || err == context.DeadlineExceeded) {
		logger.Log.Warn("Redis ping timeout")
	}
	return err
}

// ✅ ENHANCED: Set with custom TTL (giữ nguyên interface từ code gốc)
func (c *Client) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if !c.enabled || c.rdb == nil {
		logger.Log.Debug("Redis is disabled, skipping SetWithTTL operation")
		return nil
	}

	return c.setWithTTL(ctx, key, value, ttl)
}

func (c *Client) setWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		c.incrementErrors()
		logger.Log.WithError(err).WithField("key", key).Error("Failed to marshal data for Redis")
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// 🔥 Tăng timeout và tạo context riêng cho async operations
	var ctxWithTimeout context.Context
	var cancel context.CancelFunc

	// Nếu context gốc đã có deadline, sử dụng nó, nếu không tạo timeout mới
	if deadline, ok := ctx.Deadline(); ok {
		ctxWithTimeout, cancel = context.WithDeadline(context.Background(), deadline)
	} else {
		ctxWithTimeout, cancel = context.WithTimeout(context.Background(), 10*time.Second) // 🔥 Tăng từ 5s -> 10s
	}
	defer cancel()

	err = c.rdb.Set(ctxWithTimeout, key, data, ttl).Err()
	if err != nil {
		c.incrementErrors()
		// 🔥 Cải thiện error logging
		if err == context.Canceled {
			logger.Log.WithField("key", key).WithField("ttl", ttl).Warn("Redis set operation canceled")
		} else if err == context.DeadlineExceeded {
			logger.Log.WithField("key", key).WithField("ttl", ttl).Warn("Redis set operation timeout")
		} else {
			logger.Log.WithError(err).WithField("key", key).Error("Failed to set data in Redis")
		}
		return fmt.Errorf("failed to set data in Redis: %w", err)
	}

	logger.Log.WithField("key", key).WithField("ttl", ttl).Debug("Data cached successfully with custom TTL")
	return nil
}

// Original Set method (uses default TTL) - giữ nguyên từ code gốc
func (c *Client) Set(ctx context.Context, key string, value interface{}) error {
	return c.SetWithTTL(ctx, key, value, c.ttl)
}

// 🔥 NEW: Async Set with improved context handling
func (c *Client) SetAsync(ctx context.Context, key string, value interface{}, ttl time.Duration) {
	if !c.enabled || c.rdb == nil {
		return
	}

	// 🔥 Fallback to sync if async is disabled due to issues
	if !c.asyncEnabled {
		c.SetWithTTL(ctx, key, value, ttl)
		return
	}

	op := writeOperation{
		operation: "set",
		key:       key,
		value:     value,
		ttl:       ttl,
		ctx:       context.Background(), // 🔥 Sử dụng background context để tránh timeout từ request context
		retry:     0,
	}

	select {
	case c.writeQueue <- op:
		// Successfully queued for background processing
		logger.Log.WithField("key", key).Debug("Async set operation queued")
	default:
		// Queue is full, fallback to synchronous operation
		logger.Log.WithField("key", key).Warn("Write queue full, falling back to sync operation")
		c.SetWithTTL(ctx, key, value, ttl)
	}
}

// Get method - tăng timeout và better error handling
func (c *Client) Get(ctx context.Context, key string, dest interface{}) error {
	if !c.enabled || c.rdb == nil {
		return redis.Nil
	}

	// 🔥 Tăng timeout cho Get operations
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	data, err := c.rdb.Get(ctxWithTimeout, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			c.incrementMisses()
			logger.Log.WithField("key", key).Debug("Cache miss")
		} else if err == context.Canceled || err == context.DeadlineExceeded {
			c.incrementErrors()
			logger.Log.WithField("key", key).Warn("Redis get operation timeout")
		} else {
			c.incrementErrors()
			logger.Log.WithError(err).WithField("key", key).Error("Failed to get data from Redis")
		}
		return err
	}

	err = json.Unmarshal(data, dest)
	if err != nil {
		c.incrementErrors()
		logger.Log.WithError(err).WithField("key", key).Error("Failed to unmarshal data from Redis")
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	c.incrementHits()
	logger.Log.WithField("key", key).Debug("Cache hit")
	return nil
}

// Del method - giữ nguyên từ code gốc
func (c *Client) Del(ctx context.Context, key string) error {
	if !c.enabled || c.rdb == nil {
		logger.Log.Debug("Redis is disabled, skipping Del operation")
		return nil
	}

	return c.del(ctx, key)
}

func (c *Client) del(ctx context.Context, key string) error {
	// 🔥 Tăng timeout cho delete operations
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	deleted, err := c.rdb.Del(ctxWithTimeout, key).Result()
	if err != nil {
		c.incrementErrors()
		if err == context.Canceled || err == context.DeadlineExceeded {
			logger.Log.WithField("key", key).Warn("Redis delete operation timeout")
		} else {
			logger.Log.WithError(err).WithField("key", key).Error("Failed to delete key from Redis")
		}
		return fmt.Errorf("failed to delete key from Redis: %w", err)
	}

	if deleted > 0 {
		logger.Log.WithField("key", key).Debug("Key deleted from cache")
	} else {
		logger.Log.WithField("key", key).Debug("Key not found in cache")
	}
	return nil
}

// 🔥 NEW: Async Delete with improved context handling
func (c *Client) DelAsync(ctx context.Context, key string) {
	if !c.enabled || c.rdb == nil {
		return
	}

	// 🔥 Fallback to sync if async is disabled due to issues
	if !c.asyncEnabled {
		c.Del(ctx, key)
		return
	}

	op := writeOperation{
		operation: "del",
		key:       key,
		ctx:       context.Background(), // 🔥 Sử dụng background context để tránh timeout
		retry:     0,
	}

	select {
	case c.writeQueue <- op:
		// Successfully queued
		logger.Log.WithField("key", key).Debug("Async delete operation queued")
	default:
		// Fallback to sync
		logger.Log.WithField("key", key).Warn("Write queue full, falling back to sync delete")
		c.Del(ctx, key)
	}
}

// FlushAll method - giữ nguyên từ code gốc
func (c *Client) FlushAll(ctx context.Context) error {
	if !c.enabled || c.rdb == nil {
		logger.Log.Debug("Redis is disabled, skipping FlushAll operation")
		return nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := c.rdb.FlushDB(ctxWithTimeout).Err()
	if err != nil {
		c.incrementErrors()
		logger.Log.WithError(err).Error("Failed to flush Redis database")
		return fmt.Errorf("failed to flush Redis database: %w", err)
	}

	logger.Log.Info("Redis database flushed successfully")
	return nil
}

// DelMultiple method - giữ nguyên từ code gốc
func (c *Client) DelMultiple(ctx context.Context, keys ...string) error {
	if !c.enabled || c.rdb == nil || len(keys) == 0 {
		return nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	deleted, err := c.rdb.Del(ctxWithTimeout, keys...).Result()
	if err != nil {
		c.incrementErrors()
		logger.Log.WithError(err).WithField("keys", keys).Error("Failed to delete multiple keys from Redis")
		return fmt.Errorf("failed to delete multiple keys: %w", err)
	}

	logger.Log.WithField("deleted_count", deleted).WithField("requested_count", len(keys)).Debug("Multiple keys deleted from cache")
	return nil
}

// SetMultiple sets several key/value pairs using a pipeline for efficiency.
func (c *Client) SetMultiple(ctx context.Context, kvs []KeyValue) error {
	if !c.enabled || c.rdb == nil || len(kvs) == 0 {
		return nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	pipe := c.rdb.Pipeline()

	for _, kv := range kvs {
		data, err := json.Marshal(kv.Value)
		if err != nil {
			c.incrementErrors()
			return fmt.Errorf("failed to marshal value for key %s: %w", kv.Key, err)
		}
		pipe.Set(ctxWithTimeout, kv.Key, data, kv.TTL)
	}

	if _, err := pipe.Exec(ctxWithTimeout); err != nil {
		c.incrementErrors()
		return fmt.Errorf("failed to set multiple keys: %w", err)
	}

	logger.Log.WithField("count", len(kvs)).Debug("Multiple keys set via pipeline")
	return nil
}

// Exists method - giữ nguyên từ code gốc
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	if !c.enabled || c.rdb == nil {
		return false, nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	exists, err := c.rdb.Exists(ctxWithTimeout, key).Result()
	if err != nil {
		c.incrementErrors()
		logger.Log.WithError(err).WithField("key", key).Error("Failed to check key existence in Redis")
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}

	return exists == 1, nil
}

// Helper methods - giữ nguyên từ code gốc
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

func (c *Client) GenerateConfigKey(configType string) string {
	return fmt.Sprintf("config:%s", configType)
}

func (c *Client) GenerateExpirationKey(days int, includeExpired bool) string {
	return fmt.Sprintf("expiration:days:%d:expired:%t", days, includeExpired)
}

// 🔥 ENHANCED: DeleteByPattern with SCAN for large datasets
func (c *Client) DeleteByPattern(ctx context.Context, pattern string) error {
	if !c.enabled || c.rdb == nil {
		return nil
	}

	// 🔥 Use SCAN instead of KEYS for large datasets to avoid blocking Redis
	var cursor uint64
	batchSize := 1000
	totalDeleted := 0

	for {
		scanCtx, scanCancel := context.WithTimeout(ctx, 10*time.Second)
		keys, nextCursor, err := c.rdb.Scan(scanCtx, cursor, pattern, int64(batchSize)).Result()
		scanCancel()
		if err != nil {
			c.incrementErrors()
			return fmt.Errorf("failed to scan keys with pattern %s: %w", pattern, err)
		}

		if len(keys) > 0 {
			delCtx, delCancel := context.WithTimeout(ctx, 10*time.Second)
			if err := c.rdb.Del(delCtx, keys...).Err(); err != nil {
				c.incrementErrors()
				logger.Log.WithError(err).WithField("pattern", pattern).Warn("Failed to delete some keys in batch")
			} else {
				totalDeleted += len(keys)
			}
			delCancel()
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	logger.Log.WithField("pattern", pattern).
		WithField("deleted_count", totalDeleted).
		Debug("Keys deleted by pattern")
	return nil
}

// 🔥 NEW: Performance monitoring methods
func (c *Client) incrementHits() {
	c.metrics.mu.Lock()
	c.metrics.hits++
	c.metrics.mu.Unlock()
}

func (c *Client) incrementMisses() {
	c.metrics.mu.Lock()
	c.metrics.misses++
	c.metrics.mu.Unlock()
}

func (c *Client) incrementErrors() {
	c.metrics.mu.Lock()
	c.metrics.errors++
	c.metrics.mu.Unlock()
}

func (c *Client) GetMetrics() map[string]interface{} {
	c.metrics.mu.RLock()
	defer c.metrics.mu.RUnlock()

	total := c.metrics.hits + c.metrics.misses
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(c.metrics.hits) / float64(total) * 100
	}

	return map[string]interface{}{
		"hits":          c.metrics.hits,
		"misses":        c.metrics.misses,
		"errors":        c.metrics.errors,
		"hit_rate":      fmt.Sprintf("%.2f%%", hitRate),
		"total":         total,
		"enabled":       c.enabled,
		"async_enabled": c.asyncEnabled,
		"queue_len":     len(c.writeQueue),
		"queue_cap":     cap(c.writeQueue),
		"workers":       c.workers,
		"queue_usage":   fmt.Sprintf("%.1f%%", float64(len(c.writeQueue))/float64(cap(c.writeQueue))*100),
	}
}

// WarmCache method - giữ nguyên từ code gốc
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
	// Close write queue
	if c.writeQueue != nil {
		close(c.writeQueue)
	}

	// Signal monitor goroutine to stop
	if c.stopChan != nil {
		close(c.stopChan)
	}

	// Wait for background workers and monitor to finish
	c.wg.Wait()

	if c.rdb != nil {
		return c.rdb.Close()
	}
	return nil
}

func (c *Client) IsEnabled() bool {
	return c.enabled && c.rdb != nil
}

// ✅ ENHANCED: Cache statistics with performance metrics (giữ nguyên từ code gốc nhưng thêm metrics)
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
		c.incrementErrors()
		return nil, fmt.Errorf("failed to get Redis info: %w", err)
	}

	// Count keys by pattern using SCAN to avoid blocking
	countKeys := func(pattern string) int {
		var cursor uint64
		count := 0
		for {
			keys, next, err := c.rdb.Scan(ctxWithTimeout, cursor, pattern, 1000).Result()
			if err != nil {
				logger.Log.WithError(err).WithField("pattern", pattern).Warn("Failed to scan keys for stats")
				break
			}
			count += len(keys)
			cursor = next
			if cursor == 0 {
				break
			}
		}
		return count
	}

	userCount := countKeys("user:*")
	groupCount := countKeys("group:*")
	configCount := countKeys("config:*")
	filterCount := countKeys("*:filter:*")

	// Get performance metrics
	metrics := c.GetMetrics()

	stats := map[string]interface{}{
		"enabled": true,
		"info":    info,
		"key_counts": map[string]int{
			"users":   userCount,
			"groups":  groupCount,
			"config":  configCount,
			"filters": filterCount,
		},
		"ttl_settings": map[string]string{
			"user_ttl":       UserTTL.String(),
			"group_ttl":      GroupTTL.String(),
			"list_ttl":       ListTTL.String(),
			"filtered_ttl":   FilteredTTL.String(),
			"config_ttl":     ConfigTTL.String(),
			"expiration_ttl": ExpirationTTL.String(),
		},
		"performance_metrics": metrics,
	}

	return stats, nil
}
