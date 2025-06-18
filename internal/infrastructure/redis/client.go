package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"govpn/pkg/config"
	"govpn/pkg/logger"
	"time"

	"github.com/redis/go-redis/v9"
)

type Client struct {
	rdb     *redis.Client
	enabled bool
	ttl     time.Duration
	ctx     context.Context
}

func NewClient(cfg config.RedisConfig) (*Client, error) {
	client := &Client{
		enabled: cfg.Enabled,
		ttl:     cfg.TTL,
		ctx:     context.Background(),
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
	if err := client.Ping(); err != nil {
		logger.Log.WithError(err).Error("Failed to connect to Redis")
		return nil, err
	}

	logger.Log.Info("Successfully connected to Redis")
	return client, nil
}

func (c *Client) Ping() error {
	if !c.enabled || c.rdb == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()

	return c.rdb.Ping(ctx).Err()
}

func (c *Client) Set(key string, value interface{}) error {
	if !c.enabled || c.rdb == nil {
		return nil
	}

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()

	return c.rdb.Set(ctx, key, data, c.ttl).Err()
}

func (c *Client) Get(key string, dest interface{}) error {
	if !c.enabled || c.rdb == nil {
		return redis.Nil
	}

	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()

	data, err := c.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

func (c *Client) Del(key string) error {
	if !c.enabled || c.rdb == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()

	return c.rdb.Del(ctx, key).Err()
}

func (c *Client) FlushAll() error {
	if !c.enabled || c.rdb == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	return c.rdb.FlushDB(ctx).Err()
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
