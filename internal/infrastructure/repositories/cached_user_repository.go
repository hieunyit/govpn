package repositories

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/redis"
	"govpn/pkg/logger"

	redisLib "github.com/redis/go-redis/v9"
)

type CachedUserRepository struct {
	repo  repositories.UserRepository
	cache *redis.Client
}

func NewCachedUserRepository(repo repositories.UserRepository, cache *redis.Client) repositories.UserRepository {
	return &CachedUserRepository{
		repo:  repo,
		cache: cache,
	}
}

func (r *CachedUserRepository) Create(ctx context.Context, user *entities.User) error {
	err := r.repo.Create(ctx, user)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getUserKey(user.Username))
	r.cache.Del("users:list")

	logger.Log.WithField("username", user.Username).Debug("User created, cache invalidated")
	return nil
}

func (r *CachedUserRepository) GetByUsername(ctx context.Context, username string) (*entities.User, error) {
	// Try cache first
	key := r.getUserKey(username)
	var cachedUser entities.User
	if err := r.cache.Get(key, &cachedUser); err == nil {
		logger.Log.WithField("username", username).Debug("User retrieved from cache")
		return &cachedUser, nil
	} else if err != redisLib.Nil {
		logger.Log.WithField("username", username).WithError(err).Warn("Cache error")
	}

	// Cache miss - get from repository
	user, err := r.repo.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if cacheErr := r.cache.Set(key, user); cacheErr != nil {
		logger.Log.WithField("username", username).WithError(cacheErr).Warn("Failed to cache user")
	} else {
		logger.Log.WithField("username", username).Debug("User cached")
	}

	return user, nil
}

func (r *CachedUserRepository) Update(ctx context.Context, user *entities.User) error {
	err := r.repo.Update(ctx, user)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getUserKey(user.Username))
	r.cache.Del("users:list")

	logger.Log.WithField("username", user.Username).Debug("User updated, cache invalidated")
	return nil
}

func (r *CachedUserRepository) Delete(ctx context.Context, username string) error {
	err := r.repo.Delete(ctx, username)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getUserKey(username))
	r.cache.Del("users:list")

	logger.Log.WithField("username", username).Debug("User deleted, cache invalidated")
	return nil
}

func (r *CachedUserRepository) List(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, error) {
	// For simple implementation, only cache if no filter
	if filter != nil {
		return r.repo.List(ctx, filter)
	}

	// Try cache first
	key := "users:list"
	var cachedUsers []*entities.User
	if err := r.cache.Get(key, &cachedUsers); err == nil {
		logger.Log.Debug("User list retrieved from cache")
		return cachedUsers, nil
	} else if err != redisLib.Nil {
		logger.Log.WithError(err).Warn("Cache error getting user list")
	}

	// Cache miss - get from repository
	users, err := r.repo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if cacheErr := r.cache.Set(key, users); cacheErr != nil {
		logger.Log.WithError(cacheErr).Warn("Failed to cache user list")
	} else {
		logger.Log.Debug("User list cached")
	}

	return users, nil
}

func (r *CachedUserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	// Check cache first
	key := r.getUserKey(username)
	var cachedUser entities.User
	if err := r.cache.Get(key, &cachedUser); err == nil {
		return true, nil
	}

	// Cache miss - check repository
	return r.repo.ExistsByUsername(ctx, username)
}

func (r *CachedUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	return r.repo.ExistsByEmail(ctx, email)
}

func (r *CachedUserRepository) Enable(ctx context.Context, username string) error {
	err := r.repo.Enable(ctx, username)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getUserKey(username))
	r.cache.Del("users:list")

	return nil
}

func (r *CachedUserRepository) Disable(ctx context.Context, username string) error {
	err := r.repo.Disable(ctx, username)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getUserKey(username))
	r.cache.Del("users:list")

	return nil
}

func (r *CachedUserRepository) UserPropDel(ctx context.Context, user *entities.User) error {
	err := r.repo.UserPropDel(ctx, user)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getUserKey(user.Username))
	r.cache.Del("users:list")

	return nil
}

func (r *CachedUserRepository) SetPassword(ctx context.Context, username, password string) error {
	err := r.repo.SetPassword(ctx, username, password)
	if err != nil {
		return err
	}

	// Invalidate cache after password change
	r.cache.Del(r.getUserKey(username))
	r.cache.Del("users:list")

	logger.Log.WithField("username", username).Debug("Password updated, cache invalidated")
	return nil
}

func (r *CachedUserRepository) RegenerateTOTP(ctx context.Context, username string) error {
	err := r.repo.RegenerateTOTP(ctx, username)
	if err != nil {
		return err
	}

	// Invalidate cache after TOTP regeneration
	r.cache.Del(r.getUserKey(username))
	r.cache.Del("users:list")

	logger.Log.WithField("username", username).Debug("TOTP regenerated, cache invalidated")
	return nil
}

func (r *CachedUserRepository) GetExpiringUsers(ctx context.Context, days int) ([]string, error) {
	// Don't cache expiring users as it's time-sensitive data
	return r.repo.GetExpiringUsers(ctx, days)
}

func (r *CachedUserRepository) getUserKey(username string) string {
	return fmt.Sprintf("user:%s", username)
}
