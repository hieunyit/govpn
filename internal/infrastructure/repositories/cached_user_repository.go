package repositories

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/redis"
	"govpn/pkg/logger"
	"time"

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

	// Invalidate related caches
	if err := r.invalidateUserCaches(ctx, user.Username); err != nil {
		logger.Log.WithField("username", user.Username).WithError(err).Warn("Failed to invalidate cache after user creation")
	}

	logger.Log.WithField("username", user.Username).Debug("User created, cache invalidated")
	return nil
}

func (r *CachedUserRepository) GetByUsername(ctx context.Context, username string) (*entities.User, error) {
	// Try cache first
	key := r.getUserKey(username)
	var cachedUser entities.User
	if err := r.cache.Get(ctx, key, &cachedUser); err == nil {
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

	// Cache the result with user-specific TTL
	if cacheErr := r.cache.SetWithTTL(ctx, key, user, redis.UserTTL); cacheErr != nil {
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

	// Invalidate related caches
	if err := r.invalidateUserCaches(ctx, user.Username); err != nil {
		logger.Log.WithField("username", user.Username).WithError(err).Warn("Failed to invalidate cache after user update")
	}

	logger.Log.WithField("username", user.Username).Debug("User updated, cache invalidated")
	return nil
}

func (r *CachedUserRepository) Delete(ctx context.Context, username string) error {
	err := r.repo.Delete(ctx, username)
	if err != nil {
		return err
	}

	// Invalidate related caches
	if err := r.invalidateUserCaches(ctx, username); err != nil {
		logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after user deletion")
	}

	logger.Log.WithField("username", username).Debug("User deleted, cache invalidated")
	return nil
}

// ✅ ENHANCED: Now supports caching filtered queries
func (r *CachedUserRepository) List(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, error) {
	// Generate cache key based on filter
	var cacheKey string
	var useCache bool
	var ttl time.Duration

	if filter == nil || r.isEmptyFilter(filter) {
		// Simple list without filters - use basic cache
		cacheKey = "users:list"
		useCache = true
		ttl = redis.ListTTL
	} else {
		// ✅ NEW: Cache filtered queries with short TTL
		cacheKey = r.cache.GenerateFilterKey("users", filter)
		useCache = true
		ttl = redis.FilteredTTL
		logger.Log.WithField("filter_key", cacheKey).Debug("Generated cache key for filtered user query")
	}

	if useCache {
		// Try cache first
		var cachedUsers []*entities.User
		if err := r.cache.Get(ctx, cacheKey, &cachedUsers); err == nil {
			logger.Log.WithField("cache_key", cacheKey).Debug("User list retrieved from cache")
			return cachedUsers, nil
		} else if err != redisLib.Nil {
			logger.Log.WithField("cache_key", cacheKey).WithError(err).Warn("Cache error getting user list")
		}
	}

	// Cache miss - get from repository
	users, err := r.repo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Cache the result if caching is enabled for this query
	if useCache {
		if cacheErr := r.cache.SetWithTTL(ctx, cacheKey, users, ttl); cacheErr != nil {
			logger.Log.WithField("cache_key", cacheKey).WithError(cacheErr).Warn("Failed to cache user list")
		} else {
			logger.Log.WithField("cache_key", cacheKey).WithField("ttl", ttl).Debug("User list cached")
		}
	}

	return users, nil
}

func (r *CachedUserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	// Check cache first
	key := r.getUserKey(username)
	var cachedUser entities.User
	if err := r.cache.Get(ctx, key, &cachedUser); err == nil {
		return true, nil
	}

	// Cache miss - check repository
	return r.repo.ExistsByUsername(ctx, username)
}

func (r *CachedUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	// Email lookups are not cached in this implementation
	return r.repo.ExistsByEmail(ctx, email)
}

func (r *CachedUserRepository) Enable(ctx context.Context, username string) error {
	err := r.repo.Enable(ctx, username)
	if err != nil {
		return err
	}

	// Invalidate related caches
	if err := r.invalidateUserCaches(ctx, username); err != nil {
		logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after user enable")
	}

	return nil
}

func (r *CachedUserRepository) Disable(ctx context.Context, username string) error {
	err := r.repo.Disable(ctx, username)
	if err != nil {
		return err
	}

	// Invalidate related caches
	if err := r.invalidateUserCaches(ctx, username); err != nil {
		logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after user disable")
	}

	return nil
}

func (r *CachedUserRepository) UserPropDel(ctx context.Context, user *entities.User) error {
	err := r.repo.UserPropDel(ctx, user)
	if err != nil {
		return err
	}

	// Invalidate related caches
	if err := r.invalidateUserCaches(ctx, user.Username); err != nil {
		logger.Log.WithField("username", user.Username).WithError(err).Warn("Failed to invalidate cache after UserPropDel")
	}

	return nil
}

func (r *CachedUserRepository) SetPassword(ctx context.Context, username, password string) error {
	err := r.repo.SetPassword(ctx, username, password)
	if err != nil {
		return err
	}

	// Invalidate related caches
	if err := r.invalidateUserCaches(ctx, username); err != nil {
		logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after password change")
	}

	logger.Log.WithField("username", username).Debug("Password updated, cache invalidated")
	return nil
}

func (r *CachedUserRepository) RegenerateTOTP(ctx context.Context, username string) error {
	err := r.repo.RegenerateTOTP(ctx, username)
	if err != nil {
		return err
	}

	// Invalidate related caches
	if err := r.invalidateUserCaches(ctx, username); err != nil {
		logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after TOTP regeneration")
	}

	logger.Log.WithField("username", username).Debug("TOTP regenerated, cache invalidated")
	return nil
}

// ✅ ENHANCED: Cache expiring users with short TTL
func (r *CachedUserRepository) GetExpiringUsers(ctx context.Context, days int) ([]string, error) {
	// Generate cache key for expiring users
	cacheKey := r.cache.GenerateExpirationKey(days, false)

	// Try cache first
	var cachedUsers []string
	if err := r.cache.Get(ctx, cacheKey, &cachedUsers); err == nil {
		logger.Log.WithField("days", days).Debug("Expiring users retrieved from cache")
		return cachedUsers, nil
	} else if err != redisLib.Nil {
		logger.Log.WithField("days", days).WithError(err).Warn("Cache error getting expiring users")
	}

	// Cache miss - get from repository
	users, err := r.repo.GetExpiringUsers(ctx, days)
	if err != nil {
		return nil, err
	}

	// Cache the result with short TTL
	if cacheErr := r.cache.SetWithTTL(ctx, cacheKey, users, redis.ExpirationTTL); cacheErr != nil {
		logger.Log.WithField("days", days).WithError(cacheErr).Warn("Failed to cache expiring users")
	} else {
		logger.Log.WithField("days", days).Debug("Expiring users cached")
	}

	return users, nil
}

// ✅ HELPER METHODS

func (r *CachedUserRepository) getUserKey(username string) string {
	return fmt.Sprintf("user:%s", username)
}

// Enhanced cache invalidation - clears individual user, lists, and filtered queries
func (r *CachedUserRepository) invalidateUserCaches(ctx context.Context, username string) error {
	userKey := r.getUserKey(username)
	listKey := "users:list"

	// Delete individual user and basic list
	if err := r.cache.DelMultiple(ctx, userKey, listKey); err != nil {
		return err
	}

	// ✅ NEW: Delete all filtered user queries
	if err := r.cache.DeleteByPattern(ctx, "users:filter:*"); err != nil {
		logger.Log.WithError(err).Warn("Failed to delete filtered user cache by pattern")
		// Don't return error as this is not critical
	}

	// ✅ NEW: Delete expiration caches
	if err := r.cache.DeleteByPattern(ctx, "expiration:*"); err != nil {
		logger.Log.WithError(err).Warn("Failed to delete expiration cache by pattern")
		// Don't return error as this is not critical
	}

	return nil
}

// Helper to determine if filter is empty (for caching strategy)
func (r *CachedUserRepository) isEmptyFilter(filter *entities.UserFilter) bool {
	if filter == nil {
		return true
	}

	// Check if all filter fields are empty/default
	return filter.Username == "" &&
		filter.Email == "" &&
		filter.AuthMethod == "" &&
		filter.Role == "" &&
		filter.GroupName == "" &&
		filter.IsEnabled == nil &&
		filter.DenyAccess == nil &&
		filter.MFAEnabled == nil &&
		filter.UserExpirationAfter == nil &&
		filter.UserExpirationBefore == nil &&
		filter.IncludeExpired == nil &&
		filter.ExpiringInDays == nil &&
		filter.HasAccessControl == nil &&
		filter.MacAddress == "" &&
		filter.SearchText == "" &&
		filter.SortBy == "" &&
		// Don't check pagination fields for emptiness
		!filter.ExactMatch &&
		!filter.CaseSensitive
}
