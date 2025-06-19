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

	// 🔥 Write-through caching: Cache the new user immediately
	userKey := r.getUserKey(user.Username)
	r.cache.SetAsync(ctx, userKey, user, redis.UserTTL)

	// 🔥 Async cache invalidation to avoid blocking
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.invalidateUserCaches(ctx, user.Username); err != nil {
			logger.Log.WithField("username", user.Username).WithError(err).Warn("Failed to invalidate cache after user creation")
		}
	}()

	logger.Log.WithField("username", user.Username).Debug("User created, cache updated")
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

	if user != nil {
		// 🔥 Async caching to avoid blocking the response
		r.cache.SetAsync(ctx, key, user, redis.UserTTL)
		logger.Log.WithField("username", username).Debug("User cached")
	}

	return user, nil
}

func (r *CachedUserRepository) Update(ctx context.Context, user *entities.User) error {
	err := r.repo.Update(ctx, user)
	if err != nil {
		return err
	}

	// 🔥 Invalidate related caches immediately to avoid stale data
	completeUser, err := r.repo.GetByUsername(ctx, user.Username)
	if err != nil {
		// If we can't get complete user, invalidate cache instead
		logger.Log.WithField("username", user.Username).
			WithError(err).
			Warn("Failed to get complete user for cache after update, invalidating cache")

		userKey := r.getUserKey(user.Username)
		r.cache.DelAsync(ctx, userKey)
		return nil
	}

	// Cache complete object (not partial object)
	userKey := r.getUserKey(user.Username)
	r.cache.SetAsync(ctx, userKey, completeUser, redis.UserTTL)

	logger.Log.WithField("username", user.Username).Debug("User updated, cache refreshed")
	return nil
}

func (r *CachedUserRepository) Delete(ctx context.Context, username string) error {
	err := r.repo.Delete(ctx, username)
	if err != nil {
		return err
	}

	// 🔥 Immediate cache deletion for removes
	userKey := r.getUserKey(username)
	r.cache.DelAsync(ctx, userKey)

	// 🔥 Async invalidation for related caches
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.invalidateUserCaches(ctx, username); err != nil {
			logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after user deletion")
		}
	}()

	logger.Log.WithField("username", username).Debug("User deleted, cache cleared")
	return nil
}

// ✅ ENHANCED: Now supports caching filtered queries with smart strategy
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
		// 🔥 Smart caching strategy for filtered queries
		if r.shouldCacheFilter(filter) {
			cacheKey = r.cache.GenerateFilterKey("users", filter)
			useCache = true
			ttl = redis.FilteredTTL
			logger.Log.WithField("filter_key", cacheKey).Debug("Generated cache key for filtered user query")
		} else {
			// Don't cache very specific or one-time filters
			useCache = false
			logger.Log.Debug("Skipping cache for specific filter")
		}
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
	if useCache && len(users) > 0 {
		// 🔥 Async caching to not block response
		r.cache.SetAsync(ctx, cacheKey, users, ttl)
		logger.Log.WithField("cache_key", cacheKey).WithField("ttl", ttl).Debug("User list cached")
	}

	return users, nil
}

// 🔥 Smart filter caching strategy - only cache common filters
func (r *CachedUserRepository) shouldCacheFilter(filter *entities.UserFilter) bool {
	// Don't cache very specific searches (likely one-time queries)
	if filter.Username != "" || filter.Email != "" || filter.MacAddress != "" {
		return false
	}

	// Don't cache searches with exact match (usually one-time)
	if filter.ExactMatch {
		return false
	}

	// Cache common administrative filters
	if filter.IsEnabled != nil || filter.GroupName != "" || filter.Role != "" {
		return true
	}

	// Cache expiration-related queries (commonly used)
	if filter.ExpiringInDays != nil || filter.IncludeExpired != nil {
		return true
	}

	// Cache pagination queries
	if filter.Limit > 0 || filter.Offset > 0 {
		return true
	}

	// Cache text searches only if they're not too specific
	if filter.SearchText != "" && len(filter.SearchText) <= 3 {
		return true
	}

	return false
}

func (r *CachedUserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	// 🔥 Leverage cached user data if available
	key := r.getUserKey(username)
	var cachedUser entities.User
	if err := r.cache.Get(ctx, key, &cachedUser); err == nil {
		return true, nil
	}

	// Check negative cache before hitting repository
	negativeKey := fmt.Sprintf("user_not_exists:%s", username)
	var notExists bool
	if err := r.cache.Get(ctx, negativeKey, &notExists); err == nil && notExists {
		return false, nil
	}

	// Cache miss - check repository
	exists, err := r.repo.ExistsByUsername(ctx, username)
	if err != nil {
		return false, err
	}

	// 🔥 Cache negative results briefly to prevent repeated DB queries
	if !exists {
		r.cache.SetAsync(ctx, negativeKey, true, 1*time.Minute)
	} else {
		// remove stale negative entry if user exists
		r.cache.DelAsync(ctx, negativeKey)
	}

	return exists, nil
}

func (r *CachedUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	// 🔥 Cache email existence checks (useful for validation)
	cacheKey := fmt.Sprintf("email_exists:%s", email)
	var exists bool

	if err := r.cache.Get(ctx, cacheKey, &exists); err == nil {
		return exists, nil
	}

	// Cache miss - check repository
	exists, err := r.repo.ExistsByEmail(ctx, email)
	if err != nil {
		return false, err
	}

	// 🔥 Cache result briefly
	r.cache.SetAsync(ctx, cacheKey, exists, 2*time.Minute)

	return exists, nil
}

func (r *CachedUserRepository) Enable(ctx context.Context, username string) error {
	err := r.repo.Enable(ctx, username)
	if err != nil {
		return err
	}

	// 🔥 Async cache invalidation
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.invalidateUserCaches(ctx, username); err != nil {
			logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after user enable")
		}
	}()

	return nil
}

func (r *CachedUserRepository) Disable(ctx context.Context, username string) error {
	err := r.repo.Disable(ctx, username)
	if err != nil {
		return err
	}

	// 🔥 Async cache invalidation
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.invalidateUserCaches(ctx, username); err != nil {
			logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after user disable")
		}
	}()

	return nil
}

func (r *CachedUserRepository) UserPropDel(ctx context.Context, user *entities.User) error {
	err := r.repo.UserPropDel(ctx, user)
	if err != nil {
		return err
	}

	// 🔥 Invalidate caches synchronously to maintain update flow
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

	// 🔥 Async cache invalidation
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.invalidateUserCaches(ctx, username); err != nil {
			logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after password change")
		}
	}()

	logger.Log.WithField("username", username).Debug("Password updated, cache invalidated")
	return nil
}

func (r *CachedUserRepository) RegenerateTOTP(ctx context.Context, username string) error {
	err := r.repo.RegenerateTOTP(ctx, username)
	if err != nil {
		return err
	}

	// 🔥 Async cache invalidation
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.invalidateUserCaches(ctx, username); err != nil {
			logger.Log.WithField("username", username).WithError(err).Warn("Failed to invalidate cache after TOTP regeneration")
		}
	}()

	logger.Log.WithField("username", username).Debug("TOTP regenerated, cache invalidated")
	return nil
}

// ✅ ENHANCED: Cache expiring users with smart TTL
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

	// 🔥 Cache with short TTL as expiration data changes frequently
	r.cache.SetAsync(ctx, cacheKey, users, redis.ExpirationTTL)
	logger.Log.WithField("days", days).Debug("Expiring users cached")

	return users, nil
}

// ✅ HELPER METHODS

func (r *CachedUserRepository) getUserKey(username string) string {
	return fmt.Sprintf("user:%s", username)
}

// 🔥 Enhanced cache invalidation with smart batching
func (r *CachedUserRepository) invalidateUserCaches(ctx context.Context, username string) error {
	userKey := r.getUserKey(username)
	listKey := "users:list"

	// Delete individual user and basic list
	if err := r.cache.DelMultiple(ctx, userKey, listKey); err != nil {
		return err
	}

	// 🔥 Async deletion of pattern-based caches to avoid blocking
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Delete all filtered user queries
		if err := r.cache.DeleteByPattern(ctx, "users:filter:*"); err != nil {
			logger.Log.WithError(err).Warn("Failed to delete filtered user cache by pattern")
		}

		// Delete expiration caches
		if err := r.cache.DeleteByPattern(ctx, "expiration:*"); err != nil {
			logger.Log.WithError(err).Warn("Failed to delete expiration cache by pattern")
		}

		// Delete email existence caches
		if err := r.cache.DeleteByPattern(ctx, "email_exists:*"); err != nil {
			logger.Log.WithError(err).Warn("Failed to delete email existence cache by pattern")
		}

		// Delete negative caches
		if err := r.cache.DeleteByPattern(ctx, "user_not_exists:*"); err != nil {
			logger.Log.WithError(err).Warn("Failed to delete negative cache by pattern")
		}
	}()

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

// WarmupCache preloads commonly accessed users into cache
func (r *CachedUserRepository) WarmupCache(ctx context.Context) error {
	users, err := r.repo.List(ctx, &entities.UserFilter{Limit: 100})
	if err != nil {
		return err
	}

	kvs := make([]redis.KeyValue, 0, len(users)+1)
	kvs = append(kvs, redis.KeyValue{Key: "users:list", Value: users, TTL: redis.ListTTL})
	for _, u := range users {
		kvs = append(kvs, redis.KeyValue{Key: r.getUserKey(u.Username), Value: u, TTL: redis.UserTTL})
	}

	return r.cache.SetMultiple(ctx, kvs)
}
