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

type CachedGroupRepository struct {
	repo  repositories.GroupRepository
	cache *redis.Client
}

func NewCachedGroupRepository(repo repositories.GroupRepository, cache *redis.Client) repositories.GroupRepository {
	return &CachedGroupRepository{
		repo:  repo,
		cache: cache,
	}
}

func (r *CachedGroupRepository) Create(ctx context.Context, group *entities.Group) error {
	err := r.repo.Create(ctx, group)
	if err != nil {
		return err
	}

	// 🔥 Invalidate caches synchronously before caching new group
	if err := r.invalidateGroupCaches(ctx, group.GroupName); err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Warn("Failed to invalidate cache after group creation")
	}

	// 🔥 Write-through caching: Cache the new group immediately
	groupKey := r.getGroupKey(group.GroupName)
	r.cache.SetAsync(ctx, groupKey, group, redis.GroupTTL)

	logger.Log.WithField("groupName", group.GroupName).Debug("Group created, cache updated")
	return nil
}

func (r *CachedGroupRepository) GetByName(ctx context.Context, groupName string) (*entities.Group, error) {
	// Try cache first
	key := r.getGroupKey(groupName)
	var cachedGroup entities.Group
	if err := r.cache.Get(ctx, key, &cachedGroup); err == nil {
		logger.Log.WithField("groupName", groupName).Debug("Group retrieved from cache")
		return &cachedGroup, nil
	} else if err != redisLib.Nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Warn("Cache error")
	}

	// Cache miss - get from repository
	group, err := r.repo.GetByName(ctx, groupName)
	if err != nil {
		return nil, err
	}

	if group != nil {
		// 🔥 Async caching to avoid blocking the response
		r.cache.SetAsync(ctx, key, group, redis.GroupTTL)
		logger.Log.WithField("groupName", groupName).Debug("Group cached")
	}

	return group, nil
}

func (r *CachedGroupRepository) Update(ctx context.Context, group *entities.Group) error {
	err := r.repo.Update(ctx, group)
	if err != nil {
		return err
	}

	// 🔥 Invalidate caches synchronously before caching the updated group
	completeGroup, err := r.repo.GetByName(ctx, group.GroupName)
	if err != nil {
		logger.Log.WithField("groupName", group.GroupName).
			WithError(err).
			Warn("Failed to get complete group for cache after update, invalidating cache")

		groupKey := r.getGroupKey(group.GroupName)
		r.cache.DelAsync(ctx, groupKey)
		return nil
	}

	// Cache complete object
	groupKey := r.getGroupKey(group.GroupName)
	r.cache.SetAsync(ctx, groupKey, completeGroup, redis.GroupTTL)

	logger.Log.WithField("groupName", group.GroupName).Debug("Group updated, cache refreshed")
	return nil
}

func (r *CachedGroupRepository) Delete(ctx context.Context, groupName string) error {
	err := r.repo.Delete(ctx, groupName)
	if err != nil {
		return err
	}

	// 🔥 Immediate cache deletion for removes
	groupKey := r.getGroupKey(groupName)
	r.cache.DelAsync(ctx, groupKey)

	// 🔥 Invalidate related caches synchronously
	if err := r.invalidateGroupCaches(ctx, groupName); err != nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Warn("Failed to invalidate cache after group deletion")
	}

	logger.Log.WithField("groupName", groupName).Debug("Group deleted, cache cleared")
	return nil
}

func (r *CachedGroupRepository) GroupPropDel(ctx context.Context, group *entities.Group) error {
	err := r.repo.GroupPropDel(ctx, group)
	if err != nil {
		return err
	}

	// Invalidate related caches
	if err := r.invalidateGroupCaches(ctx, group.GroupName); err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Warn("Failed to invalidate cache after GroupPropDel")
	}

	return nil
}

// ✅ ENHANCED: Now supports caching filtered queries with smart strategy
func (r *CachedGroupRepository) List(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, error) {
	// Generate cache key based on filter
	var cacheKey string
	var useCache bool
	var ttl time.Duration

	if filter == nil || r.isEmptyFilter(filter) {
		// Simple list without filters - use basic cache with longer TTL (groups change less frequently)
		cacheKey = "groups:list"
		useCache = true
		ttl = redis.GroupTTL
	} else {
		// 🔥 Smart caching strategy for filtered queries
		if r.shouldCacheFilter(filter) {
			cacheKey = r.cache.GenerateFilterKey("groups", filter)
			useCache = true
			ttl = redis.FilteredTTL
			logger.Log.WithField("filter_key", cacheKey).Debug("Generated cache key for filtered group query")
		} else {
			// Don't cache very specific filters
			useCache = false
			logger.Log.Debug("Skipping cache for specific group filter")
		}
	}

	if useCache {
		// Try cache first
		var cachedGroups []*entities.Group
		if err := r.cache.Get(ctx, cacheKey, &cachedGroups); err == nil {
			logger.Log.WithField("cache_key", cacheKey).Debug("Group list retrieved from cache")
			return cachedGroups, nil
		} else if err != redisLib.Nil {
			logger.Log.WithField("cache_key", cacheKey).WithError(err).Warn("Cache error getting group list")
		}
	}

	// Cache miss - get from repository
	groups, err := r.repo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Cache the result if caching is enabled for this query
	if useCache && len(groups) > 0 {
		// 🔥 Async caching to not block response
		r.cache.SetAsync(ctx, cacheKey, groups, ttl)
		logger.Log.WithField("cache_key", cacheKey).WithField("ttl", ttl).Debug("Group list cached")
	}

	return groups, nil
}

// 🔥 Smart filter caching strategy - only cache common filters
func (r *CachedGroupRepository) shouldCacheFilter(filter *entities.GroupFilter) bool {
	// Don't cache very specific searches (likely one-time queries)
	if filter.GroupName != "" {
		return false
	}

	// Cache common administrative filters
	if filter.IsEnabled != nil {
		return true
	}

	// Cache pagination queries
	if filter.Limit > 0 || filter.Offset > 0 {
		return true
	}

	return false
}

func (r *CachedGroupRepository) ExistsByName(ctx context.Context, groupName string) (bool, error) {
	// 🔥 Leverage cached group data if available
	key := r.getGroupKey(groupName)
	var cachedGroup entities.Group
	if err := r.cache.Get(ctx, key, &cachedGroup); err == nil {
		return true, nil
	}

	// Check negative cache first
	negativeKey := fmt.Sprintf("group_not_exists:%s", groupName)
	var notExists bool
	if err := r.cache.Get(ctx, negativeKey, &notExists); err == nil && notExists {
		return false, nil
	}

	// Cache miss - check repository
	exists, err := r.repo.ExistsByName(ctx, groupName)
	if err != nil {
		return false, err
	}

	// 🔥 Cache negative results briefly to prevent repeated DB queries
	if !exists {
		r.cache.SetAsync(ctx, negativeKey, true, 1*time.Minute)
	} else {
		r.cache.DelAsync(ctx, negativeKey)
	}

	return exists, nil
}

func (r *CachedGroupRepository) Enable(ctx context.Context, groupName string) error {
	err := r.repo.Enable(ctx, groupName)
	if err != nil {
		return err
	}

	// 🔥 Invalidate caches synchronously
	if err := r.invalidateGroupCaches(ctx, groupName); err != nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Warn("Failed to invalidate cache after group enable")
	}

	return nil
}

func (r *CachedGroupRepository) Disable(ctx context.Context, groupName string) error {
	err := r.repo.Disable(ctx, groupName)
	if err != nil {
		return err
	}

	// 🔥 Invalidate caches synchronously
	if err := r.invalidateGroupCaches(ctx, groupName); err != nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Warn("Failed to invalidate cache after group disable")
	}

	return nil
}

func (r *CachedGroupRepository) ClearAccessControl(ctx context.Context, group *entities.Group) error {
	err := r.repo.ClearAccessControl(ctx, group)
	if err != nil {
		return err
	}

	// 🔥 Invalidate caches synchronously
	if err := r.invalidateGroupCaches(ctx, group.GroupName); err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Warn("Failed to invalidate cache after clearing access control")
	}

	return nil
}

// ✅ HELPER METHODS

func (r *CachedGroupRepository) getGroupKey(groupName string) string {
	return fmt.Sprintf("group:%s", groupName)
}

// 🔥 Enhanced cache invalidation with smart batching
func (r *CachedGroupRepository) invalidateGroupCaches(ctx context.Context, groupName string) error {
	groupKey := r.getGroupKey(groupName)
	listKey := "groups:list"

	// Delete individual group and basic list
	if err := r.cache.DelMultiple(ctx, groupKey, listKey); err != nil {
		return err
	}

	// 🔥 Async deletion of pattern-based caches to avoid blocking
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Delete all filtered group queries
		if err := r.cache.DeleteByPattern(ctx, "groups:filter:*"); err != nil {
			logger.Log.WithError(err).Warn("Failed to delete filtered group cache by pattern")
		}

		// Delete negative caches
		if err := r.cache.DeleteByPattern(ctx, "group_not_exists:*"); err != nil {
			logger.Log.WithError(err).Warn("Failed to delete negative group cache by pattern")
		}
	}()

	return nil
}

// Helper to determine if filter is empty (for caching strategy)
func (r *CachedGroupRepository) isEmptyFilter(filter *entities.GroupFilter) bool {
	if filter == nil {
		return true
	}

	return filter.GroupName == "" &&
		filter.IsEnabled == nil &&
		filter.Limit == 0 &&
		filter.Offset == 0
}

// WarmupCache preloads commonly accessed groups into cache
func (r *CachedGroupRepository) WarmupCache(ctx context.Context) error {
	groups, err := r.repo.List(ctx, &entities.GroupFilter{Limit: 100})
	if err != nil {
		return err
	}

	kvs := make([]redis.KeyValue, 0, len(groups)+1)
	kvs = append(kvs, redis.KeyValue{Key: "groups:list", Value: groups, TTL: redis.GroupTTL})
	for _, g := range groups {
		kvs = append(kvs, redis.KeyValue{Key: r.getGroupKey(g.GroupName), Value: g, TTL: redis.GroupTTL})
	}

	return r.cache.SetMultiple(ctx, kvs)
}
