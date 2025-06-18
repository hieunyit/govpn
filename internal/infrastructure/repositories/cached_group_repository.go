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

	// Invalidate related caches
	if err := r.invalidateGroupCaches(ctx, group.GroupName); err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Warn("Failed to invalidate cache after group creation")
	}

	logger.Log.WithField("groupName", group.GroupName).Debug("Group created, cache invalidated")
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

	// Cache the result with group-specific TTL
	if cacheErr := r.cache.SetWithTTL(ctx, key, group, redis.GroupTTL); cacheErr != nil {
		logger.Log.WithField("groupName", groupName).WithError(cacheErr).Warn("Failed to cache group")
	} else {
		logger.Log.WithField("groupName", groupName).Debug("Group cached")
	}

	return group, nil
}

func (r *CachedGroupRepository) Update(ctx context.Context, group *entities.Group) error {
	err := r.repo.Update(ctx, group)
	if err != nil {
		return err
	}

	// Invalidate related caches
	if err := r.invalidateGroupCaches(ctx, group.GroupName); err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Warn("Failed to invalidate cache after group update")
	}

	logger.Log.WithField("groupName", group.GroupName).Debug("Group updated, cache invalidated")
	return nil
}

func (r *CachedGroupRepository) Delete(ctx context.Context, groupName string) error {
	err := r.repo.Delete(ctx, groupName)
	if err != nil {
		return err
	}

	// Invalidate related caches
	if err := r.invalidateGroupCaches(ctx, groupName); err != nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Warn("Failed to invalidate cache after group deletion")
	}

	logger.Log.WithField("groupName", groupName).Debug("Group deleted, cache invalidated")
	return nil
}

// ✅ ENHANCED: Now supports caching filtered queries
func (r *CachedGroupRepository) List(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, error) {
	// Generate cache key based on filter
	var cacheKey string
	var useCache bool
	var ttl time.Duration

	if filter == nil || r.isEmptyFilter(filter) {
		// Simple list without filters - use basic cache
		cacheKey = "groups:list"
		useCache = true
		ttl = redis.ListTTL
	} else {
		// ✅ NEW: Cache filtered queries with short TTL
		cacheKey = r.cache.GenerateFilterKey("groups", filter)
		useCache = true
		ttl = redis.FilteredTTL
		logger.Log.WithField("filter_key", cacheKey).Debug("Generated cache key for filtered group query")
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
	if useCache {
		if cacheErr := r.cache.SetWithTTL(ctx, cacheKey, groups, ttl); cacheErr != nil {
			logger.Log.WithField("cache_key", cacheKey).WithError(cacheErr).Warn("Failed to cache group list")
		} else {
			logger.Log.WithField("cache_key", cacheKey).WithField("ttl", ttl).Debug("Group list cached")
		}
	}

	return groups, nil
}

func (r *CachedGroupRepository) ExistsByName(ctx context.Context, groupName string) (bool, error) {
	// Check cache first
	key := r.getGroupKey(groupName)
	var cachedGroup entities.Group
	if err := r.cache.Get(ctx, key, &cachedGroup); err == nil {
		return true, nil
	}

	// Cache miss - check repository
	return r.repo.ExistsByName(ctx, groupName)
}

func (r *CachedGroupRepository) Enable(ctx context.Context, groupName string) error {
	err := r.repo.Enable(ctx, groupName)
	if err != nil {
		return err
	}

	// Invalidate related caches
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

	// Invalidate related caches
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

	// Invalidate related caches
	if err := r.invalidateGroupCaches(ctx, group.GroupName); err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Warn("Failed to invalidate cache after ClearAccessControl")
	}

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

// ✅ HELPER METHODS

func (r *CachedGroupRepository) getGroupKey(groupName string) string {
	return fmt.Sprintf("group:%s", groupName)
}

// Enhanced cache invalidation - clears individual group, lists, and filtered queries
func (r *CachedGroupRepository) invalidateGroupCaches(ctx context.Context, groupName string) error {
	groupKey := r.getGroupKey(groupName)
	listKey := "groups:list"

	// Delete individual group and basic list
	if err := r.cache.DelMultiple(ctx, groupKey, listKey); err != nil {
		return err
	}

	// ✅ NEW: Delete all filtered group queries
	if err := r.cache.DeleteByPattern(ctx, "groups:filter:*"); err != nil {
		logger.Log.WithError(err).Warn("Failed to delete filtered group cache by pattern")
		// Don't return error as this is not critical
	}

	return nil
}

// Helper to determine if filter is empty (for caching strategy)
func (r *CachedGroupRepository) isEmptyFilter(filter *entities.GroupFilter) bool {
	if filter == nil {
		return true
	}

	// Check if all filter fields are empty/default
	return filter.GroupName == "" &&
		filter.AuthMethod == "" &&
		filter.Role == "" &&
		// Don't check pagination fields for emptiness
		filter.Page == 0 &&
		filter.Limit == 0
}
