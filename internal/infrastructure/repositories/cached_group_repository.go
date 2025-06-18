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

	// Invalidate cache
	r.cache.Del(r.getGroupKey(group.GroupName))
	r.cache.Del("groups:list")

	logger.Log.WithField("groupName", group.GroupName).Debug("Group created, cache invalidated")
	return nil
}

func (r *CachedGroupRepository) GetByName(ctx context.Context, groupName string) (*entities.Group, error) {
	// Try cache first
	key := r.getGroupKey(groupName)
	var cachedGroup entities.Group
	if err := r.cache.Get(key, &cachedGroup); err == nil {
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

	// Cache the result
	if cacheErr := r.cache.Set(key, group); cacheErr != nil {
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

	// Invalidate cache
	r.cache.Del(r.getGroupKey(group.GroupName))
	r.cache.Del("groups:list")

	logger.Log.WithField("groupName", group.GroupName).Debug("Group updated, cache invalidated")
	return nil
}

func (r *CachedGroupRepository) Delete(ctx context.Context, groupName string) error {
	err := r.repo.Delete(ctx, groupName)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getGroupKey(groupName))
	r.cache.Del("groups:list")

	logger.Log.WithField("groupName", groupName).Debug("Group deleted, cache invalidated")
	return nil
}

func (r *CachedGroupRepository) List(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, error) {
	// For simple implementation, only cache if no filter
	if filter != nil {
		return r.repo.List(ctx, filter)
	}

	// Try cache first
	key := "groups:list"
	var cachedGroups []*entities.Group
	if err := r.cache.Get(key, &cachedGroups); err == nil {
		logger.Log.Debug("Group list retrieved from cache")
		return cachedGroups, nil
	} else if err != redisLib.Nil {
		logger.Log.WithError(err).Warn("Cache error getting group list")
	}

	// Cache miss - get from repository
	groups, err := r.repo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if cacheErr := r.cache.Set(key, groups); cacheErr != nil {
		logger.Log.WithError(cacheErr).Warn("Failed to cache group list")
	} else {
		logger.Log.Debug("Group list cached")
	}

	return groups, nil
}

func (r *CachedGroupRepository) ExistsByName(ctx context.Context, groupName string) (bool, error) {
	// Check cache first
	key := r.getGroupKey(groupName)
	var cachedGroup entities.Group
	if err := r.cache.Get(key, &cachedGroup); err == nil {
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

	// Invalidate cache
	r.cache.Del(r.getGroupKey(groupName))
	r.cache.Del("groups:list")

	return nil
}

func (r *CachedGroupRepository) Disable(ctx context.Context, groupName string) error {
	err := r.repo.Disable(ctx, groupName)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getGroupKey(groupName))
	r.cache.Del("groups:list")

	return nil
}

func (r *CachedGroupRepository) ClearAccessControl(ctx context.Context, group *entities.Group) error {
	err := r.repo.ClearAccessControl(ctx, group)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getGroupKey(group.GroupName))
	r.cache.Del("groups:list")

	return nil
}

func (r *CachedGroupRepository) GroupPropDel(ctx context.Context, group *entities.Group) error {
	err := r.repo.GroupPropDel(ctx, group)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.Del(r.getGroupKey(group.GroupName))
	r.cache.Del("groups:list")

	return nil
}

func (r *CachedGroupRepository) getGroupKey(groupName string) string {
	return fmt.Sprintf("group:%s", groupName)
}
