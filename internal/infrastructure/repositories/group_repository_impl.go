package repositories

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/xmlrpc"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"strings"
)

type groupRepositoryImpl struct {
	client      *xmlrpc.Client
	groupClient *xmlrpc.GroupClient
}

func NewGroupRepository(client *xmlrpc.Client) repositories.GroupRepository {
	return &groupRepositoryImpl{
		client:      client,
		groupClient: xmlrpc.NewGroupClient(client),
	}
}

func (r *groupRepositoryImpl) Create(ctx context.Context, group *entities.Group) error {
	logger.Log.WithField("groupName", group.GroupName).Info("Creating group")

	err := r.groupClient.CreateGroup(group)
	if err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Error("Failed to create group")
		return fmt.Errorf("failed to create group: %w", err)
	}

	logger.Log.WithField("groupName", group.GroupName).Info("Group created successfully")
	return nil
}

func (r *groupRepositoryImpl) GetByName(ctx context.Context, groupName string) (*entities.Group, error) {
	logger.Log.WithField("groupName", groupName).Debug("Getting group")

	group, err := r.groupClient.GetGroup(groupName)
	if err != nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Error("Failed to get group")
		return nil, errors.NotFound("Group not found", err)
	}

	return group, nil
}

func (r *groupRepositoryImpl) GroupPropDel(ctx context.Context, group *entities.Group) error {
	logger.Log.WithField("grouname", group.GroupName).Info("GrouopPropDel user")

	err := r.groupClient.GroupPropDel(group)
	if err != nil {
		logger.Log.WithField("grouname", group.GroupName).WithError(err).Error("Failed to UserPropDel user")
		return fmt.Errorf("failed to UserPropDel user: %w", err)
	}

	logger.Log.WithField("grouname", group.GroupName).Info("User updated successfully")
	return nil
}

func (r *groupRepositoryImpl) Update(ctx context.Context, group *entities.Group) error {
	logger.Log.WithField("groupName", group.GroupName).Info("Updating group")

	err := r.groupClient.UpdateGroup(group)
	if err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Error("Failed to update group")
		return fmt.Errorf("failed to update group: %w", err)
	}

	logger.Log.WithField("groupName", group.GroupName).Info("Group updated successfully")
	return nil
}

func (r *groupRepositoryImpl) Delete(ctx context.Context, groupName string) error {
	logger.Log.WithField("groupName", groupName).Info("Deleting group")

	err := r.groupClient.DeleteGroup(groupName)
	if err != nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Error("Failed to delete group")
		return fmt.Errorf("failed to delete group: %w", err)
	}

	logger.Log.WithField("groupName", groupName).Info("Group deleted successfully")
	return nil
}

func (r *groupRepositoryImpl) List(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, error) {
	logger.Log.Debug("Listing groups")

	// Get all groups from OpenVPN AS
	groups, err := r.groupClient.GetAllGroups()
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get all groups")
		return nil, fmt.Errorf("failed to get all groups: %w", err)
	}

	// Apply filters
	filteredGroups := make([]*entities.Group, 0)
	for _, group := range groups {
		if r.matchesFilter(group, filter) {
			filteredGroups = append(filteredGroups, group)
		}
	}

	// ✅ FIX: Apply pagination with proper offset calculation
	if filter.Limit > 0 {
		// Calculate offset from page if not provided
		offset := filter.Offset
		if offset == 0 && filter.Page > 1 {
			offset = (filter.Page - 1) * filter.Limit
		}

		start := offset
		end := start + filter.Limit

		if start > len(filteredGroups) {
			return []*entities.Group{}, nil
		}

		if end > len(filteredGroups) {
			end = len(filteredGroups)
		}

		result := filteredGroups[start:end]
		logger.Log.WithField("total", len(filteredGroups)).
			WithField("returned", len(result)).
			WithField("page", filter.Page).
			WithField("offset", offset).
			Info("Groups listed successfully")

		return result, nil
	}

	// If no pagination, return all filtered results
	logger.Log.WithField("total", len(filteredGroups)).Info("All filtered groups returned")
	return filteredGroups, nil
}

func (r *groupRepositoryImpl) matchesFilter(group *entities.Group, filter *entities.GroupFilter) bool {
	if filter.GroupName != "" && !strings.Contains(strings.ToLower(group.GroupName), strings.ToLower(filter.GroupName)) {
		return false
	}
	if filter.AuthMethod != "" && group.AuthMethod != filter.AuthMethod {
		return false
	}
	if filter.Role != "" && group.Role != filter.Role {
		return false
	}
	return true
}

func (r *groupRepositoryImpl) ExistsByName(ctx context.Context, groupName string) (bool, error) {
	logger.Log.WithField("groupName", groupName).Debug("Checking if group exists")

	_, err := r.groupClient.GetGroup(groupName)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func (r *groupRepositoryImpl) Enable(ctx context.Context, groupName string) error {
	logger.Log.WithField("groupName", groupName).Info("Enabling group")

	err := r.groupClient.EnableGroup(groupName)
	if err != nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Error("Failed to enable group")
		return fmt.Errorf("failed to enable group: %w", err)
	}

	logger.Log.WithField("groupName", groupName).Info("Group enabled successfully")
	return nil
}

func (r *groupRepositoryImpl) Disable(ctx context.Context, groupName string) error {
	logger.Log.WithField("groupName", groupName).Info("Disabling group")

	err := r.groupClient.DisableGroup(groupName)
	if err != nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Error("Failed to disable group")
		return fmt.Errorf("failed to disable group: %w", err)
	}

	logger.Log.WithField("groupName", groupName).Info("Group disabled successfully")
	return nil
}

func (r *groupRepositoryImpl) ClearAccessControl(ctx context.Context, group *entities.Group) error {
	logger.Log.WithField("groupName", group.GroupName).Info("Clearing group access control")

	err := r.groupClient.ClearAccessControl(group)
	if err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Error("Failed to clear access control")
		return fmt.Errorf("failed to clear access control: %w", err)
	}

	logger.Log.WithField("groupName", group.GroupName).Info("Group access control cleared successfully")
	return nil
}
