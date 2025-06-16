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

	// Set default values if not provided
	if group.MFA == "" {
		group.MFA = "true"
	}
	if group.Role == "" {
		group.Role = entities.UserRoleUser
	}
	if group.DenyAccess == "" {
		group.DenyAccess = "false"
	}
	if group.GroupSubnet == nil {
		group.GroupSubnet = []string{}
	}
	if group.GroupRange == nil {
		group.GroupRange = []string{}
	}

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

func (r *groupRepositoryImpl) Update(ctx context.Context, group *entities.Group) error {
	logger.Log.WithField("groupName", group.GroupName).Info("Updating group")

	// Ensure default values
	if group.MFA == "" {
		group.MFA = "true"
	}
	if group.Role == "" {
		group.Role = entities.UserRoleUser
	}
	if group.GroupSubnet == nil {
		group.GroupSubnet = []string{}
	}
	if group.GroupRange == nil {
		group.GroupRange = []string{}
	}

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

	groups, err := r.groupClient.GetAllGroups()
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get all groups")
		return nil, fmt.Errorf("failed to get all groups: %w", err)
	}

	// Apply filters
	filteredGroups := r.applyFilters(groups, filter)

	// Apply pagination
	paginatedGroups := r.applyPagination(filteredGroups, filter)

	logger.Log.WithField("totalGroups", len(groups)).
		WithField("filteredGroups", len(filteredGroups)).
		WithField("paginatedGroups", len(paginatedGroups)).
		Debug("Groups listed successfully")

	return paginatedGroups, nil
}

func (r *groupRepositoryImpl) ExistsByName(ctx context.Context, groupName string) (bool, error) {
	logger.Log.WithField("groupName", groupName).Debug("Checking if group exists")

	_, err := r.groupClient.GetGroup(groupName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check group existence: %w", err)
	}

	return true, nil
}

func (r *groupRepositoryImpl) Enable(ctx context.Context, groupName string) error {
	logger.Log.WithField("groupName", groupName).Info("Enabling group")

	// Get existing group
	group, err := r.GetByName(ctx, groupName)
	if err != nil {
		return err
	}

	// Set deny access to false
	group.SetDenyAccess(false)

	// Update group
	err = r.Update(ctx, group)
	if err != nil {
		logger.Log.WithField("groupName", groupName).WithError(err).Error("Failed to enable group")
		return fmt.Errorf("failed to enable group: %w", err)
	}

	logger.Log.WithField("groupName", groupName).Info("Group enabled successfully")
	return nil
}

func (r *groupRepositoryImpl) Disable(ctx context.Context, groupName string) error {
	logger.Log.WithField("groupName", groupName).Info("Disabling group")

	// Get existing group
	group, err := r.GetByName(ctx, groupName)
	if err != nil {
		return err
	}

	// Set deny access to true
	group.SetDenyAccess(true)

	// Update group
	err = r.Update(ctx, group)
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
func (r *groupRepositoryImpl) GroupPropDel(ctx context.Context, group *entities.Group) error {
	logger.Log.WithField("groupName", group.GroupName).Info("GroupPropDel group")

	err := r.groupClient.GroupPropDel(group)
	if err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Error("Failed to GroupPropDel group")
		return fmt.Errorf("failed to GroupPropDel group: %w", err)
	}

	logger.Log.WithField("groupName", group.GroupName).Info("Group properties deleted successfully")
	return nil
}

// Helper functions
func (r *groupRepositoryImpl) applyFilters(groups []*entities.Group, filter *entities.GroupFilter) []*entities.Group {
	if filter == nil {
		return groups
	}

	var filtered []*entities.Group
	for _, group := range groups {
		// Apply group name filter
		if filter.GroupName != "" && !strings.Contains(strings.ToLower(group.GroupName), strings.ToLower(filter.GroupName)) {
			continue
		}

		// Apply auth method filter
		if filter.AuthMethod != "" && !strings.EqualFold(group.AuthMethod, filter.AuthMethod) {
			continue
		}

		// Apply role filter
		if filter.Role != "" && !strings.EqualFold(group.Role, filter.Role) {
			continue
		}

		filtered = append(filtered, group)
	}

	return filtered
}

func (r *groupRepositoryImpl) applyPagination(groups []*entities.Group, filter *entities.GroupFilter) []*entities.Group {
	if filter == nil || filter.Limit <= 0 {
		return groups
	}

	start := filter.Offset
	if start >= len(groups) {
		return []*entities.Group{}
	}

	end := start + filter.Limit
	if end > len(groups) {
		end = len(groups)
	}

	return groups[start:end]
}
