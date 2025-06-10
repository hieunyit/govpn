package repositories

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/xmlrpc"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
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
	// Note: OpenVPN AS doesn't support filtering, so we get all and filter in memory
	// This is not optimal for large datasets but works for typical VPN group counts
	logger.Log.Debug("Listing groups")

	// For now, return empty list as this requires implementing GetAllGroups in XML-RPC client
	return []*entities.Group{}, nil
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
