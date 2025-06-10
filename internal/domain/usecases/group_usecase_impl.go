package usecases

import (
	"context"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
)

type groupUsecaseImpl struct {
	groupRepo repositories.GroupRepository
}

func NewGroupUsecase(groupRepo repositories.GroupRepository) GroupUsecase {
	return &groupUsecaseImpl{
		groupRepo: groupRepo,
	}
}

func (u *groupUsecaseImpl) CreateGroup(ctx context.Context, group *entities.Group) error {
	logger.Log.WithField("groupName", group.GroupName).Info("Creating group")

	// Check if group already exists
	exists, err := u.groupRepo.ExistsByName(ctx, group.GroupName)
	if err != nil {
		return errors.InternalServerError("Failed to check group existence", err)
	}
	if exists {
		return errors.Conflict("Group already exists", errors.ErrGroupAlreadyExists)
	}

	// Validate and fix IP addresses if access control is provided
	if len(group.AccessControl) > 0 {
		accessControl, err := validator.ValidateAndFixIPs(group.AccessControl)
		if err != nil {
			return errors.BadRequest("Invalid IP addresses", err)
		}
		group.AccessControl = accessControl
	}

	// Create group
	if err := u.groupRepo.Create(ctx, group); err != nil {
		return errors.InternalServerError("Failed to create group", err)
	}

	logger.Log.WithField("groupName", group.GroupName).Info("Group created successfully")
	return nil
}

func (u *groupUsecaseImpl) GetGroup(ctx context.Context, groupName string) (*entities.Group, error) {
	logger.Log.WithField("groupName", groupName).Debug("Getting group")

	group, err := u.groupRepo.GetByName(ctx, groupName)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (u *groupUsecaseImpl) UpdateGroup(ctx context.Context, group *entities.Group) error {
	logger.Log.WithField("groupName", group.GroupName).Info("Updating group")

	// Check if group exists
	_, err := u.groupRepo.GetByName(ctx, group.GroupName)
	if err != nil {
		return err
	}

	// Validate and fix IP addresses if access control is provided
	if len(group.AccessControl) > 0 {
		accessControl, err := validator.ValidateAndFixIPs(group.AccessControl)
		if err != nil {
			return errors.BadRequest("Invalid IP addresses", err)
		}
		group.AccessControl = accessControl
	}

	// Update group
	if err := u.groupRepo.Update(ctx, group); err != nil {
		return errors.InternalServerError("Failed to update group", err)
	}

	logger.Log.WithField("groupName", group.GroupName).Info("Group updated successfully")
	return nil
}

func (u *groupUsecaseImpl) DeleteGroup(ctx context.Context, groupName string) error {
	logger.Log.WithField("groupName", groupName).Info("Deleting group")

	// Check if group exists
	_, err := u.groupRepo.GetByName(ctx, groupName)
	if err != nil {
		return err
	}

	// Delete group
	if err := u.groupRepo.Delete(ctx, groupName); err != nil {
		return errors.InternalServerError("Failed to delete group", err)
	}

	logger.Log.WithField("groupName", groupName).Info("Group deleted successfully")
	return nil
}

func (u *groupUsecaseImpl) ListGroups(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, error) {
	logger.Log.Debug("Listing groups")

	groups, err := u.groupRepo.List(ctx, filter)
	if err != nil {
		return nil, errors.InternalServerError("Failed to list groups", err)
	}

	return groups, nil
}

func (u *groupUsecaseImpl) EnableGroup(ctx context.Context, groupName string) error {
	logger.Log.WithField("groupName", groupName).Info("Enabling group")

	// Check if group exists
	_, err := u.groupRepo.GetByName(ctx, groupName)
	if err != nil {
		return err
	}

	if err := u.groupRepo.Enable(ctx, groupName); err != nil {
		return errors.InternalServerError("Failed to enable group", err)
	}

	logger.Log.WithField("groupName", groupName).Info("Group enabled successfully")
	return nil
}

func (u *groupUsecaseImpl) DisableGroup(ctx context.Context, groupName string) error {
	logger.Log.WithField("groupName", groupName).Info("Disabling group")

	// Check if group exists
	_, err := u.groupRepo.GetByName(ctx, groupName)
	if err != nil {
		return err
	}

	if err := u.groupRepo.Disable(ctx, groupName); err != nil {
		return errors.InternalServerError("Failed to disable group", err)
	}

	logger.Log.WithField("groupName", groupName).Info("Group disabled successfully")
	return nil
}
