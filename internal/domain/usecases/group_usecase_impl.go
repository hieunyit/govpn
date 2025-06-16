package usecases

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	"net"
	"strings"
)

type groupUsecaseImpl struct {
	groupRepo  repositories.GroupRepository
	configRepo repositories.ConfigRepository
}

func NewGroupUsecase(groupRepo repositories.GroupRepository, configRepo repositories.ConfigRepository) GroupUsecase {
	return &groupUsecaseImpl{
		groupRepo:  groupRepo,
		configRepo: configRepo,
	}
}

func (u *groupUsecaseImpl) CreateGroup(ctx context.Context, group *entities.Group) error {
	logger.Log.WithField("groupName", group.GroupName).Info("Creating group")

	// Set default values
	if group.MFA == "" {
		group.SetMFA(true) // Default MFA to true
	}
	if group.Role == "" {
		group.Role = entities.UserRoleUser // Default role to User
	}
	if group.GroupSubnet == nil {
		group.GroupSubnet = []string{}
	}
	if group.GroupRange == nil {
		group.GroupRange = []string{}
	}

	// Check if group already exists
	exists, err := u.groupRepo.ExistsByName(ctx, group.GroupName)
	if err != nil {
		return errors.InternalServerError("Failed to check group existence", err)
	}
	if exists {
		return errors.Conflict("Group already exists", errors.ErrGroupAlreadyExists)
	}

	// Validate GroupSubnet and GroupRange WITH conflict check against existing groups
	if err := u.validateGroupSubnetAndRangeWithConflictCheck(ctx, "", group.GroupSubnet, group.GroupRange); err != nil {
		return errors.BadRequest("Group subnet/range validation failed", err)
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
	existingGroup, err := u.groupRepo.GetByName(ctx, group.GroupName)
	if err != nil {
		return err
	}

	// Set default values if not provided, preserve existing values
	if group.MFA == "" {
		if existingGroup.MFA == "" {
			group.SetMFA(true) // Default MFA to true
		} else {
			group.MFA = existingGroup.MFA
		}
	}
	if group.Role == "" {
		if existingGroup.Role == "" {
			group.Role = entities.UserRoleUser // Default role to User
		} else {
			group.Role = existingGroup.Role
		}
	}

	// For arrays: nil = preserve existing, [] = clear/replace
	if group.GroupSubnet == nil {
		group.GroupSubnet = existingGroup.GroupSubnet
	}
	// If group.GroupSubnet != nil (including []), use the provided value (replace/clear)

	if group.GroupRange == nil {
		group.GroupRange = existingGroup.GroupRange
	}
	// If group.GroupRange != nil (including []), use the provided value (replace/clear)

	if group.AuthMethod == "" {
		group.AuthMethod = existingGroup.AuthMethod
	}
	if group.DenyAccess == "" {
		group.DenyAccess = existingGroup.DenyAccess
	}

	// AccessControl: nil = preserve, [] = clear, [values] = replace
	if group.AccessControl == nil {
		group.AccessControl = existingGroup.AccessControl
	}
	// If group.AccessControl != nil (including []), use the provided value (replace/clear)

	// Validate GroupSubnet and GroupRange
	if err := u.validateGroupSubnetAndRange(ctx, group.GroupSubnet, group.GroupRange); err != nil {
		return errors.BadRequest("Group subnet/range validation failed", err)
	}

	// Clear existing properties first
	if err := u.groupRepo.GroupPropDel(ctx, existingGroup); err != nil {
		logger.Log.WithField("groupName", group.GroupName).WithError(err).Error("Failed to GroupPropDel")
		if err := u.groupRepo.Update(ctx, existingGroup); err != nil {
			return errors.InternalServerError("Failed to restore group", err)
		}
		return errors.InternalServerError("Failed to GroupPropDel", err)
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

func (u *groupUsecaseImpl) ListGroupsWithCount(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, int, error) {
	// Get total count without pagination
	totalFilter := &entities.GroupFilter{
		GroupName:  filter.GroupName,
		AuthMethod: filter.AuthMethod,
		Role:       filter.Role,
		// No pagination params for count
	}

	allGroups, err := u.groupRepo.List(ctx, totalFilter)
	if err != nil {
		return nil, 0, errors.InternalServerError("Failed to count groups", err)
	}
	totalCount := len(allGroups)

	// Get paginated results
	groups, err := u.groupRepo.List(ctx, filter)
	if err != nil {
		return nil, 0, errors.InternalServerError("Failed to retrieve groups", err)
	}

	return groups, totalCount, nil
}

func (u *groupUsecaseImpl) ListGroupsWithTotal(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, int, error) {
	logger.Log.WithField("filter", filter).Debug("Listing groups with total count")

	// First get total count (without pagination)
	totalFilter := &entities.GroupFilter{
		GroupName:  filter.GroupName,
		AuthMethod: filter.AuthMethod,
		Role:       filter.Role,
		// Don't include pagination for total count
		Page:  0,
		Limit: 0,
	}

	allGroups, err := u.groupRepo.List(ctx, totalFilter)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get total group count")
		return nil, 0, errors.InternalServerError("Failed to get total group count", err)
	}
	totalCount := len(allGroups)

	// Then get paginated results
	paginatedGroups, err := u.groupRepo.List(ctx, filter)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get paginated groups")
		return nil, 0, errors.InternalServerError("Failed to get paginated groups", err)
	}

	logger.Log.WithField("totalCount", totalCount).
		WithField("pageSize", len(paginatedGroups)).
		Info("Groups retrieved with total count")

	return paginatedGroups, totalCount, nil
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

// validateGroupSubnetAndRange validates GroupSubnet and GroupRange according to business rules
func (u *groupUsecaseImpl) validateGroupSubnetAndRange(ctx context.Context, groupSubnets, groupRanges []string) error {
	// Rule: GroupRange requires GroupSubnet
	if len(groupSubnets) == 0 && len(groupRanges) > 0 {
		return fmt.Errorf("GroupRange requires GroupSubnet to be specified")
	}

	if len(groupSubnets) > 0 {
		// Get network config to check conflicts
		networkConfig, err := u.configRepo.GetNetworkConfig(ctx)
		if err != nil {
			return fmt.Errorf("failed to get network config for validation: %w", err)
		}

		// Parse client network and group pool
		clientNetwork := networkConfig.ClientNetwork + "/" + networkConfig.ClientNetmaskBits
		groupPool := networkConfig.GroupPool

		clientNetworkCIDR, err := u.parseCIDR(clientNetwork)
		if err != nil {
			return fmt.Errorf("invalid client network configuration: %w", err)
		}

		groupPoolCIDR, err := u.parseCIDR(groupPool)
		if err != nil {
			return fmt.Errorf("invalid group pool configuration: %w", err)
		}

		// Validate each group subnet
		for _, subnet := range groupSubnets {
			subnetCIDR, err := u.parseCIDR(subnet)
			if err != nil {
				return fmt.Errorf("invalid group subnet %s: %w", subnet, err)
			}

			// Check if group subnet overlaps with client network or group pool
			if u.networkOverlaps(subnetCIDR, clientNetworkCIDR) {
				return fmt.Errorf("group subnet %s overlaps with client network %s", subnet, clientNetwork)
			}

			if u.networkOverlaps(subnetCIDR, groupPoolCIDR) {
				return fmt.Errorf("group subnet %s overlaps with group pool %s", subnet, groupPool)
			}
		}

		// Validate group ranges if provided
		if len(groupRanges) > 0 {
			for _, ipRange := range groupRanges {
				if err := u.validateIPRangeInSubnets(ipRange, groupSubnets); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// validateGroupSubnetAndRangeWithConflictCheck validates GroupSubnet and GroupRange with existing groups conflict check
func (u *groupUsecaseImpl) validateGroupSubnetAndRangeWithConflictCheck(ctx context.Context, currentGroupName string, groupSubnets, groupRanges []string) error {
	// First do basic validation
	if err := u.validateGroupSubnetAndRange(ctx, groupSubnets, groupRanges); err != nil {
		return err
	}

	// Then check for conflicts with existing groups
	if len(groupSubnets) > 0 {
		if err := u.validateGroupSubnetOverlapWithExistingGroups(ctx, currentGroupName, groupSubnets); err != nil {
			return err
		}
	}

	return nil
}

// validateGroupSubnetOverlapWithExistingGroups checks if new group subnets overlap with existing groups
func (u *groupUsecaseImpl) validateGroupSubnetOverlapWithExistingGroups(ctx context.Context, currentGroupName string, newGroupSubnets []string) error {
	// Get all existing groups
	allGroups, err := u.groupRepo.List(ctx, &entities.GroupFilter{})
	if err != nil {
		return fmt.Errorf("failed to get existing groups for validation: %w", err)
	}

	// Parse new group subnets
	var newSubnetCIDRs []*net.IPNet
	for _, subnet := range newGroupSubnets {
		subnetCIDR, err := u.parseCIDR(subnet)
		if err != nil {
			return fmt.Errorf("invalid group subnet %s: %w", subnet, err)
		}
		newSubnetCIDRs = append(newSubnetCIDRs, subnetCIDR)
	}

	// Check against all existing groups
	for _, existingGroup := range allGroups {
		// Skip current group (for update operations)
		if existingGroup.GroupName == currentGroupName {
			continue
		}

		// Check if any existing group subnet overlaps with new subnets
		for _, existingSubnet := range existingGroup.GroupSubnet {
			if existingSubnet == "" {
				continue
			}

			existingSubnetCIDR, err := u.parseCIDR(existingSubnet)
			if err != nil {
				// Log warning but continue - existing data might have issues
				logger.Log.WithField("groupName", existingGroup.GroupName).
					WithField("subnet", existingSubnet).
					WithError(err).
					Warn("Invalid subnet in existing group")
				continue
			}

			// Check overlap with each new subnet
			for i, newSubnetCIDR := range newSubnetCIDRs {
				if u.networkOverlaps(newSubnetCIDR, existingSubnetCIDR) {
					return fmt.Errorf("group subnet %s overlaps with existing subnet %s in group %s",
						newGroupSubnets[i], existingSubnet, existingGroup.GroupName)
				}
			}
		}
	}

	return nil
}

// parseCIDR parses CIDR notation and returns network
func (u *groupUsecaseImpl) parseCIDR(cidr string) (*net.IPNet, error) {
	_, network, err := net.ParseCIDR(cidr)
	return network, err
}

// networkOverlaps checks if two networks overlap
func (u *groupUsecaseImpl) networkOverlaps(net1, net2 *net.IPNet) bool {
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}

// validateIPRangeInSubnets validates that IP range belongs to one of the group subnets
func (u *groupUsecaseImpl) validateIPRangeInSubnets(ipRange string, groupSubnets []string) error {
	// Parse IP range (e.g., "10.10.10.10-10.10.10.100")
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return fmt.Errorf("invalid IP range format %s, expected format: IP1-IP2", ipRange)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return fmt.Errorf("invalid IP addresses in range %s", ipRange)
	}

	// Check if both IPs belong to at least one of the group subnets
	for _, subnet := range groupSubnets {
		_, subnetCIDR, err := net.ParseCIDR(subnet)
		if err != nil {
			continue
		}

		if subnetCIDR.Contains(startIP) && subnetCIDR.Contains(endIP) {
			return nil // Range is valid within this subnet
		}
	}

	return fmt.Errorf("IP range %s does not belong to any of the specified group subnets", ipRange)
}
