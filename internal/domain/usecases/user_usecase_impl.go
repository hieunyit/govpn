package usecases

import (
	"context"
	"fmt"
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/ldap"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	"sort"
	"strings"
	"time"
)

type userUsecaseImpl struct {
	userRepo   repositories.UserRepository
	groupRepo  repositories.GroupRepository
	ldapClient *ldap.Client // CRITICAL FIX: Re-added LDAP client
}

func NewUserUsecase(userRepo repositories.UserRepository, groupRepo repositories.GroupRepository, ldapClient *ldap.Client) UserUsecase {
	return &userUsecaseImpl{
		userRepo:   userRepo,
		groupRepo:  groupRepo,
		ldapClient: ldapClient, // CRITICAL FIX: Initialize LDAP client
	}
}

// CreateUser creates a new user with enhanced validation
func (u *userUsecaseImpl) CreateUser(ctx context.Context, user *entities.User) error {
	logger.Log.WithField("username", user.Username).
		WithField("authMethod", user.AuthMethod).
		Info("Creating user")

		// Check if user already exists
	existingUser, err := u.userRepo.ExistsByUsername(ctx, user.Username)
	if err != nil {
		return errors.InternalServerError("Failed to check user existence", err)
	}
	if existingUser {
		return errors.Conflict("User already exists", nil)
	}
	if user.GroupName != "" {
		existingGroup, err := u.groupRepo.ExistsByName(ctx, user.GroupName)
		if err != nil {
			return errors.InternalServerError("Failed to get group", err)
		}
		if !existingGroup {
			return errors.BadRequest("Group does not exist", nil)
		}
	} else {
		user.GroupName = "__DEFAULT__"
	}
	existingEmail, err := u.userRepo.ExistsByEmail(ctx, user.Email)
	if err != nil {
		return errors.InternalServerError("Failed to get email", err)
	}
	if existingEmail {
		return errors.BadRequest("Email already exists", nil)
	}
	// CRITICAL FIX: Enhanced auth method validation
	if err := u.validateUserAuthMethod(user); err != nil {
		return errors.BadRequest("Auth method validation failed", err)
	}

	// CRITICAL FIX: For LDAP users, verify they exist in LDAP
	if user.IsLDAPAuth() {
		if err := u.ldapClient.CheckUserExists(user.Username); err != nil {
			logger.Log.WithField("username", user.Username).WithError(err).Error("LDAP user check failed")
			return errors.BadRequest("User not found in LDAP directory", err)
		}
		logger.Log.WithField("username", user.Username).Info("LDAP user existence verified")
	}

	// Validate and fix MAC addresses
	if len(user.MacAddresses) > 0 {
		macAddresses := validator.ConvertMAC(user.MacAddresses)
		user.MacAddresses = macAddresses
	}

	// Validate and fix IPs if provided
	if len(user.AccessControl) > 0 {
		accessControl, err := validator.ValidateAndFixIPs(user.AccessControl)
		if err != nil {
			return errors.BadRequest("Invalid IP addresses", err)
		}
		user.AccessControl = accessControl
	}

	// Assign or validate user IP
	if user.IPAssignMode == "" {
		user.IPAssignMode = entities.IPAssignModeDynamic
	}

	switch user.IPAssignMode {
	case entities.IPAssignModeDynamic:
		ip, err := u.assignDynamicIP(ctx, user.GroupName)
		if err != nil {
			return errors.InternalServerError("Failed to assign IP", err)
		}
		user.IPAddress = ip
	case entities.IPAssignModeStatic:
		if err := u.validateStaticIP(ctx, user.GroupName, user.IPAddress, ""); err != nil {
			return errors.BadRequest("Invalid static IP", err)
		}
	default:
		return errors.BadRequest("Invalid IP assign mode", nil)
	}

	if err := u.userRepo.Create(ctx, user); err != nil {
		return errors.InternalServerError("Failed to create user", err)
	}

	logger.Log.WithField("username", user.Username).
		WithField("authMethod", user.AuthMethod).
		Info("User created successfully")
	return nil
}

// GetUser retrieves a user by username
func (u *userUsecaseImpl) GetUser(ctx context.Context, username string) (*entities.User, error) {
	logger.Log.WithField("username", username).Debug("Getting user")

	if username == "" {
		return nil, errors.BadRequest("Username cannot be empty", nil)
	}

	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	// CRITICAL FIX: For LDAP users, verify they still exist in LDAP
	if user.IsLDAPAuth() {
		if err := u.ldapClient.CheckUserExists(username); err != nil {
			logger.Log.WithField("username", username).WithError(err).Warn("LDAP user check failed during get user")
			// Don't fail the request, but log the warning
			// This allows getting user info even if LDAP is temporarily unavailable
		} else {
			logger.Log.WithField("username", username).Debug("LDAP user existence verified")
		}
	}

	// Get group information if user has a custom group
	if user.GroupName != "__DEFAULT__" && user.GroupName != "" {
		group, err := u.groupRepo.GetByName(ctx, user.GroupName)
		if err != nil {
			logger.Log.WithField("username", username).WithError(err).Warn("Failed to get user group")
		} else {
			user.AccessControl = group.AccessControl
		}
	}

	return user, nil
}

// FIXED: UpdateUser with proper partial update logic
func (u *userUsecaseImpl) UpdateUser(ctx context.Context, user *entities.User) error {
	logger.Log.WithField("username", user.Username).Info("Updating user")

	if user.Username == "" {
		return errors.BadRequest("Username cannot be empty", nil)
	}

	// Check if user exists
	existingUser, err := u.userRepo.GetByUsername(ctx, user.Username)
	if err != nil {
		return err
	}
	if user.GroupName != "" && user.GroupName != "__DEFAULT__" {
		existingGroup, err := u.groupRepo.ExistsByName(ctx, user.GroupName)
		if err != nil {
			return errors.InternalServerError("Failed to get group", err)
		}

		if !existingGroup {
			return errors.BadRequest("Group does not exist", nil)
		}
	}
	if err := u.userRepo.UserPropDel(ctx, existingUser); err != nil {
		logger.Log.WithField("username", user.Username).WithError(err).Error("Failed to UserPropDel")
		if err := u.userRepo.Update(ctx, existingUser); err != nil {
			return errors.InternalServerError("Failed to restore user", err)
		}
		return errors.InternalServerError("Failed to UserPropDel", err)
	}

	// CRITICAL FIX: For LDAP users, verify they still exist in LDAP
	if existingUser.IsLDAPAuth() {
		if err := u.ldapClient.CheckUserExists(user.Username); err != nil {
			logger.Log.WithField("username", user.Username).WithError(err).Error("LDAP user check failed during update")
			return errors.BadRequest("User not found in LDAP directory", err)
		}
		logger.Log.WithField("username", user.Username).Debug("LDAP user existence verified for update")
	}

	// FIXED LOGIC: Create update entity with only provided fields
	updateUser := &entities.User{
		Username:     user.Username, // Required for identification
		GroupName:    existingUser.GroupName,
		IPAddress:    existingUser.IPAddress,
		IPAssignMode: existingUser.IPAssignMode,
	}

	// Partial update: Only update fields that are provided
	if user.UserExpiration != "" {
		updateUser.UserExpiration = user.UserExpiration
		logger.Log.WithField("username", user.Username).Debug("Updating user expiration")
	}

	if len(user.MacAddresses) > 0 {
		// Validate and fix MAC addresses
		macAddresses := validator.ConvertMAC(user.MacAddresses)

		updateUser.MacAddresses = macAddresses
		logger.Log.WithField("username", user.Username).
			WithField("macCount", len(macAddresses)).
			Debug("Updating MAC addresses")
	}

	if len(user.AccessControl) > 0 {
		accessControl, err := validator.ValidateAndFixIPs(user.AccessControl)
		if err != nil {
			return errors.BadRequest("Invalid IP addresses", err)
		}
		updateUser.AccessControl = accessControl
		logger.Log.WithField("username", user.Username).
			WithField("accessControlCount", len(accessControl)).
			Debug("Updating access control")
	}

	if user.DenyAccess != "" {
		updateUser.DenyAccess = user.DenyAccess
		logger.Log.WithField("username", user.Username).
			WithField("denyAccess", user.DenyAccess).
			Debug("Updating deny access")
	}

	if user.GroupName != "" {
		updateUser.GroupName = user.GroupName
		logger.Log.WithField("username", user.Username).
			WithField("groupName", user.GroupName).
			Debug("Updating group name")
	}

	if user.IPAssignMode != "" {
		updateUser.IPAssignMode = user.IPAssignMode
	}

	if user.IPAddress != "" {
		updateUser.IPAddress = user.IPAddress
	}

	// Handle IP assignment/validation
	if updateUser.IPAssignMode != "" {
		switch updateUser.IPAssignMode {
		case entities.IPAssignModeDynamic:
			ip, err := u.assignDynamicIP(ctx, updateUser.GroupName)
			if err != nil {
				return errors.InternalServerError("Failed to assign IP", err)
			}
			updateUser.IPAddress = ip
		case entities.IPAssignModeStatic:
			if err := u.validateStaticIP(ctx, updateUser.GroupName, updateUser.IPAddress, user.Username); err != nil {
				return errors.BadRequest("Invalid static IP", err)
			}
		default:
			return errors.BadRequest("Invalid IP assign mode", nil)
		}
	}

	// Update user in repository
	if err := u.userRepo.Update(ctx, updateUser); err != nil {
		return errors.InternalServerError("Failed to update user", err)
	}

	logger.Log.WithField("username", user.Username).Info("User updated successfully")
	return nil
}

func (u *userUsecaseImpl) GetUserExpirations(ctx context.Context, days int) (*dto.UserExpirationsResponse, error) {
	logger.Log.WithField("days", days).Info("Getting user expirations with full info")

	if days < 0 || days > 365 {
		return nil, errors.BadRequest("Days must be between 0 and 365", nil)
	}

	// Get all users
	users, err := u.userRepo.List(ctx, &entities.UserFilter{
		Limit:  10000, // Get all users
		Offset: 0,
	})
	if err != nil {
		return nil, errors.InternalServerError("Failed to get users", err)
	}

	var expiringUsers []dto.UserExpirationInfo
	currentTime := time.Now()
	targetDate := currentTime.AddDate(0, 0, days)

	for _, user := range users {
		if user.UserExpiration == "" {
			continue // Skip users without expiration
		}

		// Parse expiration date
		expirationTime, err := time.Parse("2006-01-02", user.UserExpiration)
		if err != nil {
			// Try alternative format
			expirationTime, err = time.Parse("02/01/2006", user.UserExpiration)
			if err != nil {
				logger.Log.WithField("username", user.Username).
					WithField("expiration", user.UserExpiration).
					Warn("Failed to parse expiration date")
				continue
			}
		}

		// Calculate days until expiry (negative if already expired)
		daysUntilExpiry := int(expirationTime.Sub(currentTime).Hours() / 24)

		// Skip users expiring after the target date
		if expirationTime.After(targetDate) {
			continue
		}

		// Skip users that expired before the range window
		if daysUntilExpiry < 0 && -daysUntilExpiry > days {
			continue
		}

		// Determine expiration status
		var status string
		if expirationTime.Before(currentTime) {
			status = "expired"
		} else if daysUntilExpiry <= 3 {
			status = "critical" // Expires in 3 days or less
		} else if daysUntilExpiry <= 7 {
			status = "warning" // Expires in 7 days or less
		} else {
			status = "expiring" // Expires within specified days
		}

		// Get group information if user has a custom group
		var accessControl []string
		if user.GroupName != "__DEFAULT__" && user.GroupName != "" {
			group, err := u.groupRepo.GetByName(ctx, user.GroupName)
			if err == nil {
				accessControl = group.AccessControl
			}
		}
		if len(user.AccessControl) > 0 {
			accessControl = user.AccessControl
		}

		expiringUser := dto.UserExpirationInfo{
			Username:         user.Username,
			Email:            user.Email,
			UserExpiration:   user.UserExpiration,
			AuthMethod:       user.AuthMethod,
			Role:             user.Role,
			GroupName:        user.GroupName,
			DenyAccess:       user.DenyAccess == "true",
			MFA:              user.MFA == "true",
			AccessControl:    accessControl,
			MacAddresses:     user.MacAddresses,
			DaysUntilExpiry:  daysUntilExpiry,
			ExpirationStatus: status,
		}

		expiringUsers = append(expiringUsers, expiringUser)
	}

	// Sort by days until expiry (most urgent first)
	sort.Slice(expiringUsers, func(i, j int) bool {
		return expiringUsers[i].DaysUntilExpiry < expiringUsers[j].DaysUntilExpiry
	})

	response := &dto.UserExpirationsResponse{
		Users: expiringUsers,
		Count: len(expiringUsers),
		Days:  days,
	}

	logger.Log.WithField("count", len(expiringUsers)).
		WithField("days", days).
		Info("User expirations retrieved successfully")

	return response, nil
}

func (u *userUsecaseImpl) GetExpiringUsers(ctx context.Context, days int) ([]string, error) {
	logger.Log.WithField("days", days).Info("Getting expiring user emails (legacy)")

	response, err := u.GetUserExpirations(ctx, days)
	if err != nil {
		return nil, err
	}

	// Extract emails for backward compatibility
	emails := make([]string, 0, len(response.Users))
	for _, user := range response.Users {
		if user.Email != "" && user.ExpirationStatus != "expired" {
			emails = append(emails, user.Email)
		}
	}

	return emails, nil
}

func (u *userUsecaseImpl) ListUsersWithCount(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, int, error) {
	// Get total count without pagination
	totalFilter := &entities.UserFilter{
		Username:   filter.Username,
		Email:      filter.Email,
		AuthMethod: filter.AuthMethod,
		Role:       filter.Role,
		GroupName:  filter.GroupName,
		// No pagination params for count
	}

	allUsers, err := u.userRepo.List(ctx, totalFilter)
	if err != nil {
		return nil, 0, errors.InternalServerError("Failed to count users", err)
	}
	totalCount := len(allUsers)

	// Get paginated results
	users, err := u.userRepo.List(ctx, filter)
	if err != nil {
		return nil, 0, errors.InternalServerError("Failed to retrieve users", err)
	}

	return users, totalCount, nil
}

func (u *userUsecaseImpl) ListUsersWithTotal(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, int, error) {
	logger.Log.WithField("filter", filter).Debug("Listing users with total count")

	// First get total count (without pagination)
	totalFilter := &entities.UserFilter{
		Username:   filter.Username,
		Email:      filter.Email,
		AuthMethod: filter.AuthMethod,
		Role:       filter.Role,
		GroupName:  filter.GroupName,
		// Don't include pagination for total count
		Page:  0,
		Limit: 0,
	}

	allUsers, err := u.userRepo.List(ctx, totalFilter)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get total user count")
		return nil, 0, errors.InternalServerError("Failed to get total user count", err)
	}
	totalCount := len(allUsers)

	// Then get paginated results
	paginatedUsers, err := u.userRepo.List(ctx, filter)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get paginated users")
		return nil, 0, errors.InternalServerError("Failed to get paginated users", err)
	}

	// Enhance users with group information (same as existing ListUsers method)
	for _, user := range paginatedUsers {
		if user.GroupName != "__DEFAULT__" && user.GroupName != "" {
			group, err := u.groupRepo.GetByName(ctx, user.GroupName)
			if err != nil {
				logger.Log.WithField("username", user.Username).WithError(err).Warn("Failed to get user group")
				continue
			}
			user.AccessControl = group.AccessControl
		}
	}

	logger.Log.WithField("totalCount", totalCount).
		WithField("pageSize", len(paginatedUsers)).
		Info("Users retrieved with total count")

	return paginatedUsers, totalCount, nil
}

// DeleteUser deletes a user
func (u *userUsecaseImpl) DeleteUser(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Deleting user")

	if username == "" {
		return errors.BadRequest("Username cannot be empty", nil)
	}

	// Check if user exists
	existingUser, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return err
	}

	// Additional validation for user deletion
	if err := u.validateUserDeletion(existingUser); err != nil {
		return errors.BadRequest("User deletion validation failed", err)
	}

	if err := u.userRepo.Delete(ctx, username); err != nil {
		return errors.InternalServerError("Failed to delete user", err)
	}

	logger.Log.WithField("username", username).Info("User deleted successfully")
	return nil
}

// ListUsers lists users with filtering
func (u *userUsecaseImpl) ListUsers(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, error) {
	logger.Log.Debug("Listing users")

	users, err := u.userRepo.List(ctx, filter)
	if err != nil {
		return nil, errors.InternalServerError("Failed to list users", err)
	}

	// Enhance users with group information
	for _, user := range users {
		if user.GroupName != "__DEFAULT__" && user.GroupName != "" {
			group, err := u.groupRepo.GetByName(ctx, user.GroupName)
			if err != nil {
				logger.Log.WithField("username", user.Username).WithError(err).Warn("Failed to get user group")
				continue
			}
			user.AccessControl = group.AccessControl
		}
	}

	return users, nil
}

// EnableUser enables a user
func (u *userUsecaseImpl) EnableUser(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Enabling user")

	if username == "" {
		return errors.BadRequest("Username cannot be empty", nil)
	}

	// Check if user exists
	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return err
	}

	// CRITICAL FIX: For LDAP users, verify they still exist in LDAP
	if user.IsLDAPAuth() {
		if err := u.ldapClient.CheckUserExists(username); err != nil {
			logger.Log.WithField("username", username).WithError(err).Error("LDAP user check failed during enable")
			return errors.BadRequest("User not found in LDAP directory", err)
		}
		logger.Log.WithField("username", username).Debug("LDAP user existence verified for enable")
	}

	if err := u.userRepo.Enable(ctx, username); err != nil {
		return errors.InternalServerError("Failed to enable user", err)
	}

	logger.Log.WithField("username", username).Info("User enabled successfully")
	return nil
}

// DisableUser disables a user
func (u *userUsecaseImpl) DisableUser(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Disabling user")

	if username == "" {
		return errors.BadRequest("Username cannot be empty", nil)
	}

	// Check if user exists
	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return err
	}

	// Additional validation for user disabling
	if err := u.validateUserAction(user, "disable"); err != nil {
		return errors.BadRequest("User disable validation failed", err)
	}

	// CRITICAL FIX: For LDAP users, verify they still exist in LDAP
	if user.IsLDAPAuth() {
		if err := u.ldapClient.CheckUserExists(username); err != nil {
			logger.Log.WithField("username", username).WithError(err).Warn("LDAP user check failed during disable - proceeding anyway")
			// Don't fail disable operation if LDAP is unavailable
			// This allows disabling users even if LDAP is down
		} else {
			logger.Log.WithField("username", username).Debug("LDAP user existence verified for disable")
		}
	}

	if err := u.userRepo.Disable(ctx, username); err != nil {
		return errors.InternalServerError("Failed to disable user", err)
	}

	logger.Log.WithField("username", username).Info("User disabled successfully")
	return nil
}

// ChangePassword changes user password with enhanced auth method validation
func (u *userUsecaseImpl) ChangePassword(ctx context.Context, username, password string) error {
	logger.Log.WithField("username", username).Info("Changing user password")

	if username == "" {
		return errors.BadRequest("Username cannot be empty", nil)
	}

	if password == "" {
		return errors.BadRequest("Password cannot be empty", nil)
	}

	// Get user details
	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return err
	}

	// CRITICAL SECURITY FIX: Check if user is local
	if !user.IsLocalAuth() {
		logger.Log.WithField("username", username).
			WithField("authMethod", user.AuthMethod).
			Error("Attempted password change for non-local user")
		return errors.BadRequest("Password can only be changed for local users", nil)
	}

	// Enhanced password validation
	if err := u.validatePasswordChange(user, password); err != nil {
		return errors.BadRequest("Password validation failed", err)
	}

	if err := u.userRepo.SetPassword(ctx, username, password); err != nil {
		return errors.InternalServerError("Failed to change password", err)
	}

	logger.Log.WithField("username", username).Info("Password changed successfully")
	return nil
}

// RegenerateTOTP regenerates TOTP for a user
func (u *userUsecaseImpl) RegenerateTOTP(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Regenerating user TOTP")

	if username == "" {
		return errors.BadRequest("Username cannot be empty", nil)
	}

	// Check if user exists
	_, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return err
	}

	if err := u.userRepo.RegenerateTOTP(ctx, username); err != nil {
		return errors.InternalServerError("Failed to regenerate TOTP", err)
	}

	logger.Log.WithField("username", username).Info("TOTP regenerated successfully")
	return nil
}

// =================== HELPER VALIDATION METHODS ===================

// validateUserAuthMethod validates auth method specific requirements
func (u *userUsecaseImpl) validateUserAuthMethod(user *entities.User) error {
	authMethod := strings.ToLower(strings.TrimSpace(user.AuthMethod))

	switch authMethod {
	case "local":
		// Local users must have password during creation
		if strings.TrimSpace(user.Password) == "" {
			return fmt.Errorf("password is required for local users")
		}

		// Validate password complexity
		if err := u.validatePasswordComplexity(user.Password); err != nil {
			return fmt.Errorf("password validation failed: %w", err)
		}

	case "ldap":
		// LDAP users should not have password set during creation
		if strings.TrimSpace(user.Password) != "" {
			logger.Log.WithField("username", user.Username).
				Warn("Password provided for LDAP user during creation - clearing password")
			user.Password = "" // Clear password for LDAP users
		}

	default:
		return fmt.Errorf("invalid authentication method: %s", user.AuthMethod)
	}

	return nil
}

// validateUserDeletion validates user deletion
func (u *userUsecaseImpl) validateUserDeletion(user *entities.User) error {
	// Cannot delete admin users (implement based on your business logic)
	if strings.EqualFold(user.Role, "admin") && strings.EqualFold(user.Username, "admin") {
		return fmt.Errorf("cannot delete system admin user")
	}

	// Additional business logic validations can be added here
	return nil
}

// validateUserAction validates user actions (enable/disable)
func (u *userUsecaseImpl) validateUserAction(user *entities.User, action string) error {
	// Cannot disable admin user
	if action == "disable" && strings.EqualFold(user.Role, "admin") && strings.EqualFold(user.Username, "admin") {
		return fmt.Errorf("cannot disable system admin user")
	}

	return nil
}

// validatePasswordChange validates password change requests
func (u *userUsecaseImpl) validatePasswordChange(user *entities.User, password string) error {
	// Must be local user
	if user.AuthMethod != "local" {
		return fmt.Errorf("password can only be changed for local users")
	}

	// Validate password complexity
	if err := u.validatePasswordComplexity(password); err != nil {
		return err
	}

	return nil
}

// validatePasswordComplexity validates password complexity
func (u *userUsecaseImpl) validatePasswordComplexity(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return fmt.Errorf("password must not exceed 128 characters")
	}

	return nil
}

// assignDynamicIP picks an available IP from group's subnets
func (u *userUsecaseImpl) assignDynamicIP(ctx context.Context, groupName string) (string, error) {
	group, err := u.groupRepo.GetByName(ctx, groupName)
	if err != nil {
		return "", fmt.Errorf("failed to get group: %w", err)
	}

	var subnets []*net.IPNet
	for _, s := range group.GroupSubnet {
		subnet := strings.TrimSpace(s)
		_, cidr, err := net.ParseCIDR(subnet)
		if err == nil {
			subnets = append(subnets, cidr)
		}
	}
	if len(subnets) == 0 {
		return "", fmt.Errorf("group has no subnet")
	}

	var ranges []ipRange
	for _, r := range group.GroupRange {
		if pr, err := parseIPRange(strings.TrimSpace(r)); err == nil {
			ranges = append(ranges, pr)
		}
	}

	users, err := u.userRepo.List(ctx, &entities.UserFilter{})
	if err != nil {
		return "", fmt.Errorf("failed to list users: %w", err)
	}
	used := map[string]bool{}
	for _, usr := range users {
		if usr.IPAddress != "" {
			used[usr.IPAddress] = true
		}
	}

	for _, subnet := range subnets {
		ip := subnet.IP.To4()
		maskSize, bits := subnet.Mask.Size()
		total := uint32(1) << uint32(bits-maskSize)
		start := ipToUint32(ip)
		for i := uint32(1); i < total-1; i++ {
			candidate := uint32ToIP(start + i)
			ipStr := candidate.String()
			if used[ipStr] || ipInRanges(candidate, ranges) {
				continue
			}
			return ipStr, nil
		}
	}
	return "", fmt.Errorf("no available IP")
}

// validateStaticIP checks if IP is valid for group and not used
func (u *userUsecaseImpl) validateStaticIP(ctx context.Context, groupName, ipStr, exclude string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP")
	}

	group, err := u.groupRepo.GetByName(ctx, groupName)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	var inSubnet bool
	for _, s := range group.GroupSubnet {
		subnet := strings.TrimSpace(s)
		_, cidr, err := net.ParseCIDR(subnet)
		if err == nil && cidr.Contains(ip) {
			inSubnet = true
			break
		}
	}
	if !inSubnet {
		return fmt.Errorf("ip not in group subnet")
	}

	for _, r := range group.GroupRange {
		pr, err := parseIPRange(strings.TrimSpace(r))
		if err == nil && ipInRange(ip, pr) {
			return fmt.Errorf("ip within restricted range")
		}
	}

	users, err := u.userRepo.List(ctx, &entities.UserFilter{})
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}
	for _, usr := range users {
		if usr.Username == exclude {
			continue
		}
		if usr.IPAddress == ipStr {
			return fmt.Errorf("ip already in use")
		}
	}
	return nil
}

type ipRange struct {
	start net.IP
	end   net.IP
}

func parseIPRange(r string) (ipRange, error) {
	parts := strings.Split(r, "-")
	if len(parts) != 2 {
		return ipRange{}, fmt.Errorf("invalid range")
	}
	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return ipRange{}, fmt.Errorf("invalid ip in range")
	}
	return ipRange{start: start, end: end}, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(i uint32) net.IP {
	return net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
}

func ipInRange(ip net.IP, r ipRange) bool {
	v := ipToUint32(ip)
	return v >= ipToUint32(r.start) && v <= ipToUint32(r.end)
}

func ipInRanges(ip net.IP, ranges []ipRange) bool {
	for _, r := range ranges {
		if ipInRange(ip, r) {
			return true
		}
	}
	return false
}
