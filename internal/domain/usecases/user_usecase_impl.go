package usecases

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/ldap"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	"strings"
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
	existingUser, err := u.userRepo.GetByUsername(ctx, user.Username)
	if err == nil && existingUser != nil {
		return errors.Conflict("User already exists", nil)
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
		Username: user.Username, // Required for identification
	}

	// IMPORTANT: Password is NOT handled here - it's handled separately by ChangePassword
	// This avoids duplicate password processing

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
		// Validate and fix IP addresses
		accessControl, err := validator.ValidateAndFixIPs(user.AccessControl)
		if err != nil {
			return errors.BadRequest("Invalid IP addresses", err)
		}
		updateUser.AccessControl = accessControl
		logger.Log.WithField("username", user.Username).
			WithField("accessControlCount", len(accessControl)).
			Debug("Updating access control")
	}

	// Handle DenyAccess if provided
	if user.DenyAccess != "" {
		updateUser.DenyAccess = user.DenyAccess
		logger.Log.WithField("username", user.Username).
			WithField("denyAccess", user.DenyAccess).
			Debug("Updating deny access")
	}

	// Update user in repository
	if err := u.userRepo.Update(ctx, updateUser); err != nil {
		return errors.InternalServerError("Failed to update user", err)
	}

	logger.Log.WithField("username", user.Username).Info("User updated successfully")
	return nil
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

// GetExpiringUsers gets users expiring within specified days
func (u *userUsecaseImpl) GetExpiringUsers(ctx context.Context, days int) ([]string, error) {
	logger.Log.WithField("days", days).Info("Getting expiring users")

	if days < 0 || days > 365 {
		return nil, errors.BadRequest("Days must be between 0 and 365", nil)
	}

	emails, err := u.userRepo.GetExpiringUsers(ctx, days)
	if err != nil {
		return nil, errors.InternalServerError("Failed to get expiring users", err)
	}

	if len(emails) == 0 {
		return []string{}, nil
	}

	return emails, nil
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
