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
	ldapClient *ldap.Client
}

func NewUserUsecase(userRepo repositories.UserRepository, groupRepo repositories.GroupRepository, ldapClient *ldap.Client) UserUsecase {
	return &userUsecaseImpl{
		userRepo:   userRepo,
		groupRepo:  groupRepo,
		ldapClient: ldapClient,
	}
}

func (u *userUsecaseImpl) CreateUser(ctx context.Context, user *entities.User) error {
	logger.Log.WithField("username", user.Username).Info("Creating user")

	// Check if user already exists
	exists, err := u.userRepo.ExistsByUsername(ctx, user.Username)
	if err != nil {
		return errors.InternalServerError("Failed to check user existence", err)
	}
	if exists {
		return errors.Conflict("User already exists", errors.ErrUserAlreadyExists)
	}

	// For LDAP users, verify they exist in LDAP
	if user.IsLDAPAuth() {
		if err := u.ldapClient.CheckUserExists(user.Username); err != nil {
			logger.Log.WithField("username", user.Username).WithError(err).Error("LDAP user check failed")
			return errors.BadRequest("User not found in LDAP", err)
		}
	}

	// Process user group
	groupName, err := u.processUserGroup(ctx, user)
	if err != nil {
		return errors.InternalServerError("Failed to process user group", err)
	}
	user.GroupName = groupName

	// Convert and validate MAC addresses
	user.MacAddresses = validator.ConvertMAC(user.MacAddresses)

	// Create user
	if err := u.userRepo.Create(ctx, user); err != nil {
		// Cleanup group if user creation fails
		if groupName != "__DEFAULT__" {
			u.groupRepo.Delete(ctx, groupName)
		}
		return errors.InternalServerError("Failed to create user", err)
	}

	logger.Log.WithField("username", user.Username).Info("User created successfully")
	return nil
}

func (u *userUsecaseImpl) GetUser(ctx context.Context, username string) (*entities.User, error) {
	logger.Log.WithField("username", username).Debug("Getting user")

	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
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

func (u *userUsecaseImpl) UpdateUser(ctx context.Context, user *entities.User) error {
	logger.Log.WithField("username", user.Username).Info("Updating user")

	// Check if user exists
	existingUser, err := u.userRepo.GetByUsername(ctx, user.Username)
	if err != nil {
		return err
	}

	// Handle access control updates
	if len(user.AccessControl) > 0 {
		// Validate and fix IPs
		accessControl, err := validator.ValidateAndFixIPs(user.AccessControl)
		if err != nil {
			return errors.BadRequest("Invalid IP addresses", err)
		}

		// Update group access control
		if existingUser.GroupName != "__DEFAULT__" && existingUser.GroupName != "" {
			group, err := u.groupRepo.GetByName(ctx, existingUser.GroupName)
			if err != nil {
				return errors.InternalServerError("Failed to get user group", err)
			}

			// Clear existing access control
			if err := u.groupRepo.ClearAccessControl(ctx, group); err != nil {
				return errors.InternalServerError("Failed to clear access control", err)
			}

			// Update with new access control
			group.AccessControl = accessControl
			if err := u.groupRepo.Update(ctx, group); err != nil {
				return errors.InternalServerError("Failed to update group access control", err)
			}
		}
	} else if existingUser.GroupName != "__DEFAULT__" && existingUser.GroupName != "" {
		// Clear access control if no new rules provided
		group, err := u.groupRepo.GetByName(ctx, existingUser.GroupName)
		if err != nil {
			return errors.InternalServerError("Failed to get user group", err)
		}

		if err := u.groupRepo.ClearAccessControl(ctx, group); err != nil {
			return errors.InternalServerError("Failed to clear access control", err)
		}
	}

	// Convert MAC addresses if provided
	if len(user.MacAddresses) > 0 {
		user.MacAddresses = validator.ConvertMAC(user.MacAddresses)
	}

	// Update user
	if err := u.userRepo.Update(ctx, user); err != nil {
		return errors.InternalServerError("Failed to update user", err)
	}

	logger.Log.WithField("username", user.Username).Info("User updated successfully")
	return nil
}

func (u *userUsecaseImpl) DeleteUser(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Deleting user")

	// Get user details
	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return err
	}

	// Delete user
	if err := u.userRepo.Delete(ctx, username); err != nil {
		return errors.InternalServerError("Failed to delete user", err)
	}

	// Delete associated group if not default
	if user.GroupName != "__DEFAULT__" && user.GroupName != "" {
		if err := u.groupRepo.Delete(ctx, user.GroupName); err != nil {
			logger.Log.WithField("groupName", user.GroupName).WithError(err).Warn("Failed to delete user group")
		}
	}

	logger.Log.WithField("username", username).Info("User deleted successfully")
	return nil
}

func (u *userUsecaseImpl) ListUsers(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, error) {
	logger.Log.Debug("Listing users")

	users, err := u.userRepo.List(ctx, filter)
	if err != nil {
		return nil, errors.InternalServerError("Failed to list users", err)
	}

	return users, nil
}

func (u *userUsecaseImpl) EnableUser(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Enabling user")

	// Check if user exists
	_, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return err
	}

	if err := u.userRepo.Enable(ctx, username); err != nil {
		return errors.InternalServerError("Failed to enable user", err)
	}

	logger.Log.WithField("username", username).Info("User enabled successfully")
	return nil
}

func (u *userUsecaseImpl) DisableUser(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Disabling user")

	// Check if user exists
	_, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return err
	}

	if err := u.userRepo.Disable(ctx, username); err != nil {
		return errors.InternalServerError("Failed to disable user", err)
	}

	logger.Log.WithField("username", username).Info("User disabled successfully")
	return nil
}

func (u *userUsecaseImpl) ChangePassword(ctx context.Context, username, password string) error {
	logger.Log.WithField("username", username).Info("Changing user password")

	// Get user details
	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return err
	}

	// Check if user is local
	if !user.IsLocalAuth() {
		return errors.BadRequest("Password can only be changed for local users", nil)
	}

	if err := u.userRepo.SetPassword(ctx, username, password); err != nil {
		return errors.InternalServerError("Failed to change password", err)
	}

	logger.Log.WithField("username", username).Info("Password changed successfully")
	return nil
}

func (u *userUsecaseImpl) RegenerateTOTP(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Regenerating user TOTP")

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

func (u *userUsecaseImpl) GetExpiringUsers(ctx context.Context, days int) ([]string, error) {
	logger.Log.WithField("days", days).Info("Getting expiring users")

	emails, err := u.userRepo.GetExpiringUsers(ctx, days)
	if err != nil {
		return nil, errors.InternalServerError("Failed to get expiring users", err)
	}

	if len(emails) == 0 {
		return []string{}, nil
	}

	return emails, nil
}

func (u *userUsecaseImpl) processUserGroup(ctx context.Context, user *entities.User) (string, error) {
	// If no access control, use default group
	if len(user.AccessControl) == 0 {
		return "__DEFAULT__", nil
	}

	// Validate and fix IP addresses
	accessControl, err := validator.ValidateAndFixIPs(user.AccessControl)
	if err != nil {
		return "", fmt.Errorf("invalid IP addresses: %w", err)
	}

	// Create group name based on username
	groupName := strings.ToUpper(user.Username) + "_GR"

	// Create group
	group := entities.NewGroup(groupName, user.AuthMethod)
	group.AccessControl = accessControl

	if err := u.groupRepo.Create(ctx, group); err != nil {
		return "", fmt.Errorf("failed to create group: %w", err)
	}

	return groupName, nil
}
