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

type userRepositoryImpl struct {
	client     *xmlrpc.Client
	userClient *xmlrpc.UserClient
}

func NewUserRepository(client *xmlrpc.Client) repositories.UserRepository {
	return &userRepositoryImpl{
		client:     client,
		userClient: xmlrpc.NewUserClient(client),
	}
}

func (r *userRepositoryImpl) Create(ctx context.Context, user *entities.User) error {
	logger.Log.WithField("username", user.Username).Info("Creating user")

	err := r.userClient.CreateUser(user)
	if err != nil {
		logger.Log.WithField("username", user.Username).WithError(err).Error("Failed to create user")
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Set password for local users
	if user.IsLocalAuth() && user.Password != "" {
		if err := r.userClient.SetUserPassword(user.Username, user.Password); err != nil {
			// Cleanup: delete user if password setting fails
			r.userClient.DeleteUser(user.Username)
			logger.Log.WithField("username", user.Username).WithError(err).Error("Failed to set user password")
			return fmt.Errorf("failed to set user password: %w", err)
		}
	}

	logger.Log.WithField("username", user.Username).Info("User created successfully")
	return nil
}

func (r *userRepositoryImpl) GetByUsername(ctx context.Context, username string) (*entities.User, error) {
	logger.Log.WithField("username", username).Debug("Getting user")

	user, err := r.userClient.GetUser(username)
	if err != nil {
		logger.Log.WithField("username", username).WithError(err).Error("Failed to get user")
		return nil, errors.NotFound("User not found", err)
	}

	return user, nil
}

func (r *userRepositoryImpl) Update(ctx context.Context, user *entities.User) error {
	logger.Log.WithField("username", user.Username).Info("Updating user")

	err := r.userClient.UpdateUser(user)
	if err != nil {
		logger.Log.WithField("username", user.Username).WithError(err).Error("Failed to update user")
		return fmt.Errorf("failed to update user: %w", err)
	}

	logger.Log.WithField("username", user.Username).Info("User updated successfully")
	return nil
}

func (r *userRepositoryImpl) UserPropDel(ctx context.Context, user *entities.User) error {
	logger.Log.WithField("username", user.Username).Info("UserPropDel user")

	err := r.userClient.UserPropDel(user)
	if err != nil {
		logger.Log.WithField("username", user.Username).WithError(err).Error("Failed to UserPropDel user")
		return fmt.Errorf("failed to UserPropDel user: %w", err)
	}

	logger.Log.WithField("username", user.Username).Info("User updated successfully")
	return nil
}

func (r *userRepositoryImpl) Delete(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Deleting user")

	err := r.userClient.DeleteUser(username)
	if err != nil {
		logger.Log.WithField("username", username).WithError(err).Error("Failed to delete user")
		return fmt.Errorf("failed to delete user: %w", err)
	}

	logger.Log.WithField("username", username).Info("User deleted successfully")
	return nil
}

func (r *userRepositoryImpl) List(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, error) {
	logger.Log.Debug("Listing users")

	// Get all users from OpenVPN AS
	users, err := r.userClient.GetAllUsers()
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get all users")
		return nil, fmt.Errorf("failed to get all users: %w", err)
	}

	// Apply filters
	filteredUsers := make([]*entities.User, 0)
	for _, user := range users {
		if r.matchesFilter(user, filter) {
			filteredUsers = append(filteredUsers, user)
		}
	}

	// Apply pagination
	start := filter.Offset
	end := start + filter.Limit

	if start > len(filteredUsers) {
		return []*entities.User{}, nil
	}

	if end > len(filteredUsers) {
		end = len(filteredUsers)
	}

	result := filteredUsers[start:end]
	logger.Log.WithField("total", len(filteredUsers)).WithField("returned", len(result)).Info("Users listed successfully")

	return result, nil
}

func (r *userRepositoryImpl) matchesFilter(user *entities.User, filter *entities.UserFilter) bool {
	if filter.Username != "" && !strings.Contains(strings.ToLower(user.Username), strings.ToLower(filter.Username)) {
		return false
	}
	if filter.Email != "" && !strings.Contains(strings.ToLower(user.Email), strings.ToLower(filter.Email)) {
		return false
	}
	if filter.AuthMethod != "" && user.AuthMethod != filter.AuthMethod {
		return false
	}
	if filter.Role != "" && user.Role != filter.Role {
		return false
	}
	if filter.GroupName != "" && user.GroupName != filter.GroupName {
		return false
	}
	return true
}

func (r *userRepositoryImpl) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	logger.Log.WithField("username", username).Debug("Checking if user exists")

	_, err := r.userClient.GetUser(username)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func (r *userRepositoryImpl) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	logger.Log.WithField("email", email).Debug("Checking if user exists")

	_, err := r.userClient.ExistsByEmail(email)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func (r *userRepositoryImpl) Enable(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Enabling user")

	err := r.userClient.EnableUser(username)
	if err != nil {
		logger.Log.WithField("username", username).WithError(err).Error("Failed to enable user")
		return fmt.Errorf("failed to enable user: %w", err)
	}

	logger.Log.WithField("username", username).Info("User enabled successfully")
	return nil
}

func (r *userRepositoryImpl) Disable(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Disabling user")

	err := r.userClient.DisableUser(username)
	if err != nil {
		logger.Log.WithField("username", username).WithError(err).Error("Failed to disable user")
		return fmt.Errorf("failed to disable user: %w", err)
	}

	logger.Log.WithField("username", username).Info("User disabled successfully")
	return nil
}

func (r *userRepositoryImpl) SetPassword(ctx context.Context, username, password string) error {
	logger.Log.WithField("username", username).Info("Setting user password")

	err := r.userClient.SetUserPassword(username, password)
	if err != nil {
		logger.Log.WithField("username", username).WithError(err).Error("Failed to set user password")
		return fmt.Errorf("failed to set user password: %w", err)
	}

	logger.Log.WithField("username", username).Info("User password set successfully")
	return nil
}

func (r *userRepositoryImpl) RegenerateTOTP(ctx context.Context, username string) error {
	logger.Log.WithField("username", username).Info("Regenerating user TOTP")

	err := r.userClient.RegenerateTOTP(username)
	if err != nil {
		logger.Log.WithField("username", username).WithError(err).Error("Failed to regenerate TOTP")
		return fmt.Errorf("failed to regenerate TOTP: %w", err)
	}

	logger.Log.WithField("username", username).Info("User TOTP regenerated successfully")
	return nil
}

func (r *userRepositoryImpl) GetExpiringUsers(ctx context.Context, days int) ([]string, error) {
	logger.Log.WithField("days", days).Info("Getting expiring users")

	emails, err := r.userClient.GetExpiringUsers(days)
	if err != nil {
		logger.Log.WithField("days", days).WithError(err).Error("Failed to get expiring users")
		return nil, fmt.Errorf("failed to get expiring users: %w", err)
	}

	logger.Log.WithField("count", len(emails)).Info("Retrieved expiring users")
	return emails, nil
}
