package repositories

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/xmlrpc"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"sort"
	"strings"
	"time"
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

	// Apply sorting
	r.sortUsers(filteredUsers, filter.SortBy, filter.SortOrder)

	// Apply pagination with proper offset calculation
	if filter.Limit > 0 {
		// Calculate offset from page if not provided
		offset := filter.Offset
		if offset == 0 && filter.Page > 1 {
			offset = (filter.Page - 1) * filter.Limit
		}

		start := offset
		end := start + filter.Limit

		if start > len(filteredUsers) {
			return []*entities.User{}, nil
		}

		if end > len(filteredUsers) {
			end = len(filteredUsers)
		}

		result := filteredUsers[start:end]
		logger.Log.WithField("total", len(filteredUsers)).
			WithField("returned", len(result)).
			WithField("page", filter.Page).
			WithField("offset", offset).
			Info("Users listed successfully")

		return result, nil
	}

	// If no pagination, return all filtered results
	logger.Log.WithField("total", len(filteredUsers)).Info("All filtered users returned")
	return filteredUsers, nil
}

// Enhanced matchesFilter with comprehensive filtering support
func (r *userRepositoryImpl) matchesFilter(user *entities.User, filter *entities.UserFilter) bool {
	// Basic filters (existing)
	if filter.Username != "" {
		if filter.ExactMatch {
			if filter.CaseSensitive {
				if user.Username != filter.Username {
					return false
				}
			} else if strings.ToLower(user.Username) != strings.ToLower(filter.Username) {
				return false
			}
		} else {
			if filter.CaseSensitive {
				if !strings.Contains(user.Username, filter.Username) {
					return false
				}
			} else if !strings.Contains(strings.ToLower(user.Username), strings.ToLower(filter.Username)) {
				return false
			}
		}
	}

	if filter.Email != "" {
		if filter.ExactMatch {
			if filter.CaseSensitive {
				if user.Email != filter.Email {
					return false
				}
			} else if strings.ToLower(user.Email) != strings.ToLower(filter.Email) {
				return false
			}
		} else {
			if filter.CaseSensitive {
				if !strings.Contains(user.Email, filter.Email) {
					return false
				}
			} else if !strings.Contains(strings.ToLower(user.Email), strings.ToLower(filter.Email)) {
				return false
			}
		}
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

	// NEW: Status filters
	if filter.IsEnabled != nil {
		userEnabled := user.DenyAccess != "true"
		if *filter.IsEnabled != userEnabled {
			return false
		}
	}

	if filter.DenyAccess != nil {
		userDenyAccess := user.DenyAccess == "true"
		if *filter.DenyAccess != userDenyAccess {
			return false
		}
	}

	if filter.MFAEnabled != nil {
		userMFAEnabled := user.MFA == "true"
		if *filter.MFAEnabled != userMFAEnabled {
			return false
		}
	}

	// NEW: Expiration filters
	if filter.UserExpirationAfter != nil || filter.UserExpirationBefore != nil || filter.ExpiringInDays != nil || (filter.IncludeExpired != nil && !*filter.IncludeExpired) {
		if user.UserExpiration == "" {
			return false // Skip users without expiration date
		}

		// Parse user expiration date (assuming DD/MM/YYYY format based on the DTO examples)
		userExpTime, err := r.parseExpirationDate(user.UserExpiration)
		if err != nil {
			return false // Skip users with invalid expiration dates
		}

		if filter.UserExpirationAfter != nil && userExpTime.Before(*filter.UserExpirationAfter) {
			return false
		}

		if filter.UserExpirationBefore != nil && userExpTime.After(*filter.UserExpirationBefore) {
			return false
		}

		if filter.ExpiringInDays != nil {
			daysUntilExp := int(time.Until(userExpTime).Hours() / 24)
			if daysUntilExp > *filter.ExpiringInDays || daysUntilExp < 0 {
				return false
			}
		}

		// Include expired check
		if filter.IncludeExpired != nil && !*filter.IncludeExpired {
			if time.Now().After(userExpTime) {
				return false // Exclude expired users
			}
		}
	}

	// NEW: Access control filter
	if filter.HasAccessControl != nil {
		hasAccessControl := len(user.AccessControl) > 0
		if *filter.HasAccessControl != hasAccessControl {
			return false
		}
	}

	// NEW: MAC address filter
	if filter.MacAddress != "" {
		found := false
		for _, mac := range user.MacAddresses {
			if filter.ExactMatch {
				if strings.EqualFold(mac, filter.MacAddress) {
					found = true
					break
				}
			} else {
				if strings.Contains(strings.ToLower(mac), strings.ToLower(filter.MacAddress)) {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	// NEW: Search text (across multiple fields)
	if filter.SearchText != "" {
		searchTerm := filter.SearchText
		if !filter.CaseSensitive {
			searchTerm = strings.ToLower(searchTerm)
		}

		fields := []string{user.Username, user.Email, user.GroupName}
		if !filter.CaseSensitive {
			for i := range fields {
				fields[i] = strings.ToLower(fields[i])
			}
		}

		found := false
		for _, field := range fields {
			if strings.Contains(field, searchTerm) {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

// NEW: Helper method to parse expiration date
func (r *userRepositoryImpl) parseExpirationDate(dateStr string) (time.Time, error) {
	// Try different date formats
	formats := []string{
		"02/01/2006", // DD/MM/YYYY (based on DTO examples)
		"2006-01-02", // YYYY-MM-DD (ISO format)
		"01/02/2006", // MM/DD/YYYY (US format)
		"2006/01/02", // YYYY/MM/DD
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// NEW: Sorting functionality
func (r *userRepositoryImpl) sortUsers(users []*entities.User, sortBy, sortOrder string) {
	if sortBy == "" {
		return
	}

	sort.Slice(users, func(i, j int) bool {
		var result bool

		switch sortBy {
		case "username":
			result = strings.ToLower(users[i].Username) < strings.ToLower(users[j].Username)
		case "email":
			result = strings.ToLower(users[i].Email) < strings.ToLower(users[j].Email)
		case "authMethod":
			result = users[i].AuthMethod < users[j].AuthMethod
		case "role":
			result = users[i].Role < users[j].Role
		case "groupName":
			result = users[i].GroupName < users[j].GroupName
		case "userExpiration":
			// Handle empty dates and sort by parsed dates
			dateI, errI := r.parseExpirationDate(users[i].UserExpiration)
			dateJ, errJ := r.parseExpirationDate(users[j].UserExpiration)

			if errI != nil && errJ != nil {
				result = false // Both invalid, maintain order
			} else if errI != nil {
				result = false // Invalid dates go to end
			} else if errJ != nil {
				result = true // Valid dates come first
			} else {
				result = dateI.Before(dateJ)
			}
		default:
			// Default to username sorting
			result = strings.ToLower(users[i].Username) < strings.ToLower(users[j].Username)
		}

		if sortOrder == "desc" {
			return !result
		}
		return result
	})
}

func (r *userRepositoryImpl) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	logger.Log.WithField("username", username).Debug("Checking if user exists")

	_, err := r.userClient.GetUser(username)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return true, nil
}

func (r *userRepositoryImpl) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	logger.Log.WithField("email", email).Debug("Checking if user exists")

	exists, err := r.userClient.ExistsByEmail(email)
	if err != nil {
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}

	return exists, nil
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
