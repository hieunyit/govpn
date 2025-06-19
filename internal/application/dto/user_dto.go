package dto

import (
	"fmt"
	"time"
)

type CreateUserRequest struct {
	Username       string   `json:"username" validate:"required,min=3,max=30,username" example:"testuser"`
	Email          string   `json:"email" validate:"required,email" example:"testuser@example.com"`
	Password       string   `json:"password,omitempty" validate:"password_if_local" example:"SecurePass123!"`
	AuthMethod     string   `json:"authMethod" validate:"required,oneof=ldap local" example:"local"`
	GroupName      string   `json:"groupName,omitempty" example:"TEST_GR"`
	UserExpiration string   `json:"userExpiration" validate:"required,date" example:"31/12/2024"`
	MacAddresses   []string `json:"macAddresses" validate:"required,dive,mac_address" example:"5E:CD:C9:D4:88:65"`
	AccessControl  []string `json:"accessControl,omitempty" validate:"omitempty,dive,ipv4|cidrv4|ipv4_protocol" example:"192.168.1.0/24"`
	IPAddress      string   `json:"ipAddress,omitempty" validate:"omitempty,ipv4" example:"10.0.0.10"`
	IPAssignMode   string   `json:"ipAssignMode" validate:"required,oneof=dynamic static" example:"static"`
}

type UpdateUserRequest struct {
	UserExpiration string   `json:"userExpiration,omitempty" validate:"omitempty,date" example:"31/12/2025"`
	DenyAccess     *bool    `json:"denyAccess,omitempty" example:"false"`
	MacAddresses   []string `json:"macAddresses,omitempty" validate:"omitempty,dive,mac_address" example:"5E:CD:C9:D4:88:65"`
	AccessControl  []string `json:"accessControl,omitempty" validate:"omitempty,dive,ipv4|cidrv4|ipv4_protocol" example:"192.168.1.0/24"`
	GroupName      string   `json:"groupName,omitempty" example:"TEST_GR"`
	IPAddress      string   `json:"ipAddress,omitempty" validate:"omitempty,ipv4" example:"10.0.0.10"`
	IPAssignMode   string   `json:"ipAssignMode,omitempty" validate:"omitempty,oneof=dynamic static" example:"static"`
}

// Enhanced UserResponse with computed fields
type UserResponse struct {
	Username       string   `json:"username" example:"testuser"`
	Email          string   `json:"email" example:"testuser@example.com"`
	AuthMethod     string   `json:"authMethod" example:"local"`
	UserExpiration string   `json:"userExpiration" example:"31/12/2024"`
	MacAddresses   []string `json:"macAddresses" example:"5E:CD:C9:D4:88:65"`
	MFA            bool     `json:"mfa" example:"true"`
	Role           string   `json:"role" example:"User"`
	DenyAccess     bool     `json:"denyAccess" example:"false"`
	AccessControl  []string `json:"accessControl" example:"192.168.1.0/24"`
	GroupName      string   `json:"groupName" example:"TEST_GR"`
	IPAddress      string   `json:"ipAddress" example:"10.0.0.10"`

	// NEW: Computed fields for enhanced filtering
	IsEnabled    bool `json:"isEnabled" example:"true"`         // Inverse of DenyAccess
	IsExpired    bool `json:"isExpired" example:"false"`        // Whether user is past expiration
	DaysUntilExp int  `json:"daysUntilExpiration" example:"30"` // Days until expiration (-1 if expired)
}

// Enhanced UserFilter with comprehensive filtering options
type UserFilter struct {
	// Basic filters (existing)
	Username   string `form:"username" example:"testuser"`
	Email      string `form:"email" example:"test@example.com"`
	AuthMethod string `form:"authMethod" validate:"omitempty,oneof=ldap local" example:"local"`
	Role       string `form:"role" validate:"omitempty,oneof=Admin User" example:"User"`
	GroupName  string `form:"groupName" example:"TEST_GR"`

	// NEW: Status filters
	IsEnabled  *bool `form:"isEnabled" example:"true"`   // Filter by enabled status
	DenyAccess *bool `form:"denyAccess" example:"false"` // Filter by access denial status
	MFAEnabled *bool `form:"mfaEnabled" example:"true"`  // Filter by MFA status

	// NEW: Expiration filters
	UserExpirationAfter  *time.Time `form:"userExpirationAfter" time_format:"2006-01-02" example:"2025-06-17"`  // Users expiring after date
	UserExpirationBefore *time.Time `form:"userExpirationBefore" time_format:"2006-01-02" example:"2025-06-22"` // Users expiring before date
	IncludeExpired       *bool      `form:"includeExpired" example:"true"`                                      // Include expired users
	ExpiringInDays       *int       `form:"expiringInDays" validate:"omitempty,min=0" example:"7"`              // Users expiring within X days

	// NEW: Advanced filters
	HasAccessControl *bool  `form:"hasAccessControl" example:"true"`                                         // Filter by access control presence
	MacAddress       string `form:"macAddress" validate:"omitempty,mac_address" example:"5E:CD:C9:D4:88:65"` // Filter by MAC address
	SearchText       string `form:"searchText" validate:"omitempty,min=2" example:"john"`                    // Search across username, email, group

	// Enhanced sorting & pagination
	SortBy    string `form:"sortBy" validate:"omitempty,oneof=username email authMethod role groupName userExpiration" example:"username"`
	SortOrder string `form:"sortOrder" validate:"omitempty,oneof=asc desc" example:"asc"`
	Page      int    `form:"page,default=1" validate:"min=1" example:"1"`
	Limit     int    `form:"limit,default=20" validate:"min=1,max=100" example:"20"`

	// NEW: Search options
	ExactMatch    bool `form:"exactMatch" example:"false"`    // Use exact matching instead of partial
	CaseSensitive bool `form:"caseSensitive" example:"false"` // Case sensitive search
}

// SetDefaults sets default values for UserFilter
func (f *UserFilter) SetDefaults() {
	if f.Page == 0 {
		f.Page = 1
	}
	if f.Limit == 0 {
		f.Limit = 20
	}
	if f.SortBy == "" {
		f.SortBy = "username"
	}
	if f.SortOrder == "" {
		f.SortOrder = "asc"
	}
}

// NEW: Filter metadata for response
type FilterMetadata struct {
	AppliedFilters []string `json:"appliedFilters" example:"username,authMethod,isEnabled"` // List of applied filters
	SortedBy       string   `json:"sortedBy" example:"username"`                            // Current sort field
	SortOrder      string   `json:"sortOrder" example:"asc"`                                // Current sort order
	FilterCount    int      `json:"filterCount" example:"3"`                                // Number of active filters
}

// Enhanced UserListResponse with metadata
type UserListResponse struct {
	Users      []UserResponse `json:"users"`
	Total      int            `json:"total" example:"50"`
	Page       int            `json:"page" example:"1"`
	Limit      int            `json:"limit" example:"20"`
	TotalPages int            `json:"totalPages" example:"3"` // NEW: Total pages
	Filters    UserFilter     `json:"filters"`                // NEW: Applied filters
	Metadata   FilterMetadata `json:"metadata"`               // NEW: Filter metadata
}

type UserActionRequest struct {
	Action string `json:"action" validate:"required,oneof=enable disable reset-otp change-password" example:"enable"`
}

type ChangePasswordRequest struct {
	Password string `json:"password" validate:"required,min=8" example:"NewSecurePass123!"`
}

type UserExpirationResponse struct {
	Emails []string `json:"emails" example:"user1@example.com,user2@example.com"`
	Count  int      `json:"count" example:"2"`
	Days   int      `json:"days" example:"7"`
}

type UserExpirationsResponse struct {
	Users []UserExpirationInfo `json:"users"`
	Count int                  `json:"count"`
	Days  int                  `json:"days"`
}

type UserExpirationInfo struct {
	Username         string   `json:"username"`
	Email            string   `json:"email"`
	UserExpiration   string   `json:"userExpiration"`
	AuthMethod       string   `json:"authMethod"`
	Role             string   `json:"role"`
	GroupName        string   `json:"groupName"`
	DenyAccess       bool     `json:"denyAccess"`
	MFA              bool     `json:"mfa"`
	AccessControl    []string `json:"accessControl,omitempty"`
	MacAddresses     []string `json:"macAddresses,omitempty"`
	DaysUntilExpiry  int      `json:"daysUntilExpiry"`  // Số ngày còn lại
	ExpirationStatus string   `json:"expirationStatus"` // "expired", "expiring", "warning"
}

// Enhanced validation messages with new filters
func (r CreateUserRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Username.required":          "Username is required",
		"Username.min":               "Username must be at least 3 characters",
		"Username.max":               "Username must not exceed 30 characters",
		"Username.username":          "Username can only contain lowercase letters, numbers, dots and underscores",
		"Email.required":             "Email is required",
		"Email.email":                "Email must be a valid email address",
		"Password.password_if_local": "Password is required for local authentication and must be at least 8 characters",
		"AuthMethod.required":        "Authentication method is required",
		"AuthMethod.oneof":           "Authentication method must be either 'ldap' or 'local'",
		"UserExpiration.required":    "User expiration date is required",
		"UserExpiration.date":        "User expiration must be a future date in format DD/MM/YYYY",
		"MacAddresses.required":      "At least one MAC address is required",
		"MacAddresses.mac_address":   "MAC address must be in format XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, or XXXXXXXXXXXX",
		"AccessControl.ipv4":         "Access control must be valid IPv4 address",
		"AccessControl.cidrv4":       "Access control must be valid CIDR notation",
		"IPAssignMode.required":      "IP assign mode is required",
		"IPAssignMode.oneof":         "IP assign mode must be 'dynamic' or 'static'",
		"IPAddress.ipv4":             "IP address must be a valid IPv4 address",
	}
}

func (r UpdateUserRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Password.min":             "Password must be at least 8 characters",
		"UserExpiration.date":      "User expiration must be a future date in format DD/MM/YYYY",
		"MacAddresses.mac_address": "MAC address must be in format XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, or XXXXXXXXXXXX",
		"AccessControl.ipv4":       "Access control must be valid IPv4 address",
		"AccessControl.cidrv4":     "Access control must be valid CIDR notation",
		"IPAssignMode.oneof":       "IP assign mode must be 'dynamic' or 'static'",
		"IPAddress.ipv4":           "IP address must be a valid IPv4 address",
	}
}

func (r ChangePasswordRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Password.required": "Password is required",
		"Password.min":      "Password must be at least 8 characters",
	}
}

// NEW: Enhanced UserFilter validation messages
func (f UserFilter) GetValidationErrors() map[string]string {
	return map[string]string{
		"AuthMethod.oneof":       "Authentication method must be either 'ldap' or 'local'",
		"Role.oneof":             "Role must be either 'Admin' or 'User'",
		"Page.min":               "Page must be at least 1",
		"Limit.min":              "Limit must be at least 1",
		"Limit.max":              "Limit must not exceed 100",
		"ExpiringInDays.min":     "Expiring in days must be non-negative",
		"MacAddress.mac_address": "MAC address must be in valid format",
		"SearchText.min":         "Search text must be at least 2 characters",
		"SortBy.oneof":           "Sort by must be one of: username, email, authMethod, role, groupName, userExpiration",
		"SortOrder.oneof":        "Sort order must be either 'asc' or 'desc'",
	}
}

// CRITICAL FIX: Helper method to validate auth-specific requirements
func (r CreateUserRequest) ValidateAuthSpecific() error {
	if r.AuthMethod == "local" && r.Password == "" {
		return fmt.Errorf("password is required for local authentication")
	}

	if r.AuthMethod == "local" && len(r.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters for local authentication")
	}

	if r.AuthMethod == "ldap" && r.Password != "" {
		return fmt.Errorf("password should not be provided for LDAP users - authentication handled by LDAP server")
	}

	return nil
}

// Helper method to check if password is required
func (r CreateUserRequest) IsPasswordRequired() bool {
	return r.AuthMethod == "local"
}

// NEW: Helper method to validate UserFilter date ranges
func (f UserFilter) ValidateDateRanges() error {
	if f.UserExpirationAfter != nil && f.UserExpirationBefore != nil {
		if f.UserExpirationAfter.After(*f.UserExpirationBefore) {
			return fmt.Errorf("userExpirationAfter cannot be after userExpirationBefore")
		}
	}

	if f.ExpiringInDays != nil && *f.ExpiringInDays < 0 {
		return fmt.Errorf("expiringInDays must be non-negative")
	}

	return nil
}

// Enhanced user creation with validation examples
type CreateUserExamples struct {
	LocalUser CreateUserRequest `json:"localUser"`
	LDAPUser  CreateUserRequest `json:"ldapUser"`
}

func GetCreateUserExamples() CreateUserExamples {
	return CreateUserExamples{
		LocalUser: CreateUserRequest{
			Username:       "localuser",
			Email:          "localuser@example.com",
			Password:       "SecurePass123!",
			AuthMethod:     "local",
			GroupName:      "TEST_GR",
			UserExpiration: "31/12/2024",
			MacAddresses:   []string{"5E:CD:C9:D4:88:65", "AA-BB-CC-DD-EE-FF"},
			AccessControl:  []string{"192.168.1.0/24", "10.0.0.0/8"},
		},
		LDAPUser: CreateUserRequest{
			Username:       "ldapuser",
			Email:          "ldapuser@company.com",
			Password:       "", // Not required for LDAP
			AuthMethod:     "ldap",
			GroupName:      "TEST_GR",
			UserExpiration: "31/12/2024",
			MacAddresses:   []string{"5E:CD:C9:D4:88:66"},
			AccessControl:  []string{"192.168.2.0/24"},
		},
	}
}

// NEW: Filter examples for documentation
type UserFilterExamples struct {
	Basic      UserFilter `json:"basic"`
	Status     UserFilter `json:"status"`
	Expiration UserFilter `json:"expiration"`
	Advanced   UserFilter `json:"advanced"`
}

func GetUserFilterExamples() UserFilterExamples {
	// Helper function to create bool pointers
	boolPtr := func(b bool) *bool { return &b }
	intPtr := func(i int) *int { return &i }
	timePtr := func(s string) *time.Time {
		t, _ := time.Parse("2006-01-02", s)
		return &t
	}

	return UserFilterExamples{
		Basic: UserFilter{
			Username:   "john",
			AuthMethod: "local",
			Role:       "User",
			Page:       1,
			Limit:      20,
			SortBy:     "username",
			SortOrder:  "asc",
		},
		Status: UserFilter{
			IsEnabled:  boolPtr(false),
			MFAEnabled: boolPtr(true),
			DenyAccess: boolPtr(false),
			Page:       1,
			Limit:      20,
		},
		Expiration: UserFilter{
			UserExpirationAfter:  timePtr("2025-06-17"),
			UserExpirationBefore: timePtr("2025-06-22"),
			IncludeExpired:       boolPtr(false),
			ExpiringInDays:       intPtr(7),
			Page:                 1,
			Limit:                20,
		},
		Advanced: UserFilter{
			SearchText:       "developer",
			HasAccessControl: boolPtr(true),
			MacAddress:       "5E:CD:C9",
			ExactMatch:       false,
			CaseSensitive:    false,
			Page:             1,
			Limit:            20,
			SortBy:           "userExpiration",
			SortOrder:        "desc",
		},
	}
}
