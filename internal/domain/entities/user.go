package entities

import "time"

type User struct {
	Username       string   `json:"username"`
	Email          string   `json:"email"`
	AuthMethod     string   `json:"authMethod"`
	GroupName      string   `json:"groupName"`
	Password       string   `json:"password,omitempty"`
	UserExpiration string   `json:"userExpiration"`
	MacAddresses   []string `json:"macAddresses"`
	MFA            string   `json:"mfa"`
	Role           string   `json:"role"`
	DenyAccess     string   `json:"denyAccess"`
	AccessControl  []string `json:"accessControl"`
	IPAddress      string   `json:"ipAddress"`
	IPAssignMode   string   `json:"ipAssignMode"`
}

type UserFilter struct {
	// Basic filters (existing)
	Username   string `json:"username" form:"username"`
	Email      string `json:"email" form:"email"`
	AuthMethod string `json:"authMethod" form:"authMethod" binding:"omitempty,oneof=local ldap"`
	Role       string `json:"role" form:"role" binding:"omitempty,oneof=Admin User"`
	GroupName  string `json:"groupName" form:"groupName"`

	// Status filters (based on existing fields)
	IsEnabled  *bool `json:"isEnabled" form:"isEnabled"`   // Based on DenyAccess field
	DenyAccess *bool `json:"denyAccess" form:"denyAccess"` // Direct mapping to DenyAccess field
	MFAEnabled *bool `json:"mfaEnabled" form:"mfaEnabled"` // Based on MFA field

	// Expiration filters (based on UserExpiration field)
	UserExpirationAfter  *time.Time `json:"userExpirationAfter" form:"userExpirationAfter" time_format:"2006-01-02"`
	UserExpirationBefore *time.Time `json:"userExpirationBefore" form:"userExpirationBefore" time_format:"2006-01-02"`
	IncludeExpired       *bool      `json:"includeExpired" form:"includeExpired"` // Include users past expiration date
	ExpiringInDays       *int       `json:"expiringInDays" form:"expiringInDays"` // Users expiring within X days

	// Advanced filters (based on existing fields)
	HasAccessControl *bool  `json:"hasAccessControl" form:"hasAccessControl"` // Based on AccessControl field
	MacAddress       string `json:"macAddress" form:"macAddress"`             // Based on MacAddresses field
	SearchText       string `json:"searchText" form:"searchText"`             // Search across username, email
	IPAddress        string `json:"ipAddress" form:"ipAddress"`

	// Sorting & pagination
	SortBy    string `json:"sortBy" form:"sortBy" binding:"omitempty,oneof=username email authMethod role groupName userExpiration"`
	SortOrder string `json:"sortOrder" form:"sortOrder" binding:"omitempty,oneof=asc desc"`
	Page      int    `json:"page" form:"page" binding:"min=1"`
	Limit     int    `json:"limit" form:"limit" binding:"min=1,max=100"`
	Offset    int    `json:"-"` // Calculated from Page & Limit

	// Options
	ExactMatch    bool `json:"exactMatch" form:"exactMatch"`       // Exact vs partial matching
	CaseSensitive bool `json:"caseSensitive" form:"caseSensitive"` // Case sensitive search
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

	// Calculate offset
	f.Offset = (f.Page - 1) * f.Limit
}

// UserRole constants
const (
	UserRoleAdmin = "Admin"
	UserRoleUser  = "User"
)

// AuthMethod constants
const (
	AuthMethodLocal = "local"
	AuthMethodLDAP  = "ldap"
)

// IP assignment modes
const (
	IPAssignModeDynamic = "dynamic"
	IPAssignModeStatic  = "static"
)

// Methods
func (u *User) IsAdmin() bool {
	return u.Role == UserRoleAdmin
}

func (u *User) IsLocalAuth() bool {
	return u.AuthMethod == AuthMethodLocal
}

func (u *User) IsLDAPAuth() bool {
	return u.AuthMethod == AuthMethodLDAP
}

func (u *User) IsAccessDenied() bool {
	return u.DenyAccess == "true"
}

func (u *User) IsMFAEnabled() bool {
	return u.MFA == "true"
}

func (u *User) IsEnabled() bool {
	return u.DenyAccess != "true"
}

func (u *User) HasAccessControl() bool {
	return len(u.AccessControl) > 0
}

func (u *User) SetDenyAccess(deny bool) {
	if deny {
		u.DenyAccess = "true"
	} else {
		u.DenyAccess = "false"
	}
}

func (u *User) SetMFA(enabled bool) {
	if enabled {
		u.MFA = "true"
	} else {
		u.MFA = "false"
	}
}

func NewUser(username, email, authMethod, groupName string) *User {
	return &User{
		Username:     username,
		Email:        email,
		AuthMethod:   authMethod,
		GroupName:    groupName,
		Role:         UserRoleUser,
		DenyAccess:   "false",
		MFA:          "true",
		IPAssignMode: IPAssignModeDynamic,
	}
}
