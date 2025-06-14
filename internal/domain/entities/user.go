package entities

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
}

type UserFilter struct {
	Username   string
	Email      string
	AuthMethod string
	Role       string
	GroupName  string
	Limit      int
	Offset     int // ✅ Make sure this exists
	Page       int
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
		Username:   username,
		Email:      email,
		AuthMethod: authMethod,
		GroupName:  groupName,
		Role:       UserRoleUser,
		DenyAccess: "false",
		MFA:        "true",
	}
}
