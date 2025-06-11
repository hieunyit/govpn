package dto

import "fmt"

type CreateUserRequest struct {
	Username       string   `json:"username" validate:"required,min=3,max=30,username" example:"testuser"`
	Email          string   `json:"email" validate:"required,email" example:"testuser@example.com"`
	Password       string   `json:"password,omitempty" validate:"password_if_local" example:"SecurePass123!"`
	AuthMethod     string   `json:"authMethod" validate:"required,oneof=ldap local" example:"local"`
	UserExpiration string   `json:"userExpiration" validate:"required,date" example:"31/12/2024"`
	MacAddresses   []string `json:"macAddresses" validate:"required,dive,mac_address" example:"5E:CD:C9:D4:88:65"`
	AccessControl  []string `json:"accessControl,omitempty" validate:"omitempty,dive,ipv4|cidrv4|ipv4_protocol" example:"192.168.1.0/24"`
}

type UpdateUserRequest struct {
	Password       string   `json:"password,omitempty" validate:"omitempty,min=8" example:"NewSecurePass123!"`
	UserExpiration string   `json:"userExpiration,omitempty" validate:"omitempty,date" example:"31/12/2025"`
	DenyAccess     *bool    `json:"denyAccess,omitempty" example:"false"`
	MacAddresses   []string `json:"macAddresses,omitempty" validate:"omitempty,dive,mac_address" example:"5E:CD:C9:D4:88:65"`
	AccessControl  []string `json:"accessControl,omitempty" validate:"omitempty,dive,ipv4|cidrv4|ipv4_protocol" example:"192.168.1.0/24"`
}

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
}

type UserListResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total" example:"50"`
	Page  int            `json:"page" example:"1"`
	Limit int            `json:"limit" example:"10"`
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

type UserFilter struct {
	Username   string `form:"username" example:"testuser"`
	Email      string `form:"email" example:"test@example.com"`
	AuthMethod string `form:"authMethod" validate:"omitempty,oneof=ldap local" example:"local"`
	Role       string `form:"role" validate:"omitempty,oneof=Admin User" example:"User"`
	GroupName  string `form:"groupName" example:"TEST_GR"`
	Page       int    `form:"page,default=1" validate:"min=1" example:"1"`
	Limit      int    `form:"limit,default=10" validate:"min=1,max=100" example:"10"`
}

// Enhanced validation messages with specific auth method guidance
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
	}
}

func (r UpdateUserRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Password.min":             "Password must be at least 8 characters",
		"UserExpiration.date":      "User expiration must be a future date in format DD/MM/YYYY",
		"MacAddresses.mac_address": "MAC address must be in format XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, or XXXXXXXXXXXX",
		"AccessControl.ipv4":       "Access control must be valid IPv4 address",
		"AccessControl.cidrv4":     "Access control must be valid CIDR notation",
	}
}

func (r ChangePasswordRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Password.required": "Password is required",
		"Password.min":      "Password must be at least 8 characters",
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
			UserExpiration: "31/12/2024",
			MacAddresses:   []string{"5E:CD:C9:D4:88:65", "AA-BB-CC-DD-EE-FF"},
			AccessControl:  []string{"192.168.1.0/24", "10.0.0.0/8"},
		},
		LDAPUser: CreateUserRequest{
			Username:       "ldapuser",
			Email:          "ldapuser@company.com",
			Password:       "", // Not required for LDAP
			AuthMethod:     "ldap",
			UserExpiration: "31/12/2024",
			MacAddresses:   []string{"5E:CD:C9:D4:88:66"},
			AccessControl:  []string{"192.168.2.0/24"},
		},
	}
}
