package dto

type CreateUserRequest struct {
	Username       string   `json:"username" validate:"required,min=3,max=30,username"`
	Email          string   `json:"email" validate:"required,email"`
	Password       string   `json:"password,omitempty" validate:"omitempty,min=8"`
	AuthMethod     string   `json:"authMethod" validate:"required,oneof=ldap local"`
	UserExpiration string   `json:"userExpiration" validate:"required,date"`
	MacAddresses   []string `json:"macAddresses" validate:"required,dive,hex16"`
	AccessControl  []string `json:"accessControl,omitempty" validate:"omitempty,dive,ipv4|cidrv4|ipv4_protocol"`
}

type UpdateUserRequest struct {
	Password       string   `json:"password,omitempty" validate:"omitempty,min=8"`
	UserExpiration string   `json:"userExpiration,omitempty" validate:"omitempty,date"`
	DenyAccess     *bool    `json:"denyAccess,omitempty"`
	MacAddresses   []string `json:"macAddresses,omitempty" validate:"omitempty,dive,hex16"`
	AccessControl  []string `json:"accessControl,omitempty" validate:"omitempty,dive,ipv4|cidrv4|ipv4_protocol"`
}

type UserResponse struct {
	Username       string   `json:"username"`
	Email          string   `json:"email"`
	AuthMethod     string   `json:"authMethod"`
	UserExpiration string   `json:"userExpiration"`
	MacAddresses   []string `json:"macAddresses"`
	MFA            bool     `json:"mfa"`
	Role           string   `json:"role"`
	DenyAccess     bool     `json:"denyAccess"`
	AccessControl  []string `json:"accessControl"`
	GroupName      string   `json:"groupName"`
}

type UserListResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Limit int            `json:"limit"`
}

type UserActionRequest struct {
	Action string `json:"action" validate:"required,oneof=enable disable reset-otp change-password"`
}

type ChangePasswordRequest struct {
	Password string `json:"password" validate:"required,min=8"`
}

type UserExpirationResponse struct {
	Emails []string `json:"emails"`
	Count  int      `json:"count"`
	Days   int      `json:"days"`
}

type UserFilter struct {
	Username   string `form:"username"`
	Email      string `form:"email"`
	AuthMethod string `form:"authMethod"`
	Role       string `form:"role"`
	GroupName  string `form:"groupName"`
	Page       int    `form:"page,default=1" validate:"min=1"`
	Limit      int    `form:"limit,default=10" validate:"min=1,max=100"`
}

// Validation messages
func (r CreateUserRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Username.required":       "Username is required",
		"Username.min":            "Username must be at least 3 characters",
		"Username.max":            "Username must not exceed 30 characters",
		"Username.username":       "Username can only contain lowercase letters, numbers, dots and underscores",
		"Email.required":          "Email is required",
		"Email.email":             "Email must be a valid email address",
		"Password.min":            "Password must be at least 8 characters",
		"AuthMethod.required":     "Authentication method is required",
		"AuthMethod.oneof":        "Authentication method must be either 'ldap' or 'local'",
		"UserExpiration.required": "User expiration date is required",
		"UserExpiration.date":     "User expiration must be a future date in format DD/MM/YYYY",
		"MacAddresses.required":   "At least one MAC address is required",
		"MacAddresses.hex16":      "MAC address must be 16 hexadecimal characters",
	}
}

func (r UpdateUserRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Password.min":        "Password must be at least 8 characters",
		"UserExpiration.date": "User expiration must be a future date in format DD/MM/YYYY",
		"MacAddresses.hex16":  "MAC address must be 16 hexadecimal characters",
	}
}
