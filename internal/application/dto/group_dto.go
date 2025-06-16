package dto

type CreateGroupRequest struct {
	GroupName     string   `json:"groupName" validate:"required,min=3,max=50"`
	AuthMethod    string   `json:"authMethod" validate:"required,oneof=ldap local"`
	MFA           *bool    `json:"mfa,omitempty"`
	Role          string   `json:"role,omitempty" validate:"omitempty,oneof=User Admin"`
	AccessControl []string `json:"accessControl,omitempty" validate:"omitempty,dive,ipv4|cidrv4|ipv4_protocol"`
	GroupSubnet   []string `json:"groupSubnet,omitempty" validate:"omitempty,dive,cidrv4"`
	GroupRange    []string `json:"groupRange,omitempty" validate:"omitempty,dive,ip_range"`
}

type UpdateGroupRequest struct {
	AccessControl []string `json:"accessControl,omitempty" validate:"omitempty,dive,ipv4|cidrv4|ipv4_protocol"`
	MFA           *bool    `json:"mfa,omitempty"`
	Role          string   `json:"role,omitempty" validate:"omitempty,oneof=User Admin"`
	DenyAccess    *bool    `json:"denyAccess,omitempty"`
	GroupSubnet   []string `json:"groupSubnet,omitempty" validate:"omitempty,dive,cidrv4"`
	GroupRange    []string `json:"groupRange,omitempty" validate:"omitempty,dive,ip_range"`
}

type GroupResponse struct {
	GroupName     string   `json:"groupName"`
	AuthMethod    string   `json:"authMethod"`
	MFA           bool     `json:"mfa"`
	Role          string   `json:"role"`
	DenyAccess    bool     `json:"denyAccess"`
	AccessControl []string `json:"accessControl"`
	GroupSubnet   []string `json:"groupSubnet"`
	GroupRange    []string `json:"groupRange"`
}

type GroupListResponse struct {
	Groups []GroupResponse `json:"groups"`
	Total  int             `json:"total"`
	Page   int             `json:"page"`
	Limit  int             `json:"limit"`
}

type GroupActionRequest struct {
	Action string `json:"action" validate:"required,oneof=enable disable"`
}

type GroupFilter struct {
	GroupName  string `form:"groupName"`
	AuthMethod string `form:"authMethod"`
	Role       string `form:"role"`
	Page       int    `form:"page,default=1" validate:"min=1"`
	Limit      int    `form:"limit,default=10" validate:"min=1,max=100"`
}

// Validation messages
func (r CreateGroupRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"GroupName.required":   "Group name is required",
		"GroupName.min":        "Group name must be at least 3 characters",
		"GroupName.max":        "Group name must not exceed 50 characters",
		"AuthMethod.required":  "Authentication method is required",
		"AuthMethod.oneof":     "Authentication method must be either 'ldap' or 'local'",
		"Role.oneof":           "Role must be either 'User' or 'Admin'",
		"AccessControl.ipv4":   "Access control must be valid IPv4 address",
		"AccessControl.cidrv4": "Access control must be valid CIDR notation",
		"GroupSubnet.cidrv4":   "Group subnet must be valid CIDR notation",
		"GroupRange.ip_range":  "Group range must be valid IP range (e.g., 10.10.10.10-10.10.10.100)",
	}
}

func (r UpdateGroupRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Role.oneof":           "Role must be either 'User' or 'Admin'",
		"AccessControl.ipv4":   "Access control must be valid IPv4 address",
		"AccessControl.cidrv4": "Access control must be valid CIDR notation",
		"GroupSubnet.cidrv4":   "Group subnet must be valid CIDR notation",
		"GroupRange.ip_range":  "Group range must be valid IP range (e.g., 10.10.10.10-10.10.10.100)",
	}
}

func (r GroupActionRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Action.required": "Action is required",
		"Action.oneof":    "Action must be either 'enable' or 'disable'",
	}
}
