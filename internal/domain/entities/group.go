package entities

type Group struct {
	GroupName     string   `json:"groupName"`
	AuthMethod    string   `json:"authMethod"`
	MFA           string   `json:"mfa"`
	Role          string   `json:"role"`
	DenyAccess    string   `json:"denyAccess"`
	AccessControl []string `json:"accessControl"`
	GroupSubnet   []string `json:"groupSubnet"`
	GroupRange    []string `json:"groupRange"`
}

type GroupFilter struct {
	GroupName  string
	AuthMethod string
	Role       string
	Limit      int
	Offset     int
	Page       int
}

// Methods
func (g *Group) IsAccessDenied() bool {
	return g.DenyAccess == "true"
}

func (g *Group) SetDenyAccess(deny bool) {
	if deny {
		g.DenyAccess = "true"
	} else {
		g.DenyAccess = "false"
	}
}

func (g *Group) SetMFA(enabled bool) {
	if enabled {
		g.MFA = "true"
	} else {
		g.MFA = "false"
	}
}

func (g *Group) HasAccessControl() bool {
	return len(g.AccessControl) > 0
}

func (g *Group) HasGroupSubnet() bool {
	return len(g.GroupSubnet) > 0
}

func (g *Group) HasGroupRange() bool {
	return len(g.GroupRange) > 0
}

func NewGroup(groupName, authMethod string) *Group {
	return &Group{
		GroupName:   groupName,
		AuthMethod:  authMethod,
		Role:        UserRoleUser,
		DenyAccess:  "false",
		MFA:         "true",
		GroupSubnet: []string{},
		GroupRange:  []string{},
	}
}
