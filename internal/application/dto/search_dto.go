package dto

import "time"

// =================== ADVANCED USER SEARCH ===================

// AdvancedUserSearchRequest for complex user search operations
type AdvancedUserSearchRequest struct {
	// Basic filters
	Username   string `json:"username,omitempty" example:"test"`
	Email      string `json:"email,omitempty" example:"test@example.com"`
	AuthMethod string `json:"authMethod,omitempty" validate:"omitempty,oneof=ldap local" example:"local"`
	Role       string `json:"role,omitempty" validate:"omitempty,oneof=Admin User" example:"User"`
	GroupName  string `json:"groupName,omitempty" example:"TEST_GR"`

	// Status filters
	IsEnabled *bool `json:"isEnabled,omitempty" example:"true"`
	HasMFA    *bool `json:"hasMFA,omitempty" example:"true"`
	IsExpired *bool `json:"isExpired,omitempty" example:"false"`

	// Date range filters
	CreatedAfter  *time.Time `json:"createdAfter,omitempty" example:"2024-01-01T00:00:00Z"`
	CreatedBefore *time.Time `json:"createdBefore,omitempty" example:"2024-12-31T23:59:59Z"`
	ExpiresAfter  *time.Time `json:"expiresAfter,omitempty" example:"2024-06-01T00:00:00Z"`
	ExpiresBefore *time.Time `json:"expiresBefore,omitempty" example:"2024-12-31T23:59:59Z"`

	// Expiration alerts
	ExpiringInDays *int `json:"expiringInDays,omitempty" validate:"omitempty,min=0,max=365" example:"30"`

	// MAC Address filters
	HasMacAddress     *bool  `json:"hasMacAddress,omitempty" example:"true"`
	MacAddressPattern string `json:"macAddressPattern,omitempty" example:"AA:BB:*"`

	// Access control filters
	HasAccessControl     *bool  `json:"hasAccessControl,omitempty" example:"true"`
	AccessControlPattern string `json:"accessControlPattern,omitempty" example:"192.168.1.*"`

	// Text search (searches across multiple fields)
	SearchText string `json:"searchText,omitempty" example:"john"`

	// Sorting
	SortBy    string `json:"sortBy,omitempty" validate:"omitempty,oneof=username email authMethod role groupName userExpiration createdAt" example:"username"`
	SortOrder string `json:"sortOrder,omitempty" validate:"omitempty,oneof=asc desc" example:"asc"`

	// Pagination
	Page  int `json:"page,omitempty" validate:"min=1" example:"1"`
	Limit int `json:"limit,omitempty" validate:"min=1,max=1000" example:"50"`

	// Advanced options
	IncludeDisabled bool `json:"includeDisabled,omitempty" example:"false"`
	ExactMatch      bool `json:"exactMatch,omitempty" example:"false"`
}

// AdvancedUserSearchResponse with enhanced metadata
type AdvancedUserSearchResponse struct {
	Users      []UserResponse            `json:"users"`
	Total      int                       `json:"total" example:"150"`
	Page       int                       `json:"page" example:"1"`
	Limit      int                       `json:"limit" example:"50"`
	TotalPages int                       `json:"totalPages" example:"3"`
	Metadata   UserSearchMetadata        `json:"metadata"`
	Filters    AdvancedUserSearchRequest `json:"filters,omitempty"`
}

// UserSearchMetadata provides search statistics
type UserSearchMetadata struct {
	SearchDuration  string               `json:"searchDuration" example:"125ms"`
	FilteredTotal   int                  `json:"filteredTotal" example:"150"`
	UnfilteredTotal int                  `json:"unfilteredTotal" example:"500"`
	AuthMethodStats map[string]int       `json:"authMethodStats" example:"{\"local\":80,\"ldap\":70}"`
	RoleStats       map[string]int       `json:"roleStats" example:"{\"Admin\":10,\"User\":140}"`
	ExpirationStats ExpirationStatistics `json:"expirationStats"`
	GroupStats      map[string]int       `json:"groupStats,omitempty"`
}

// ExpirationStatistics provides expiration insights
type ExpirationStatistics struct {
	ExpiredCount     int `json:"expiredCount" example:"5"`
	ExpiringIn7Days  int `json:"expiringIn7Days" example:"10"`
	ExpiringIn30Days int `json:"expiringIn30Days" example:"25"`
	ExpiringIn90Days int `json:"expiringIn90Days" example:"45"`
}

// =================== ADVANCED GROUP SEARCH ===================

// AdvancedGroupSearchRequest for complex group search operations
type AdvancedGroupSearchRequest struct {
	// Basic filters
	GroupName  string `json:"groupName,omitempty" example:"TEST"`
	AuthMethod string `json:"authMethod,omitempty" validate:"omitempty,oneof=ldap local" example:"local"`
	Role       string `json:"role,omitempty" validate:"omitempty,oneof=Admin User" example:"User"`

	// Status filters
	IsEnabled *bool `json:"isEnabled,omitempty" example:"true"`
	HasMFA    *bool `json:"hasMFA,omitempty" example:"true"`

	// Member count filters
	MinMemberCount *int  `json:"minMemberCount,omitempty" validate:"omitempty,min=0" example:"1"`
	MaxMemberCount *int  `json:"maxMemberCount,omitempty" validate:"omitempty,min=0" example:"100"`
	HasMembers     *bool `json:"hasMembers,omitempty" example:"true"`

	// Access control filters
	HasAccessControl     *bool  `json:"hasAccessControl,omitempty" example:"true"`
	AccessControlPattern string `json:"accessControlPattern,omitempty" example:"192.168.*"`

	// Date range filters
	CreatedAfter  *time.Time `json:"createdAfter,omitempty" example:"2024-01-01T00:00:00Z"`
	CreatedBefore *time.Time `json:"createdBefore,omitempty" example:"2024-12-31T23:59:59Z"`

	// Text search
	SearchText string `json:"searchText,omitempty" example:"admin"`

	// Sorting
	SortBy    string `json:"sortBy,omitempty" validate:"omitempty,oneof=groupName authMethod role memberCount createdAt" example:"groupName"`
	SortOrder string `json:"sortOrder,omitempty" validate:"omitempty,oneof=asc desc" example:"asc"`

	// Pagination
	Page  int `json:"page,omitempty" validate:"min=1" example:"1"`
	Limit int `json:"limit,omitempty" validate:"min=1,max=500" example:"25"`

	// Advanced options
	IncludeDisabled    bool `json:"includeDisabled,omitempty" example:"false"`
	IncludeMemberCount bool `json:"includeMemberCount,omitempty" example:"true"`
	ExactMatch         bool `json:"exactMatch,omitempty" example:"false"`
}

// AdvancedGroupSearchResponse with enhanced metadata
type AdvancedGroupSearchResponse struct {
	Groups     []EnhancedGroupResponse    `json:"groups"`
	Total      int                        `json:"total" example:"25"`
	Page       int                        `json:"page" example:"1"`
	Limit      int                        `json:"limit" example:"25"`
	TotalPages int                        `json:"totalPages" example:"1"`
	Metadata   GroupSearchMetadata        `json:"metadata"`
	Filters    AdvancedGroupSearchRequest `json:"filters,omitempty"`
}

// EnhancedGroupResponse extends GroupResponse with additional metadata
type EnhancedGroupResponse struct {
	GroupResponse
	MemberCount  int        `json:"memberCount" example:"15"`
	CreatedAt    *time.Time `json:"createdAt,omitempty" example:"2024-01-15T10:30:00Z"`
	LastModified *time.Time `json:"lastModified,omitempty" example:"2024-03-10T14:22:00Z"`
	LastUsed     *time.Time `json:"lastUsed,omitempty" example:"2024-06-01T08:15:00Z"`
}

// GroupSearchMetadata provides group search statistics
type GroupSearchMetadata struct {
	SearchDuration   string                `json:"searchDuration" example:"45ms"`
	FilteredTotal    int                   `json:"filteredTotal" example:"25"`
	UnfilteredTotal  int                   `json:"unfilteredTotal" example:"100"`
	AuthMethodStats  map[string]int        `json:"authMethodStats" example:"{\"local\":15,\"ldap\":10}"`
	RoleStats        map[string]int        `json:"roleStats" example:"{\"Admin\":5,\"User\":20}"`
	MemberCountStats MemberCountStatistics `json:"memberCountStats"`
}

// MemberCountStatistics provides member count insights
type MemberCountStatistics struct {
	EmptyGroups  int     `json:"emptyGroups" example:"3"`
	SmallGroups  int     `json:"smallGroups" example:"10"` // 1-10 members
	MediumGroups int     `json:"mediumGroups" example:"8"` // 11-50 members
	LargeGroups  int     `json:"largeGroups" example:"4"`  // 50+ members
	AverageSize  float64 `json:"averageSize" example:"12.5"`
	MaxSize      int     `json:"maxSize" example:"75"`
}

// =================== SAVED SEARCHES ===================

// SavedSearchRequest for saving frequently used searches
type SavedSearchRequest struct {
	Name        string      `json:"name" validate:"required,min=3,max=50" example:"Expiring Users Next Month"`
	Description string      `json:"description,omitempty" example:"Users expiring in the next 30 days"`
	SearchType  string      `json:"searchType" validate:"required,oneof=users groups" example:"users"`
	Filters     interface{} `json:"filters" example:"{\"expiringInDays\":30}"`
	IsPublic    bool        `json:"isPublic,omitempty" example:"false"`
	Tags        []string    `json:"tags,omitempty" example:"[\"expiration\",\"maintenance\"]"`
}

// SavedSearchResponse for saved search information
type SavedSearchResponse struct {
	ID          string      `json:"id" example:"search_123"`
	Name        string      `json:"name" example:"Expiring Users Next Month"`
	Description string      `json:"description,omitempty" example:"Users expiring in the next 30 days"`
	SearchType  string      `json:"searchType" example:"users"`
	Filters     interface{} `json:"filters"`
	IsPublic    bool        `json:"isPublic" example:"false"`
	Tags        []string    `json:"tags,omitempty" example:"[\"expiration\",\"maintenance\"]"`
	CreatedBy   string      `json:"createdBy" example:"admin"`
	CreatedAt   time.Time   `json:"createdAt" example:"2024-01-15T10:30:00Z"`
	LastUsed    *time.Time  `json:"lastUsed,omitempty" example:"2024-06-01T08:15:00Z"`
	UseCount    int         `json:"useCount" example:"15"`
}

// =================== SEARCH SUGGESTIONS ===================

// SearchSuggestionsRequest for getting search suggestions
type SearchSuggestionsRequest struct {
	SearchType string `json:"searchType" validate:"required,oneof=users groups" example:"users"`
	Query      string `json:"query" validate:"required,min=1" example:"test"`
	Field      string `json:"field,omitempty" validate:"omitempty,oneof=username email groupName" example:"username"`
	Limit      int    `json:"limit,omitempty" validate:"min=1,max=20" example:"10"`
}

// SearchSuggestionsResponse provides autocomplete suggestions
type SearchSuggestionsResponse struct {
	Suggestions []SearchSuggestion `json:"suggestions"`
	Total       int                `json:"total" example:"5"`
}

// SearchSuggestion represents a single suggestion
type SearchSuggestion struct {
	Value      string            `json:"value" example:"testuser"`
	Label      string            `json:"label" example:"testuser (test@example.com)"`
	Type       string            `json:"type" example:"username"`
	Metadata   map[string]string `json:"metadata,omitempty" example:"{\"authMethod\":\"local\"}"`
	MatchCount int               `json:"matchCount" example:"1"`
}

// =================== VALIDATION MESSAGES ===================

func (r AdvancedUserSearchRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"AuthMethod.oneof":   "Auth method must be either 'ldap' or 'local'",
		"Role.oneof":         "Role must be either 'Admin' or 'User'",
		"ExpiringInDays.min": "Expiring in days must be at least 0",
		"ExpiringInDays.max": "Expiring in days must be at most 365",
		"SortBy.oneof":       "Sort by must be one of: username, email, authMethod, role, groupName, userExpiration, createdAt",
		"SortOrder.oneof":    "Sort order must be either 'asc' or 'desc'",
		"Page.min":           "Page must be at least 1",
		"Limit.min":          "Limit must be at least 1",
		"Limit.max":          "Limit must be at most 1000",
	}
}

func (r AdvancedGroupSearchRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"AuthMethod.oneof":   "Auth method must be either 'ldap' or 'local'",
		"Role.oneof":         "Role must be either 'Admin' or 'User'",
		"MinMemberCount.min": "Minimum member count must be at least 0",
		"MaxMemberCount.min": "Maximum member count must be at least 0",
		"SortBy.oneof":       "Sort by must be one of: groupName, authMethod, role, memberCount, createdAt",
		"SortOrder.oneof":    "Sort order must be either 'asc' or 'desc'",
		"Page.min":           "Page must be at least 1",
		"Limit.min":          "Limit must be at least 1",
		"Limit.max":          "Limit must be at most 500",
	}
}

func (r SavedSearchRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Name.required":       "Search name is required",
		"Name.min":            "Search name must be at least 3 characters",
		"Name.max":            "Search name must not exceed 50 characters",
		"SearchType.required": "Search type is required",
		"SearchType.oneof":    "Search type must be either 'users' or 'groups'",
	}
}

func (r SearchSuggestionsRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"SearchType.required": "Search type is required",
		"SearchType.oneof":    "Search type must be either 'users' or 'groups'",
		"Query.required":      "Query is required",
		"Query.min":           "Query must be at least 1 character",
		"Field.oneof":         "Field must be one of: username, email, groupName",
		"Limit.min":           "Limit must be at least 1",
		"Limit.max":           "Limit must be at most 20",
	}
}
