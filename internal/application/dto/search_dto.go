package dto

import (
	"time"
)

// =================== ADVANCED USER SEARCH ===================

// AdvancedUserSearchRequest for complex user search operations
type AdvancedUserSearchRequest struct {
	// Basic filters
	Username   string `json:"username,omitempty" example:"testuser"`
	Email      string `json:"email,omitempty" example:"test@example.com"`
	AuthMethod string `json:"authMethod,omitempty" validate:"omitempty,oneof=ldap local" example:"local"`
	Role       string `json:"role,omitempty" validate:"omitempty,oneof=Admin User" example:"User"`
	GroupName  string `json:"groupName,omitempty" example:"TEST_GROUP"`

	// Status filters
	IsEnabled *bool `json:"isEnabled,omitempty" example:"true"`
	HasMFA    *bool `json:"hasMFA,omitempty" example:"true"`

	// Expiration filters
	IsExpired        *bool      `json:"isExpired,omitempty" example:"false"`
	ExpiringInDays   *int       `json:"expiringInDays,omitempty" validate:"omitempty,min=0,max=365" example:"30"`
	ExpirationAfter  *time.Time `json:"expirationAfter,omitempty" example:"2024-01-01T00:00:00Z"`
	ExpirationBefore *time.Time `json:"expirationBefore,omitempty" example:"2024-12-31T23:59:59Z"`

	// MAC address filters
	HasMacAddress     *bool  `json:"hasMacAddress,omitempty" example:"true"`
	MacAddressPattern string `json:"macAddressPattern,omitempty" example:"00:11:22"`

	// Access control filters
	HasAccessControl     *bool  `json:"hasAccessControl,omitempty" example:"true"`
	AccessControlPattern string `json:"accessControlPattern,omitempty" example:"192.168.1.0/24"`

	// Date range filters
	CreatedAfter  *time.Time `json:"createdAfter,omitempty" example:"2024-01-01T00:00:00Z"`
	CreatedBefore *time.Time `json:"createdBefore,omitempty" example:"2024-12-31T23:59:59Z"`

	// Text search
	SearchText string `json:"searchText,omitempty" example:"admin"`

	// Sorting
	SortBy    string `json:"sortBy,omitempty" validate:"omitempty,oneof=username email authMethod role groupName userExpiration" example:"username"`
	SortOrder string `json:"sortOrder,omitempty" validate:"omitempty,oneof=asc desc" example:"asc"`

	// Pagination
	Page  int `json:"page,omitempty" validate:"min=1" example:"1"`
	Limit int `json:"limit,omitempty" validate:"min=1,max=1000" example:"25"`

	// Advanced options
	IncludeDisabled bool `json:"includeDisabled,omitempty" example:"false"`
	ExactMatch      bool `json:"exactMatch,omitempty" example:"false"`
}

// AdvancedUserSearchResponse with enhanced metadata
type AdvancedUserSearchResponse struct {
	Users      []UserResponse            `json:"users"`
	Total      int                       `json:"total" example:"150"`
	Page       int                       `json:"page" example:"1"`
	Limit      int                       `json:"limit" example:"25"`
	TotalPages int                       `json:"totalPages" example:"6"`
	Metadata   UserSearchMetadata        `json:"metadata"`
	Filters    AdvancedUserSearchRequest `json:"filters,omitempty"`
}

// UserSearchMetadata provides search statistics
type UserSearchMetadata struct {
	SearchDuration  string               `json:"searchDuration" example:"125ms"`
	FilteredTotal   int                  `json:"filteredTotal" example:"150"`
	UnfilteredTotal int                  `json:"unfilteredTotal" example:"500"`
	AuthMethodStats map[string]int       `json:"authMethodStats"`
	RoleStats       map[string]int       `json:"roleStats"`
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
	AccessControlPattern string `json:"accessControlPattern,omitempty" example:"192.168.1.0/24"`

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
	AuthMethodStats  map[string]int        `json:"authMethodStats"`
	RoleStats        map[string]int        `json:"roleStats"`
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
	Filters     interface{} `json:"filters"`
	IsPublic    bool        `json:"isPublic,omitempty" example:"false"`
	Tags        []string    `json:"tags,omitempty"`
}

// SavedSearchResponse for saved search information
type SavedSearchResponse struct {
	ID          string      `json:"id" example:"search_123"` // Keep both for compatibility
	SearchId    string      `json:"searchId" example:"search_123"`
	Name        string      `json:"name" example:"Expiring Users Next Month"`
	Description string      `json:"description,omitempty" example:"Users expiring in the next 30 days"`
	SearchType  string      `json:"searchType" example:"users"`
	Filters     interface{} `json:"filters"`
	IsPublic    bool        `json:"isPublic" example:"false"`
	Tags        []string    `json:"tags,omitempty"`
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
	Text        string            `json:"text" example:"testuser"`
	Type        string            `json:"type" example:"username"`
	Description string            `json:"description" example:"User: testuser (test@example.com)"`
	Count       int               `json:"count" example:"1"`
	Value       string            `json:"value,omitempty" example:"testuser"`
	Label       string            `json:"label,omitempty" example:"testuser (test@example.com)"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	MatchCount  int               `json:"matchCount,omitempty" example:"1"`
}

// =================== QUICK SEARCH ===================

// QuickSearchRequest for simple search operations
type QuickSearchRequest struct {
	Query      string `json:"query" validate:"required,min=1" example:"admin"`
	SearchType string `json:"searchType,omitempty" validate:"omitempty,oneof=all users groups" example:"all"`
	Limit      int    `json:"limit,omitempty" validate:"min=1,max=100" example:"10"`
}

// QuickSearchResponse provides quick search results
type QuickSearchResponse struct {
	Query      string                 `json:"query" example:"admin"`
	SearchType string                 `json:"searchType" example:"all"`
	Results    map[string]interface{} `json:"results"`
	Total      int                    `json:"total" example:"25"`
	Duration   string                 `json:"duration" example:"45ms"`
}

// =================== ANALYTICS & STATISTICS ===================

// SearchAnalyticsRequest for search analytics
type SearchAnalyticsRequest struct {
	Username  string     `json:"username,omitempty" example:"admin"`
	Period    string     `json:"period" validate:"required,oneof=day week month year" example:"month"`
	StartDate *time.Time `json:"startDate,omitempty" example:"2024-01-01T00:00:00Z"`
	EndDate   *time.Time `json:"endDate,omitempty" example:"2024-01-31T23:59:59Z"`
}

// SearchAnalyticsResponse provides search usage analytics
type SearchAnalyticsResponse struct {
	Period          string             `json:"period" example:"month"`
	Username        string             `json:"username,omitempty" example:"admin"`
	TotalSearches   int                `json:"totalSearches" example:"157"`
	SearchBreakdown map[string]int     `json:"searchBreakdown"`
	PopularTerms    []string           `json:"popularTerms"`
	AvgResponseTime string             `json:"avgResponseTime" example:"145ms"`
	SearchFrequency map[string]int     `json:"searchFrequency"`
	PeakHours       []int              `json:"peakHours"`
	TrendData       []SearchTrendPoint `json:"trendData"`
}

// SearchTrendPoint represents a point in search trend data
type SearchTrendPoint struct {
	Date  string `json:"date" example:"2024-01-15"`
	Count int    `json:"count" example:"23"`
}

// =================== EXPORT ===================

// ExportRequest for exporting search results
type ExportRequest struct {
	Format     string      `json:"format" validate:"required,oneof=csv xlsx json" example:"csv"`
	SearchType string      `json:"searchType" validate:"required,oneof=users groups" example:"users"`
	Filters    interface{} `json:"filters"`
	Filename   string      `json:"filename,omitempty" example:"users_export"`
}

// ExportResponse provides export file information
type ExportResponse struct {
	Filename    string    `json:"filename" example:"users_export_20240115_143022.csv"`
	Size        int64     `json:"size" example:"15024"`
	RecordCount int       `json:"recordCount" example:"150"`
	Format      string    `json:"format" example:"csv"`
	DownloadURL string    `json:"downloadUrl,omitempty" example:"/api/exports/download/abc123"`
	ExportedAt  time.Time `json:"exportedAt" example:"2024-01-15T14:30:22Z"`
}

// =================== FUZZY & SIMILARITY SEARCH ===================

// FuzzySearchRequest for fuzzy search operations
type FuzzySearchRequest struct {
	Query      string  `json:"query" validate:"required,min=1" example:"admni"`
	EntityType string  `json:"entityType" validate:"required,oneof=users groups" example:"users"`
	Threshold  float64 `json:"threshold,omitempty" validate:"min=0,max=1" example:"0.6"`
	Limit      int     `json:"limit,omitempty" validate:"min=1,max=50" example:"10"`
}

// FuzzySearchResponse provides fuzzy search results
type FuzzySearchResponse struct {
	Query   string              `json:"query" example:"admni"`
	Results []FuzzySearchResult `json:"results"`
	Total   int                 `json:"total" example:"5"`
	Options FuzzySearchOptions  `json:"options"`
}

// FuzzySearchResult represents a fuzzy search result
type FuzzySearchResult struct {
	Entity     interface{} `json:"entity"`
	Score      float64     `json:"score" example:"0.85"`
	MatchType  string      `json:"matchType" example:"username"`
	MatchField string      `json:"matchField" example:"username"`
	Confidence string      `json:"confidence" example:"high"`
}

// FuzzySearchOptions provides fuzzy search configuration
type FuzzySearchOptions struct {
	Threshold   float64 `json:"threshold" example:"0.6"`
	Algorithm   string  `json:"algorithm" example:"levenshtein"`
	MaxDistance int     `json:"maxDistance" example:"2"`
}

// SimilaritySearchRequest for similarity search operations
type SimilaritySearchRequest struct {
	EntityType   string  `json:"entityType" validate:"required,oneof=users groups" example:"users"`
	EntityId     string  `json:"entityId" validate:"required" example:"admin"`
	Threshold    float64 `json:"threshold,omitempty" validate:"min=0,max=1" example:"0.5"`
	Limit        int     `json:"limit,omitempty" validate:"min=1,max=50" example:"10"`
	IncludeScore bool    `json:"includeScore,omitempty" example:"true"`
}

// SimilaritySearchResponse provides similarity search results
type SimilaritySearchResponse struct {
	ReferenceEntity interface{}        `json:"referenceEntity"`
	SimilarEntities []SimilarityResult `json:"similarEntities"`
	Total           int                `json:"total" example:"8"`
	Options         SimilarityOptions  `json:"options"`
}

// SimilarityResult represents a similarity search result
type SimilarityResult struct {
	Entity     interface{}            `json:"entity"`
	Score      float64                `json:"score" example:"0.75"`
	Reasons    []string               `json:"reasons"`
	Attributes map[string]interface{} `json:"attributes"`
}

// SimilarityOptions provides similarity search configuration
type SimilarityOptions struct {
	Threshold float64            `json:"threshold" example:"0.5"`
	Algorithm string             `json:"algorithm" example:"cosine"`
	Weights   map[string]float64 `json:"weights"`
	Features  []string           `json:"features"`
}

// =================== GEO SEARCH ===================

// GeoSearchRequest for geographic search operations
type GeoSearchRequest struct {
	Latitude   float64 `json:"latitude" validate:"required,min=-90,max=90" example:"21.0285"`
	Longitude  float64 `json:"longitude" validate:"required,min=-180,max=180" example:"105.8542"`
	Radius     float64 `json:"radius" validate:"required,min=0" example:"50.0"`
	Unit       string  `json:"unit,omitempty" validate:"omitempty,oneof=km mi" example:"km"`
	EntityType string  `json:"entityType" validate:"required,oneof=users groups connections" example:"users"`
	Limit      int     `json:"limit,omitempty" validate:"min=1,max=100" example:"20"`
}

// GeoSearchResponse provides geographic search results
type GeoSearchResponse struct {
	Center      GeoPoint       `json:"center"`
	Radius      float64        `json:"radius" example:"50.0"`
	Unit        string         `json:"unit" example:"km"`
	Results     []GeoResult    `json:"results"`
	Total       int            `json:"total" example:"15"`
	BoundingBox GeoBoundingBox `json:"boundingBox"`
}

// GeoPoint represents a geographic coordinate
type GeoPoint struct {
	Latitude  float64 `json:"latitude" example:"21.0285"`
	Longitude float64 `json:"longitude" example:"105.8542"`
}

// GeoResult represents a geographic search result
type GeoResult struct {
	Entity   interface{} `json:"entity"`
	Location GeoPoint    `json:"location"`
	Distance float64     `json:"distance" example:"12.5"`
	Address  string      `json:"address,omitempty" example:"Hanoi, Vietnam"`
}

// GeoBoundingBox represents a geographic bounding box
type GeoBoundingBox struct {
	NorthEast GeoPoint `json:"northEast"`
	SouthWest GeoPoint `json:"southWest"`
}

// =================== SEARCH OPTIMIZATION ===================

// SearchIndexRequest for building search indexes
type SearchIndexRequest struct {
	EntityType string   `json:"entityType" validate:"required,oneof=users groups" example:"users"`
	Fields     []string `json:"fields,omitempty" example:"[\"username\",\"email\",\"groupName\"]"`
	Rebuild    bool     `json:"rebuild,omitempty" example:"false"`
}

// SearchIndexResponse provides index build results
type SearchIndexResponse struct {
	EntityType     string    `json:"entityType" example:"users"`
	Status         string    `json:"status" example:"completed"`
	RecordsIndexed int       `json:"recordsIndexed" example:"1500"`
	Duration       string    `json:"duration" example:"2.5s"`
	IndexSize      string    `json:"indexSize" example:"2.3MB"`
	CreatedAt      time.Time `json:"createdAt" example:"2024-01-15T14:30:22Z"`
}

// SearchPerformanceRequest for performance analysis
type SearchPerformanceRequest struct {
	Period     string     `json:"period" validate:"required,oneof=hour day week month" example:"day"`
	StartDate  *time.Time `json:"startDate,omitempty" example:"2024-01-01T00:00:00Z"`
	EndDate    *time.Time `json:"endDate,omitempty" example:"2024-01-31T23:59:59Z"`
	EntityType string     `json:"entityType,omitempty" validate:"omitempty,oneof=users groups" example:"users"`
}

// SearchPerformanceResponse provides performance metrics
type SearchPerformanceResponse struct {
	Period              string                 `json:"period" example:"day"`
	AverageResponseTime string                 `json:"averageResponseTime" example:"145ms"`
	MedianResponseTime  string                 `json:"medianResponseTime" example:"120ms"`
	P95ResponseTime     string                 `json:"p95ResponseTime" example:"250ms"`
	TotalQueries        int                    `json:"totalQueries" example:"1250"`
	SlowQueries         int                    `json:"slowQueries" example:"25"`
	CacheHitRate        float64                `json:"cacheHitRate" example:"0.85"`
	IndexUsage          map[string]interface{} `json:"indexUsage"`
	Recommendations     []string               `json:"recommendations"`
}

// =================== VALIDATION MESSAGES ===================

func (r AdvancedUserSearchRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"AuthMethod.oneof":   "Auth method must be either 'ldap' or 'local'",
		"Role.oneof":         "Role must be either 'Admin' or 'User'",
		"ExpiringInDays.min": "Expiring in days must be at least 0",
		"ExpiringInDays.max": "Expiring in days cannot exceed 365",
		"Page.min":           "Page must be at least 1",
		"Limit.min":          "Limit must be at least 1",
		"Limit.max":          "Limit cannot exceed 1000",
		"SortBy.oneof":       "Sort by must be one of: username, email, authMethod, role, groupName, userExpiration",
		"SortOrder.oneof":    "Sort order must be either 'asc' or 'desc'",
	}
}

func (r AdvancedGroupSearchRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"AuthMethod.oneof":   "Auth method must be either 'ldap' or 'local'",
		"Role.oneof":         "Role must be either 'Admin' or 'User'",
		"MinMemberCount.min": "Minimum member count must be at least 0",
		"MaxMemberCount.min": "Maximum member count must be at least 0",
		"Page.min":           "Page must be at least 1",
		"Limit.min":          "Limit must be at least 1",
		"Limit.max":          "Limit cannot exceed 500",
		"SortBy.oneof":       "Sort by must be one of: groupName, authMethod, role, memberCount, createdAt",
		"SortOrder.oneof":    "Sort order must be either 'asc' or 'desc'",
	}
}

func (r SavedSearchRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Name.required":       "Search name is required",
		"Name.min":            "Search name must be at least 3 characters",
		"Name.max":            "Search name cannot exceed 50 characters",
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
		"Limit.max":           "Limit cannot exceed 20",
	}
}

// =================== HELPER FUNCTIONS ===================

// NewAdvancedUserSearchRequest creates a new user search request with defaults
func NewAdvancedUserSearchRequest() *AdvancedUserSearchRequest {
	return &AdvancedUserSearchRequest{
		Page:      1,
		Limit:     25,
		SortBy:    "username",
		SortOrder: "asc",
	}
}

// NewAdvancedGroupSearchRequest creates a new group search request with defaults
func NewAdvancedGroupSearchRequest() *AdvancedGroupSearchRequest {
	return &AdvancedGroupSearchRequest{
		Page:               1,
		Limit:              25,
		SortBy:             "groupName",
		SortOrder:          "asc",
		IncludeMemberCount: true,
	}
}

// NewSearchSuggestionsRequest creates a new search suggestions request with defaults
func NewSearchSuggestionsRequest(searchType, query string) *SearchSuggestionsRequest {
	return &SearchSuggestionsRequest{
		SearchType: searchType,
		Query:      query,
		Limit:      10,
	}
}

// IsValidSortField checks if a sort field is valid for the given entity type
func IsValidSortField(entityType, field string) bool {
	validFields := map[string][]string{
		"users":  {"username", "email", "authMethod", "role", "groupName", "userExpiration"},
		"groups": {"groupName", "authMethod", "role", "memberCount", "createdAt"},
	}

	if fields, exists := validFields[entityType]; exists {
		for _, validField := range fields {
			if field == validField {
				return true
			}
		}
	}
	return false
}

// IsValidSearchType checks if a search type is valid
func IsValidSearchType(searchType string) bool {
	validTypes := []string{"users", "groups", "all"}
	for _, validType := range validTypes {
		if searchType == validType {
			return true
		}
	}
	return false
}
