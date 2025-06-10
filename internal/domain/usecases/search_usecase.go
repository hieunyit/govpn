package usecases

import (
	"context"
	"govpn/internal/application/dto"
)

// SearchUsecase defines advanced search operations for users and groups
type SearchUsecase interface {
	// =================== ADVANCED SEARCH ===================

	// AdvancedUserSearch performs complex search on users with multiple filters
	// Supports text search, date ranges, status filters, sorting, and pagination
	AdvancedUserSearch(ctx context.Context, req *dto.AdvancedUserSearchRequest) (*dto.AdvancedUserSearchResponse, error)

	// AdvancedGroupSearch performs complex search on groups with multiple filters
	// Supports text search, member count filters, status filters, sorting, and pagination
	AdvancedGroupSearch(ctx context.Context, req *dto.AdvancedGroupSearchRequest) (*dto.AdvancedGroupSearchResponse, error)

	// =================== SAVED SEARCHES ===================

	// SaveSearch saves frequently used search criteria for reuse
	// Associates search with user and supports public/private searches
	SaveSearch(ctx context.Context, req *dto.SavedSearchRequest, username string) (*dto.SavedSearchResponse, error)

	// GetSavedSearches retrieves saved searches for a user
	// Can filter by search type and include public searches
	GetSavedSearches(ctx context.Context, username string, searchType string, includePublic bool) ([]dto.SavedSearchResponse, error)

	// ExecuteSavedSearch executes a previously saved search
	// Applies current pagination parameters to saved criteria
	ExecuteSavedSearch(ctx context.Context, searchId string, username string, page int, limit int) (interface{}, error)

	// UpdateSavedSearch updates an existing saved search
	UpdateSavedSearch(ctx context.Context, searchId string, req *dto.SavedSearchRequest, username string) (*dto.SavedSearchResponse, error)

	// DeleteSavedSearch removes a saved search
	// Only owner or admin can delete
	DeleteSavedSearch(ctx context.Context, searchId string, username string) error

	// =================== SEARCH SUGGESTIONS ===================

	// GetSearchSuggestions provides autocomplete suggestions for search fields
	// Returns matching values based on partial input
	GetSearchSuggestions(ctx context.Context, req *dto.SearchSuggestionsRequest) (*dto.SearchSuggestionsResponse, error)

	// GetPopularSearchTerms returns frequently used search terms
	// Helps users discover common search patterns
	GetPopularSearchTerms(ctx context.Context, searchType string, limit int) ([]string, error)

	// =================== QUICK SEARCH ===================

	// QuickSearch performs fast text search across multiple entity types
	// Returns combined results from users and groups
	QuickSearch(ctx context.Context, query string, searchType string, limit int) (map[string]interface{}, error)

	// GlobalSearch searches across all entities and returns categorized results
	// Provides unified search experience
	GlobalSearch(ctx context.Context, query string, limit int) (map[string]interface{}, error)

	// =================== SEARCH ANALYTICS ===================

	// GetSearchAnalytics returns analytics about search usage and patterns
	// Includes popular searches, performance metrics, and user behavior
	GetSearchAnalytics(ctx context.Context, username string, period string) (map[string]interface{}, error)

	// TrackSearchUsage records search usage for analytics
	// Called internally when searches are performed
	TrackSearchUsage(ctx context.Context, username string, searchType string, query interface{}, resultCount int, duration int64)

	// GetSearchStatistics returns system-wide search statistics
	// Provides insights for administrators
	GetSearchStatistics(ctx context.Context, period string) (map[string]interface{}, error)

	// =================== EXPORT FUNCTIONALITY ===================

	// ExportSearchResults exports search results to various formats
	// Supports CSV, XLSX, and JSON formats
	ExportSearchResults(ctx context.Context, req *dto.AdvancedUserSearchRequest, format string) (filename string, content []byte, error error)

	// ExportGroupSearchResults exports group search results
	ExportGroupSearchResults(ctx context.Context, req *dto.AdvancedGroupSearchRequest, format string) (filename string, content []byte, error error)

	// =================== SEARCH OPTIMIZATION ===================

	// BuildSearchIndex builds or rebuilds search indexes for better performance
	// Should be called when data changes significantly
	BuildSearchIndex(ctx context.Context, entityType string) error

	// OptimizeSearchPerformance analyzes and optimizes search performance
	// Returns recommendations for improving search speed
	OptimizeSearchPerformance(ctx context.Context) (map[string]interface{}, error)

	// ValidateSearchCriteria validates search request parameters
	// Returns detailed validation errors and suggestions
	ValidateSearchCriteria(req interface{}) (bool, []string, error)

	// =================== SEARCH FILTERS ===================

	// GetAvailableFilters returns available filter options for search
	// Helps build dynamic search UI
	GetAvailableFilters(ctx context.Context, entityType string) (map[string]interface{}, error)

	// GetFilterValues returns possible values for specific filter fields
	// Supports autocomplete for filter values
	GetFilterValues(ctx context.Context, entityType string, fieldName string) ([]string, error)

	// =================== SEARCH HISTORY ===================

	// GetSearchHistory returns search history for a user
	// Helps users repeat previous searches
	GetSearchHistory(ctx context.Context, username string, limit int) ([]interface{}, error)

	// ClearSearchHistory clears search history for a user
	ClearSearchHistory(ctx context.Context, username string) error

	// =================== ADVANCED FEATURES ===================

	// SimilaritySearch finds entities similar to a given entity
	// Uses various similarity algorithms
	SimilaritySearch(ctx context.Context, entityType string, entityId string, limit int) ([]interface{}, error)

	// FuzzySearch performs fuzzy matching for typo-tolerant search
	// Helpful when exact matches are not found
	FuzzySearch(ctx context.Context, query string, entityType string, limit int) ([]interface{}, error)

	// GeoSearch performs location-based search if location data is available
	// Searches based on IP ranges or geographic criteria
	GeoSearch(ctx context.Context, req interface{}) (interface{}, error)
}
