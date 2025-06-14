package usecases

import (
	"context"
	"govpn/internal/domain/entities"
)

type GroupUsecase interface {
	// CRUD operations
	CreateGroup(ctx context.Context, group *entities.Group) error
	GetGroup(ctx context.Context, groupName string) (*entities.Group, error)
	UpdateGroup(ctx context.Context, group *entities.Group) error
	DeleteGroup(ctx context.Context, groupName string) error
	ListGroups(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, error)
	ListGroupsWithCount(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, int, error)
	ListGroupsWithTotal(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, int, error)
	// Group operations
	EnableGroup(ctx context.Context, groupName string) error
	DisableGroup(ctx context.Context, groupName string) error
}
