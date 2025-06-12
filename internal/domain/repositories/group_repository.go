package repositories

import (
	"context"
	"govpn/internal/domain/entities"
)

type GroupRepository interface {
	// CRUD operations
	Create(ctx context.Context, group *entities.Group) error
	GetByName(ctx context.Context, groupName string) (*entities.Group, error)
	Update(ctx context.Context, group *entities.Group) error
	GroupPropDel(ctx context.Context, group *entities.Group) error
	Delete(ctx context.Context, groupName string) error
	List(ctx context.Context, filter *entities.GroupFilter) ([]*entities.Group, error)

	// Existence checks
	ExistsByName(ctx context.Context, groupName string) (bool, error)

	// Group operations
	Enable(ctx context.Context, groupName string) error
	Disable(ctx context.Context, groupName string) error
	ClearAccessControl(ctx context.Context, group *entities.Group) error
}
