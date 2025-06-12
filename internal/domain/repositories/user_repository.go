package repositories

import (
	"context"
	"govpn/internal/domain/entities"
)

type UserRepository interface {
	// CRUD operations
	Create(ctx context.Context, user *entities.User) error
	GetByUsername(ctx context.Context, username string) (*entities.User, error)
	Update(ctx context.Context, user *entities.User) error
	UserPropDel(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, username string) error
	List(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, error)

	// Existence checks
	ExistsByUsername(ctx context.Context, username string) (bool, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)

	// User operations
	Enable(ctx context.Context, username string) error
	Disable(ctx context.Context, username string) error
	SetPassword(ctx context.Context, username, password string) error
	RegenerateTOTP(ctx context.Context, username string) error

	// Expiration operations
	GetExpiringUsers(ctx context.Context, days int) ([]string, error)
}
