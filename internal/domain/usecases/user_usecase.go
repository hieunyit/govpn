package usecases

import (
	"context"
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
)

type UserUsecase interface {
	// CRUD operations
	CreateUser(ctx context.Context, user *entities.User) error
	GetUser(ctx context.Context, username string) (*entities.User, error)
	UpdateUser(ctx context.Context, user *entities.User) error
	DeleteUser(ctx context.Context, username string) error
	ListUsers(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, error)
	ListUsersWithCount(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, int, error)
	ListUsersWithTotal(ctx context.Context, filter *entities.UserFilter) ([]*entities.User, int, error)
	// User operations
	EnableUser(ctx context.Context, username string) error
	DisableUser(ctx context.Context, username string) error
	ChangePassword(ctx context.Context, username, password string) error
	RegenerateTOTP(ctx context.Context, username string) error

	// Expiration operations
	GetExpiringUsers(ctx context.Context, days int) ([]string, error)
	GetUserExpirations(ctx context.Context, days int) (*dto.UserExpirationsResponse, error)
}
