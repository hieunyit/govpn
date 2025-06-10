package usecases

import (
	"context"
	"govpn/internal/domain/entities"
)

type AuthUsecase interface {
	Login(ctx context.Context, credentials *entities.LoginCredentials) (*entities.AuthTokens, error)
	RefreshToken(ctx context.Context, request *entities.RefreshTokenRequest) (*entities.AuthTokens, error)
	ValidateToken(ctx context.Context, token string) (*entities.AuthUser, error)
}
