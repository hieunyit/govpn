package repositories

import (
	"context"
	"govpn/internal/domain/entities"
)

type ConfigRepository interface {
	GetServerInfo(ctx context.Context) (*entities.ServerInfo, error)
	GetNetworkConfig(ctx context.Context) (*entities.NetworkConfig, error)
	GetAllConfig(ctx context.Context) (map[string]string, error)
}
