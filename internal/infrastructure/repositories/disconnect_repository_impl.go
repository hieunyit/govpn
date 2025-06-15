// internal/infrastructure/repositories/disconnect_repository_impl.go
package repositories

import (
	"context"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/xmlrpc"
)

type disconnectRepositoryImpl struct {
	disconnectClient *xmlrpc.DisconnectClient
}

func NewDisconnectRepository(xmlrpcClient *xmlrpc.Client) repositories.DisconnectRepository {
	return &disconnectRepositoryImpl{
		disconnectClient: xmlrpc.NewDisconnectClient(xmlrpcClient),
	}
}

func (r *disconnectRepositoryImpl) DisconnectUser(ctx context.Context, username, message string) error {
	return r.disconnectClient.DisconnectSingleUser(username, message)
}

func (r *disconnectRepositoryImpl) DisconnectUsers(ctx context.Context, usernames []string, message string) error {
	return r.disconnectClient.DisconnectUsers(usernames, message)
}
