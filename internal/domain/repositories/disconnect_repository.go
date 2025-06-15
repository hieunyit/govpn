package repositories

import (
	"context"
)

type DisconnectRepository interface {
	DisconnectUser(ctx context.Context, username, message string) error
	DisconnectUsers(ctx context.Context, usernames []string, message string) error
}
