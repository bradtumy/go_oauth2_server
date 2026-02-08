package store

import "context"

type ClientStore interface {
	CreateClient(ctx context.Context, client Client) (Client, error)
	GetClient(ctx context.Context, id string) (Client, bool, error)
	ListClients(ctx context.Context) ([]Client, error)
	UpdateClient(ctx context.Context, client Client) (Client, error)
	DeleteClient(ctx context.Context, id string) error
}
