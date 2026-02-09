package mem

import (
	"context"
	"sync"
	"time"

	"tokenator/internal/store"
)

type ClientStore struct {
	mu      sync.Mutex
	clients map[string]store.Client
}

func NewClientStore() *ClientStore {
	return &ClientStore{
		clients: make(map[string]store.Client),
	}
}

func (s *ClientStore) CreateClient(_ context.Context, client store.Client) (store.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.ID]; exists {
		return store.Client{}, store.ErrClientExists
	}
	now := time.Now().UTC()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = now
	}
	client.UpdatedAt = now
	s.clients[client.ID] = client
	return client, nil
}

func (s *ClientStore) GetClient(_ context.Context, id string) (store.Client, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.clients[id]
	return client, ok, nil
}

func (s *ClientStore) ListClients(_ context.Context) ([]store.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clients := make([]store.Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	return clients, nil
}

func (s *ClientStore) UpdateClient(_ context.Context, client store.Client) (store.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.ID]; !exists {
		return store.Client{}, store.ErrClientNotFound
	}
	client.UpdatedAt = time.Now().UTC()
	s.clients[client.ID] = client
	return client, nil
}

func (s *ClientStore) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[id]; !exists {
		return store.ErrClientNotFound
	}
	delete(s.clients, id)
	return nil
}
