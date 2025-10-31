package identity

import (
	"context"
	"errors"
	"time"
)

var (
	ErrHumanNotFound     = errors.New("human not found")
	ErrAgentNotFound     = errors.New("agent not found")
	ErrHumanEmailExists  = errors.New("human email already exists")
	ErrAgentLabelExists  = errors.New("agent label already exists for client")
	ErrInvalidPagination = errors.New("invalid pagination parameters")
)

type Human struct {
	ID         string            `json:"id"`
	Email      string            `json:"email"`
	Name       string            `json:"name"`
	TenantID   string            `json:"tenant_id"`
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

type Agent struct {
	ID            string            `json:"id"`
	AgentID       string            `json:"agent_id"`
	Name          string            `json:"name"`
	ClientID      string            `json:"client_id"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	DPoPPublicJWK string            `json:"dpop_public_jwk,omitempty"`
	PolicyID      string            `json:"policy_id,omitempty"`
	TenantID      string            `json:"tenant_id"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
}

type Store interface {
	CreateHuman(ctx context.Context, input Human) (Human, error)
	GetHuman(ctx context.Context, id string) (Human, bool)
	GetHumanByEmail(ctx context.Context, email string) (Human, bool)
	ListHumans(ctx context.Context, limit, offset int) ([]Human, error)
	DeleteHuman(ctx context.Context, id string) error

	CreateAgent(ctx context.Context, input Agent) (Agent, error)
	GetAgent(ctx context.Context, id string) (Agent, bool)
	GetAgentByLabel(ctx context.Context, clientID, agentLabel string) (Agent, bool)
	ListAgents(ctx context.Context, limit, offset int) ([]Agent, error)
	DeleteAgent(ctx context.Context, id string) error
	ListAgentsByClient(ctx context.Context, clientID string) ([]Agent, error)
}
