package mem

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"go_oauth2_server/internal/identity"
	"go_oauth2_server/internal/random"
)

const (
	defaultLimit = 50
)

type Store struct {
	mu              sync.RWMutex
	humans          map[string]identity.Human
	agents          map[string]identity.Agent
	emailIndex      map[string]string
	agentLabelIndex map[string]string
	agentsByClient  map[string]map[string]struct{}
}

func New() *Store {
	return &Store{
		humans:          make(map[string]identity.Human),
		agents:          make(map[string]identity.Agent),
		emailIndex:      make(map[string]string),
		agentLabelIndex: make(map[string]string),
		agentsByClient:  make(map[string]map[string]struct{}),
	}
}

func (s *Store) CreateHuman(ctx context.Context, input identity.Human) (identity.Human, error) {
	if err := ctx.Err(); err != nil {
		return identity.Human{}, err
	}
	emailKey := normalizeEmail(input.Email)
	if emailKey == "" {
		return identity.Human{}, fmt.Errorf("email required")
	}
	displayEmail := strings.TrimSpace(input.Email)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.emailIndex[emailKey]; exists {
		return identity.Human{}, identity.ErrHumanEmailExists
	}
	if input.ID == "" {
		input.ID = random.NewID()
	}
	input.CreatedAt = time.Now().UTC()
	input.Email = displayEmail
	if len(input.Attributes) > 0 {
		input.Attributes = copyStringMap(input.Attributes)
	}
	s.humans[input.ID] = input
	s.emailIndex[emailKey] = input.ID
	return input, nil
}

func (s *Store) GetHuman(ctx context.Context, id string) (identity.Human, bool) {
	if err := ctx.Err(); err != nil {
		return identity.Human{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.humans[id]
	return h, ok
}

func (s *Store) GetHumanByEmail(ctx context.Context, email string) (identity.Human, bool) {
	if err := ctx.Err(); err != nil {
		return identity.Human{}, false
	}
	key := normalizeEmail(email)
	if key == "" {
		return identity.Human{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if id, ok := s.emailIndex[key]; ok {
		if human, exists := s.humans[id]; exists {
			return human, true
		}
	}
	return identity.Human{}, false
}

func (s *Store) ListHumans(ctx context.Context, limit, offset int) ([]identity.Human, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, identity.ErrInvalidPagination
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]identity.Human, 0, len(s.humans))
	for _, h := range s.humans {
		list = append(list, h)
	}
	slices.SortFunc(list, func(a, b identity.Human) int {
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		if b.CreatedAt.Before(a.CreatedAt) {
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	if offset >= len(list) {
		return []identity.Human{}, nil
	}
	end := offset + limit
	if end > len(list) {
		end = len(list)
	}
	result := make([]identity.Human, end-offset)
	copy(result, list[offset:end])
	return result, nil
}

func (s *Store) DeleteHuman(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.humans[id]
	if !ok {
		return identity.ErrHumanNotFound
	}
	delete(s.humans, id)
	delete(s.emailIndex, normalizeEmail(h.Email))
	return nil
}

func (s *Store) CreateAgent(ctx context.Context, input identity.Agent) (identity.Agent, error) {
	if err := ctx.Err(); err != nil {
		return identity.Agent{}, err
	}
	rawLabel := strings.TrimSpace(input.AgentID)
	labelKey := normalizeLabel(rawLabel)
	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" {
		return identity.Agent{}, fmt.Errorf("client_id required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if labelKey != "" {
		idxKey := labelIndexKey(clientID, labelKey)
		if _, exists := s.agentLabelIndex[idxKey]; exists {
			return identity.Agent{}, identity.ErrAgentLabelExists
		}
	}
	if input.ID == "" {
		input.ID = random.NewID()
	}
	input.AgentID = rawLabel
	input.ClientID = clientID
	input.CreatedAt = time.Now().UTC()
	if len(input.Capabilities) > 0 {
		input.Capabilities = slices.Clone(input.Capabilities)
	}
	if len(input.Metadata) > 0 {
		input.Metadata = copyStringMap(input.Metadata)
	}
	s.agents[input.ID] = input
	if labelKey != "" {
		s.agentLabelIndex[labelIndexKey(clientID, labelKey)] = input.ID
	}
	if _, ok := s.agentsByClient[clientID]; !ok {
		s.agentsByClient[clientID] = make(map[string]struct{})
	}
	s.agentsByClient[clientID][input.ID] = struct{}{}
	return input, nil
}

func (s *Store) GetAgent(ctx context.Context, id string) (identity.Agent, bool) {
	if err := ctx.Err(); err != nil {
		return identity.Agent{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, ok := s.agents[id]
	return agent, ok
}

func (s *Store) GetAgentByLabel(ctx context.Context, clientID, agentLabel string) (identity.Agent, bool) {
	if err := ctx.Err(); err != nil {
		return identity.Agent{}, false
	}
	clientID = strings.TrimSpace(clientID)
	label := normalizeLabel(agentLabel)
	if clientID == "" || label == "" {
		return identity.Agent{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if id, ok := s.agentLabelIndex[labelIndexKey(clientID, label)]; ok {
		if agent, exists := s.agents[id]; exists {
			return agent, true
		}
	}
	return identity.Agent{}, false
}

func (s *Store) ListAgents(ctx context.Context, limit, offset int) ([]identity.Agent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, identity.ErrInvalidPagination
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]identity.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		list = append(list, a)
	}
	slices.SortFunc(list, func(a, b identity.Agent) int {
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		if b.CreatedAt.Before(a.CreatedAt) {
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	if offset >= len(list) {
		return []identity.Agent{}, nil
	}
	end := offset + limit
	if end > len(list) {
		end = len(list)
	}
	result := make([]identity.Agent, end-offset)
	copy(result, list[offset:end])
	return result, nil
}

func (s *Store) DeleteAgent(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agents[id]
	if !ok {
		return identity.ErrAgentNotFound
	}
	delete(s.agents, id)
	if agent.AgentID != "" {
		delete(s.agentLabelIndex, labelIndexKey(agent.ClientID, normalizeLabel(agent.AgentID)))
	}
	if byClient, ok := s.agentsByClient[agent.ClientID]; ok {
		delete(byClient, agent.ID)
		if len(byClient) == 0 {
			delete(s.agentsByClient, agent.ClientID)
		}
	}
	return nil
}

func (s *Store) ListAgentsByClient(ctx context.Context, clientID string) ([]identity.Agent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.agentsByClient[clientID]
	if len(ids) == 0 {
		return nil, nil
	}
	result := make([]identity.Agent, 0, len(ids))
	for id := range ids {
		if agent, ok := s.agents[id]; ok {
			result = append(result, agent)
		}
	}
	slices.SortFunc(result, func(a, b identity.Agent) int {
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		if b.CreatedAt.Before(a.CreatedAt) {
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	return result, nil
}

func copyStringMap(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func normalizeLabel(label string) string {
	return strings.ToLower(strings.TrimSpace(label))
}

func labelIndexKey(clientID, label string) string {
	if clientID == "" || label == "" {
		return ""
	}
	return clientID + "|" + label
}
