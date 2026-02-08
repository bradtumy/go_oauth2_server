package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go_oauth2_server/internal/store"
)

type ClientStore struct {
	path string
}

func NewClientStore(path string) (*ClientStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("client db path required")
	}
	store := &ClientStore{path: path}
	if err := store.init(context.Background()); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *ClientStore) init(ctx context.Context) error {
	schema := `CREATE TABLE IF NOT EXISTS clients (
client_id TEXT PRIMARY KEY,
client_type TEXT NOT NULL,
client_secret TEXT,
redirect_uris TEXT NOT NULL,
grant_types TEXT NOT NULL,
scopes TEXT NOT NULL,
audiences TEXT,
created_at TEXT NOT NULL,
updated_at TEXT NOT NULL
);`
	_, err := s.exec(ctx, schema)
	if err != nil {
		return fmt.Errorf("init schema: %w", err)
	}
	return nil
}

func (s *ClientStore) CreateClient(ctx context.Context, client store.Client) (store.Client, error) {
	now := time.Now().UTC()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = now
	}
	client.UpdatedAt = now
	payload, err := encodeClient(client)
	if err != nil {
		return store.Client{}, err
	}
	sql := fmt.Sprintf(
		"INSERT INTO clients (client_id, client_type, client_secret, redirect_uris, grant_types, scopes, audiences, created_at, updated_at) VALUES ('%s','%s','%s','%s','%s','%s','%s','%s','%s');",
		sqlQuote(client.ID),
		sqlQuote(client.Type),
		sqlQuote(client.Secret),
		sqlQuote(payload.redirectURIs),
		sqlQuote(payload.grantTypes),
		sqlQuote(payload.scopes),
		sqlQuote(payload.audiences),
		sqlQuote(client.CreatedAt.Format(time.RFC3339Nano)),
		sqlQuote(client.UpdatedAt.Format(time.RFC3339Nano)),
	)
	_, err = s.exec(ctx, sql)
	if err != nil {
		if isConstraintError(err) {
			return store.Client{}, store.ErrClientExists
		}
		return store.Client{}, fmt.Errorf("insert client: %w", err)
	}
	return client, nil
}

func (s *ClientStore) GetClient(ctx context.Context, id string) (store.Client, bool, error) {
	sql := fmt.Sprintf("SELECT client_id, client_type, client_secret, redirect_uris, grant_types, scopes, audiences, created_at, updated_at FROM clients WHERE client_id = '%s';", sqlQuote(id))
	clients, err := s.queryClients(ctx, sql)
	if err != nil {
		return store.Client{}, false, err
	}
	if len(clients) == 0 {
		return store.Client{}, false, nil
	}
	return clients[0], true, nil
}

func (s *ClientStore) ListClients(ctx context.Context) ([]store.Client, error) {
	sql := "SELECT client_id, client_type, client_secret, redirect_uris, grant_types, scopes, audiences, created_at, updated_at FROM clients ORDER BY client_id;"
	return s.queryClients(ctx, sql)
}

func (s *ClientStore) UpdateClient(ctx context.Context, client store.Client) (store.Client, error) {
	_, ok, err := s.GetClient(ctx, client.ID)
	if err != nil {
		return store.Client{}, err
	}
	if !ok {
		return store.Client{}, store.ErrClientNotFound
	}
	client.UpdatedAt = time.Now().UTC()
	payload, err := encodeClient(client)
	if err != nil {
		return store.Client{}, err
	}
	sql := fmt.Sprintf(
		"UPDATE clients SET client_type='%s', client_secret='%s', redirect_uris='%s', grant_types='%s', scopes='%s', audiences='%s', updated_at='%s' WHERE client_id = '%s';",
		sqlQuote(client.Type),
		sqlQuote(client.Secret),
		sqlQuote(payload.redirectURIs),
		sqlQuote(payload.grantTypes),
		sqlQuote(payload.scopes),
		sqlQuote(payload.audiences),
		sqlQuote(client.UpdatedAt.Format(time.RFC3339Nano)),
		sqlQuote(client.ID),
	)
	_, err = s.exec(ctx, sql)
	if err != nil {
		return store.Client{}, fmt.Errorf("update client: %w", err)
	}
	return client, nil
}

func (s *ClientStore) DeleteClient(ctx context.Context, id string) error {
	_, ok, err := s.GetClient(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrClientNotFound
	}
	sql := fmt.Sprintf("DELETE FROM clients WHERE client_id = '%s';", sqlQuote(id))
	_, err = s.exec(ctx, sql)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	return nil
}

type clientPayload struct {
	redirectURIs string
	grantTypes   string
	scopes       string
	audiences    string
}

func encodeClient(client store.Client) (clientPayload, error) {
	redirectURIs, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return clientPayload{}, fmt.Errorf("encode redirect_uris: %w", err)
	}
	grantTypes, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return clientPayload{}, fmt.Errorf("encode grant_types: %w", err)
	}
	scopes, err := json.Marshal(client.Scopes)
	if err != nil {
		return clientPayload{}, fmt.Errorf("encode scopes: %w", err)
	}
	audiences, err := json.Marshal(client.Audiences)
	if err != nil {
		return clientPayload{}, fmt.Errorf("encode audiences: %w", err)
	}
	return clientPayload{
		redirectURIs: string(redirectURIs),
		grantTypes:   string(grantTypes),
		scopes:       string(scopes),
		audiences:    string(audiences),
	}, nil
}

func (s *ClientStore) queryClients(ctx context.Context, sql string) ([]store.Client, error) {
	output, err := s.execJSON(ctx, sql)
	if err != nil {
		return nil, err
	}
	if len(output) == 0 {
		return nil, nil
	}
	var rows []map[string]any
	if err := json.Unmarshal(output, &rows); err != nil {
		return nil, fmt.Errorf("decode rows: %w", err)
	}
	clients := make([]store.Client, 0, len(rows))
	for _, row := range rows {
		client, err := decodeRow(row)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, nil
}

func decodeRow(row map[string]any) (store.Client, error) {
	client := store.Client{
		ID:   asString(row["client_id"]),
		Type: asString(row["client_type"]),
	}
	client.Secret = asString(row["client_secret"])
	if err := json.Unmarshal([]byte(asString(row["redirect_uris"])), &client.RedirectURIs); err != nil {
		return store.Client{}, fmt.Errorf("decode redirect_uris: %w", err)
	}
	if err := json.Unmarshal([]byte(asString(row["grant_types"])), &client.GrantTypes); err != nil {
		return store.Client{}, fmt.Errorf("decode grant_types: %w", err)
	}
	if err := json.Unmarshal([]byte(asString(row["scopes"])), &client.Scopes); err != nil {
		return store.Client{}, fmt.Errorf("decode scopes: %w", err)
	}
	audiencesRaw := asString(row["audiences"])
	if audiencesRaw != "" {
		if err := json.Unmarshal([]byte(audiencesRaw), &client.Audiences); err != nil {
			return store.Client{}, fmt.Errorf("decode audiences: %w", err)
		}
	}
	var err error
	client.CreatedAt, err = time.Parse(time.RFC3339Nano, asString(row["created_at"]))
	if err != nil {
		return store.Client{}, fmt.Errorf("parse created_at: %w", err)
	}
	client.UpdatedAt, err = time.Parse(time.RFC3339Nano, asString(row["updated_at"]))
	if err != nil {
		return store.Client{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return client, nil
}

func (s *ClientStore) exec(ctx context.Context, sql string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sqlite3", s.path, sql)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("sqlite3 exec: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (s *ClientStore) execJSON(ctx context.Context, sql string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sqlite3", "-json", s.path, sql)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("sqlite3 query: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func sqlQuote(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func asString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func isConstraintError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
