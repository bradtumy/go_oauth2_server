package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"go_oauth2_server/internal/store"
	sqlstore "go_oauth2_server/internal/store/sqlite"
)

func main() {
	var (
		dbPath = flag.String("db", os.Getenv("AS_CLIENTS_DB"), "sqlite db path")
		dir    = flag.String("dir", "clients", "directory containing client json files")
	)
	flag.Parse()

	if *dbPath == "" {
		log.Fatal("db path required")
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		log.Fatalf("ensure db dir: %v", err)
	}

	clientStore, err := sqlstore.NewClientStore(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		log.Fatalf("read dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(*dir, entry.Name())
		if err := seedFile(context.Background(), clientStore, path); err != nil {
			log.Fatalf("seed %s: %v", path, err)
		}
	}
}

func seedFile(ctx context.Context, clientStore store.ClientStore, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	var input store.ClientInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	normalized, err := store.ValidateClientInput(input)
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	client := store.Client{
		ID:           normalized.ClientID,
		Type:         normalized.ClientType,
		Secret:       normalized.ClientSecret,
		RedirectURIs: normalized.RedirectURIs,
		GrantTypes:   normalized.GrantTypes,
		Scopes:       normalized.Scopes,
		Audiences:    normalized.Audiences,
	}
	_, err = clientStore.CreateClient(ctx, client)
	if err != nil {
		if err == store.ErrClientExists {
			log.Printf("client %s already exists, skipping", client.ID)
			return nil
		}
		return err
	}
	log.Printf("seeded client: %s", client.ID)
	return nil
}
