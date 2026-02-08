package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// KeyMeta tracks metadata about a signing key.
type KeyMeta struct {
	Source  string
	ModTime time.Time
}

// KeySet represents a collection of RSA keys with an active key.
type KeySet struct {
	ActiveKeyID string
	PrivateKeys map[string]*rsa.PrivateKey
	PublicKeys  map[string]*rsa.PublicKey
	Meta        map[string]KeyMeta
}

// LoadKeySetFromPEM loads a single key from PEM.
func LoadKeySetFromPEM(keyPEM []byte, keyID string) (*KeySet, error) {
	if len(keyPEM) == 0 {
		return nil, errors.New("missing signing key")
	}
	privateKey, err := parseRSAPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	if strings.TrimSpace(keyID) == "" {
		keyID = "default"
	}
	return &KeySet{
		ActiveKeyID: keyID,
		PrivateKeys: map[string]*rsa.PrivateKey{keyID: privateKey},
		PublicKeys:  map[string]*rsa.PublicKey{keyID: &privateKey.PublicKey},
		Meta:        map[string]KeyMeta{keyID: {Source: "pem"}},
	}, nil
}

// LoadKeySetFromDir loads all PEM keys from a directory.
func LoadKeySetFromDir(dir string, activeKeyID string) (*KeySet, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("signing key directory required")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read signing key dir: %w", err)
	}
	privateKeys := map[string]*rsa.PrivateKey{}
	publicKeys := map[string]*rsa.PublicKey{}
	meta := map[string]KeyMeta{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".pem" && ext != ".key" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ext)
		if strings.TrimSpace(name) == "" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read signing key %s: %w", entry.Name(), err)
		}
		privateKey, err := parseRSAPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse signing key %s: %w", entry.Name(), err)
		}
		privateKeys[name] = privateKey
		publicKeys[name] = &privateKey.PublicKey
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat signing key %s: %w", entry.Name(), err)
		}
		meta[name] = KeyMeta{Source: path, ModTime: info.ModTime()}
	}
	if len(privateKeys) == 0 {
		return nil, errors.New("no signing keys found in directory")
	}
	activeKeyID = strings.TrimSpace(activeKeyID)
	if activeKeyID == "" {
		activeKeyID = newestKey(meta)
	}
	if _, ok := privateKeys[activeKeyID]; !ok {
		return nil, fmt.Errorf("active signing key %q not found", activeKeyID)
	}
	return &KeySet{
		ActiveKeyID: activeKeyID,
		PrivateKeys: privateKeys,
		PublicKeys:  publicKeys,
		Meta:        meta,
	}, nil
}

func newestKey(meta map[string]KeyMeta) string {
	if len(meta) == 0 {
		return ""
	}
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return meta[keys[i]].ModTime.After(meta[keys[j]].ModTime)
	})
	return keys[0]
}
