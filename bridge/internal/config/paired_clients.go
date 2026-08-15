package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type PublicKeyJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type PairedClient struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Origin     string       `json:"origin"`
	PublicKey  PublicKeyJWK `json:"publicKey"`
	CreatedAt  time.Time    `json:"createdAt"`
	LastUsedAt time.Time    `json:"lastUsedAt"`
}

type pairedClientsFile struct {
	Version int            `json:"version"`
	Clients []PairedClient `json:"clients"`
}

type PairedClientStore struct {
	mu    sync.Mutex
	paths Paths
}

func NewPairedClientStore(paths Paths) *PairedClientStore {
	return &PairedClientStore{paths: paths}
}

func (s *PairedClientStore) List() ([]PairedClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *PairedClientStore) Get(id, origin string) (PairedClient, bool, error) {
	normalized, err := NormalizeHTTPSOrigin(origin)
	if err != nil {
		return PairedClient{}, false, err
	}
	clients, err := s.List()
	if err != nil {
		return PairedClient{}, false, err
	}
	for _, client := range clients {
		if client.ID == id && client.Origin == normalized {
			return client, true, nil
		}
	}
	return PairedClient{}, false, nil
}

func (s *PairedClientStore) Upsert(client PairedClient) (PairedClient, error) {
	client.ID = strings.TrimSpace(client.ID)
	client.Name = strings.TrimSpace(client.Name)
	if client.ID == "" || len(client.ID) > 200 || client.Name == "" || len(client.Name) > 200 {
		return PairedClient{}, errors.New("client id and name are required")
	}
	normalized, err := NormalizeHTTPSOrigin(client.Origin)
	if err != nil {
		return PairedClient{}, err
	}
	client.Origin = normalized
	if client.PublicKey.Kty != "EC" || client.PublicKey.Crv != "P-256" || client.PublicKey.X == "" || client.PublicKey.Y == "" {
		return PairedClient{}, errors.New("an ECDSA P-256 public key is required")
	}
	now := time.Now().UTC()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = now
	}
	if client.LastUsedAt.IsZero() {
		client.LastUsedAt = now
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clients, err := s.loadLocked()
	if err != nil {
		return PairedClient{}, err
	}
	found := false
	for index := range clients {
		if clients[index].ID == client.ID && clients[index].Origin == client.Origin {
			client.CreatedAt = clients[index].CreatedAt
			clients[index] = client
			found = true
			break
		}
	}
	if !found {
		clients = append(clients, client)
	}
	return client, s.writeLocked(clients)
}

func (s *PairedClientStore) Touch(id, origin string) error {
	normalized, err := NormalizeHTTPSOrigin(origin)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clients, err := s.loadLocked()
	if err != nil {
		return err
	}
	for index := range clients {
		if clients[index].ID == id && clients[index].Origin == normalized {
			clients[index].LastUsedAt = time.Now().UTC()
			return s.writeLocked(clients)
		}
	}
	return errors.New("paired client was not found")
}

func (s *PairedClientStore) Remove(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clients, err := s.loadLocked()
	if err != nil {
		return false, err
	}
	next := make([]PairedClient, 0, len(clients))
	removed := false
	for _, client := range clients {
		if client.ID == id {
			removed = true
			continue
		}
		next = append(next, client)
	}
	if !removed {
		return false, nil
	}
	return true, s.writeLocked(next)
}

func (s *PairedClientStore) loadLocked() ([]PairedClient, error) {
	file, err := os.Open(s.paths.PairedClientsFile)
	if errors.Is(err, os.ErrNotExist) {
		return []PairedClient{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var stored pairedClientsFile
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("read paired clients: %w", err)
	}
	if stored.Version != 1 {
		return nil, errors.New("unsupported paired clients version")
	}
	for index := range stored.Clients {
		normalized, err := NormalizeHTTPSOrigin(stored.Clients[index].Origin)
		if err != nil {
			return nil, fmt.Errorf("invalid paired client origin: %w", err)
		}
		stored.Clients[index].Origin = normalized
	}
	sort.Slice(stored.Clients, func(left, right int) bool {
		return stored.Clients[left].CreatedAt.Before(stored.Clients[right].CreatedAt)
	})
	return stored.Clients, nil
}

func (s *PairedClientStore) writeLocked(clients []PairedClient) error {
	return writeRestrictedJSON(s.paths.Directory, s.paths.PairedClientsFile, ".paired-clients-*.tmp", pairedClientsFile{
		Version: 1, Clients: clients,
	})
}
