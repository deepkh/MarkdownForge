package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

const DefaultAllowedOrigin = "https://localdraft.ai"

type securityFile struct {
	Version        int      `json:"version"`
	AllowedOrigins []string `json:"allowedOrigins"`
}

type SecurityStore struct {
	mu    sync.Mutex
	paths Paths
}

func NewSecurityStore(paths Paths) *SecurityStore {
	return &SecurityStore{paths: paths}
}

func NormalizeHTTPSOrigin(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", errors.New("an exact HTTPS origin is required")
	}
	if parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", errors.New("origin must contain only an HTTPS scheme, host, and optional port")
	}
	if strings.Contains(parsed.Hostname(), "*") || parsed.Hostname() == "" {
		return "", errors.New("wildcard origins are not supported")
	}
	if parsed.Port() != "" {
		if _, err := url.ParseRequestURI("https://example.invalid:" + parsed.Port()); err != nil {
			return "", errors.New("origin port is invalid")
		}
	}
	hostname := strings.ToLower(parsed.Hostname())
	if strings.IndexFunc(hostname, func(value rune) bool { return value > 127 }) >= 0 {
		return "", errors.New("origin hostname must use its ASCII form")
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port := parsed.Port(); port != "" && port != "443" {
		host = net.JoinHostPort(hostname, port)
	}
	return "https://" + host, nil
}

func (s *SecurityStore) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *SecurityStore) Add(origin string) ([]string, error) {
	normalized, err := NormalizeHTTPSOrigin(origin)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	origins, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	for _, existing := range origins {
		if existing == normalized {
			return origins, nil
		}
	}
	origins = append(origins, normalized)
	sort.Strings(origins)
	return origins, s.writeLocked(origins)
}

func (s *SecurityStore) Remove(origin string) ([]string, bool, error) {
	normalized, err := NormalizeHTTPSOrigin(origin)
	if err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	origins, err := s.loadLocked()
	if err != nil {
		return nil, false, err
	}
	next := make([]string, 0, len(origins))
	removed := false
	for _, existing := range origins {
		if existing == normalized {
			removed = true
			continue
		}
		next = append(next, existing)
	}
	if !removed {
		return origins, false, nil
	}
	return next, true, s.writeLocked(next)
}

func (s *SecurityStore) loadLocked() ([]string, error) {
	file, err := os.Open(s.paths.SecurityFile)
	if errors.Is(err, os.ErrNotExist) {
		defaults := []string{DefaultAllowedOrigin}
		if err := s.writeLocked(defaults); err != nil {
			return nil, err
		}
		return defaults, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var stored securityFile
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("read bridge settings: %w", err)
	}
	if stored.Version != 1 {
		return nil, errors.New("unsupported bridge settings version")
	}
	seen := make(map[string]bool)
	origins := make([]string, 0, len(stored.AllowedOrigins))
	for _, value := range stored.AllowedOrigins {
		normalized, err := NormalizeHTTPSOrigin(value)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed origin: %w", err)
		}
		if !seen[normalized] {
			seen[normalized] = true
			origins = append(origins, normalized)
		}
	}
	sort.Strings(origins)
	return origins, nil
}

func (s *SecurityStore) writeLocked(origins []string) error {
	return writeRestrictedJSON(s.paths.Directory, s.paths.SecurityFile, ".bridge-settings-*.tmp", securityFile{
		Version: 1, AllowedOrigins: origins,
	})
}

func writeRestrictedJSON(directory, target, pattern string, value any) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil && !errors.Is(err, os.ErrPermission) {
		return err
	}
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	temporary, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, target); err != nil {
		return err
	}
	return os.Chmod(target, 0o600)
}
