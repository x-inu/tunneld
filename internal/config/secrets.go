package config

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// secretsDoc is the on-disk secrets.yaml shape:
//
//	secrets:
//	  mikrotik1-password: "..."
//	  mikrotik1-psk: "..."
type secretsDoc struct {
	Secrets map[string]string `yaml:"secrets"`
}

// SecretStore is a concurrency-safe, server-side credential store. Secret
// values are never serialized into API responses.
type SecretStore struct {
	mu     sync.RWMutex
	path   string
	values map[string]string
}

// LoadSecrets reads secrets.yaml and enforces mode 0600. A missing file is
// treated as an empty store so a fresh installation can start and ask the
// administrator to fill credentials; save creates it with 0600.
func LoadSecrets(path string) (*SecretStore, []string, error) {
	s := &SecretStore{path: path, values: map[string]string{}}
	var warnings []string
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, []string{fmt.Sprintf("credential store %s does not exist yet; connections will fail until credentials are saved", path)}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("credential store %s must not be a symlink", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, nil, fmt.Errorf("credential store %s has mode %o and could not be restricted to 0600: %w", path, info.Mode().Perm(), err)
		}
		warnings = append(warnings, fmt.Sprintf("credential store %s had insecure permissions; changed to 0600", path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc secretsDoc
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("parse credential store: %w", err)
	}
	if doc.Secrets != nil {
		s.values = doc.Secrets
	}
	return s, warnings, nil
}

func (s *SecretStore) Path() string { return s.path }

func (s *SecretStore) Get(ref string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.values[ref]
	return v, ok
}

// Has reports whether a non-empty credential exists for ref.
func (s *SecretStore) Has(ref string) bool {
	v, ok := s.Get(ref)
	return ok && v != ""
}

func (s *SecretStore) Set(ref, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[ref] = value
	return s.saveLocked()
}

// SetMany applies all non-nil changes in one atomic write. A nil value keeps
// the existing secret untouched; an empty string deletes the secret.
func (s *SecretStore) SetMany(changes map[string]*string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ref, val := range changes {
		if val == nil {
			continue
		}
		if *val == "" {
			delete(s.values, ref)
		} else {
			s.values[ref] = *val
		}
	}
	return s.saveLocked()
}

func (s *SecretStore) DeleteRefs(refs ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ref := range refs {
		delete(s.values, ref)
	}
	return s.saveLocked()
}

// Snapshot returns a copy of all secret values. It is only used by the log
// redactor and must never be exposed by an HTTP handler.
func (s *SecretStore) Snapshot() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.values))
	for _, v := range s.values {
		if v != "" {
			out = append(out, v)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

func (s *SecretStore) RefCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.values)
}

func (s *SecretStore) saveLocked() error {
	doc := secretsDoc{Secrets: s.values}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	header := []byte("# tunneld credential store. Keep this file mode 0600.\n" +
		"# Values here are never returned by the dashboard or written to logs.\n")
	return WriteFileAtomic(s.path, append(header, out...), 0o600)
}
