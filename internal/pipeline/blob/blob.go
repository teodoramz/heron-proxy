// Package blob stores oversized request bodies as content-addressed files.
package blob

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotFound reports a key with no stored content.
var ErrNotFound = errors.New("blob: not found")

// Store is a content-addressed file store rooted at a directory. Identical
// content yields the same key and is stored once.
type Store struct {
	dir string
}

// New returns a Store rooted at dir.
func New(dir string) *Store { return &Store{dir: dir} }

// Key returns the storage key for content without writing it.
func Key(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Put writes content and returns its key.
func (s *Store) Put(data []byte) (string, error) {
	key := Key(data)
	path := s.path(key)
	if _, err := os.Stat(path); err == nil {
		return key, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("blob: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("blob: temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", fmt.Errorf("blob: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("blob: close: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("blob: commit: %w", err)
	}
	return key, nil
}

// Get returns stored content by key.
func (s *Store) Get(key string) ([]byte, error) {
	if !validKey(key) {
		return nil, fmt.Errorf("blob: invalid key %q", key)
	}
	data, err := os.ReadFile(s.path(key))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("blob: read: %w", err)
	}
	return data, nil
}

// Delete removes stored content. A missing key is not an error.
func (s *Store) Delete(key string) error {
	if !validKey(key) {
		return fmt.Errorf("blob: invalid key %q", key)
	}
	if err := os.Remove(s.path(key)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("blob: delete: %w", err)
	}
	return nil
}

// path shards on the first two key bytes to keep directories small.
func (s *Store) path(key string) string {
	return filepath.Join(s.dir, key[0:2], key[2:4], key)
}

func validKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}
