package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// SaveFile atomically replaces the file at path with data: the payload is
// written to a temp file in the same directory, fsynced, then renamed over
// the target. A crash mid-write therefore never damages the previous vault.
// The file is created with 0600 permissions.
func SaveFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".keytray-*")
	if err != nil {
		return fmt.Errorf("vault: create temp file: %w", err)
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			f.Close()
			os.Remove(tmp)
		}
	}()

	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("vault: chmod temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("vault: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("vault: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("vault: close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("vault: rename: %w", err)
	}
	keep = true

	// Make the rename itself durable.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// LoadFile reads the vault file; a missing file yields ErrNotFound.
func LoadFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}
