package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.kt")

	if err := SaveFile(path, []byte("payload-1")); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload-1" {
		t.Errorf("got %q", got)
	}
	assertNoTempFiles(t, dir)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}
}

func TestSaveOverwritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.kt")
	if err := SaveFile(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := SaveFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("got %q, want %q", got, "new")
	}
	assertNoTempFiles(t, dir)
}

// A rename failure (target is a directory) must clean the temp file up and
// leave the error with the caller — this is the crash-safety cleanup path.
func TestSaveFailureCleansTempFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "occupied")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveFile(target, []byte("x")); err == nil {
		t.Fatal("expected rename error")
	}
	assertNoTempFiles(t, dir)
}

func TestLoadFileNotFound(t *testing.T) {
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.kt")); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(dir, ".keytray-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}
