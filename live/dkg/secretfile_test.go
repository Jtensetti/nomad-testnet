package dkgnet

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// A threshold share is the single most sensitive file this system writes: one
// share plus t-1 others reconstructs the committee key. Its confidentiality
// rests entirely on the mode bits, because it sits in plaintext on the
// operator's disk.
//
// Both halves were implemented and neither was tested. That combination is how
// the WAN campaign shipped a node-secrets file at 0644: `curl -o` respects the
// umask and nobody had asserted otherwise, so the node correctly refused to
// start and the run captured nothing. The write side there had no test either.

func TestASecretIsWrittenUnreadableByAnyoneElse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not the access-control model on Windows")
	}
	path := filepath.Join(t.TempDir(), "share.json")
	if err := writeNew(path, []byte(`{"share":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions&0o077 != 0 {
		t.Fatalf("the share was written %04o, readable or writable by group or other", permissions)
	}
}

// The umask is the part that actually bites. It can only clear bits, so a
// permissive one cannot widen 0600 -- but that is a property worth asserting
// rather than reasoning about, because the failure mode is silent and the file
// is a threshold share.
func TestAPermissiveUmaskCannotWidenASecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not the access-control model on Windows")
	}
	previous := syscall.Umask(0)
	defer syscall.Umask(previous)

	path := filepath.Join(t.TempDir(), "share.json")
	if err := writeNew(path, []byte(`{"share":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("under umask 0 the share was written %04o, want 0600", permissions)
	}
}

// A share must never be silently replaced: overwriting one is how an operator
// loses the only copy of their contribution to a committee, and O_EXCL is what
// stops it.
func TestASecretIsNeverSilentlyOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "share.json")
	if err := writeNew(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(path, []byte("second"), 0o600); err == nil {
		t.Fatal("an existing share was overwritten")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "first" {
		t.Fatalf("the original share was modified: %q", content)
	}
}

// A failed write must leave nothing behind. A partially written share that
// later loads is worse than no share at all.
func TestAFailedSecretWriteLeavesNoFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "missing-parent", "share.json")
	if err := writeNew(path, []byte("secret"), 0o600); err == nil {
		t.Fatal("a write into a missing directory reported success")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a failed write left something behind: %v", err)
	}
}
