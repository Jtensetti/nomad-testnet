package committee

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// A threshold share is the operator's half of the committee key. LoadShare
// carries the file checks that stop one being read from a world-readable path,
// a symlink or something that is not a file at all, and none of them had a
// test: LoadShare was at zero coverage across the repository, so deleting a
// check broke nothing.
//
// The checks run before any content verification, so these drive them with
// bytes that would fail verification anyway. What is asserted is which
// refusal came back.

func writeShare(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "share.json")
	if err := os.WriteFile(path, []byte(`{"version":"placeholder"}`), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the umask, so the mode is set explicitly: a test that
	// meant to write 0644 and got 0600 would pass for the wrong reason.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadShare(t *testing.T, path string) error {
	t.Helper()
	_, err := LoadShare(path, Verified{}, topology.Verified{})
	return err
}

func TestAThresholdShareIsRefusedWhenOthersCanReadIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the permission check is not applied on Windows, which uses its ACL model")
	}
	for name, mode := range map[string]os.FileMode{
		"group readable": 0o640,
		"world readable": 0o604,
		"world writable": 0o602,
	} {
		err := loadShare(t, writeShare(t, mode))
		if err == nil {
			t.Fatalf("a %s threshold share was accepted", name)
		}
		if !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("a %s share was refused for %q rather than its permissions", name, err)
		}
	}

	// 0600 and 0400 must both reach content verification, which is where this
	// placeholder fails. A permission refusal here would mean the check is an
	// equality rather than a mask, and 0400 is how a mounted secret arrives.
	for _, mode := range []os.FileMode{0o600, 0o400} {
		err := loadShare(t, writeShare(t, mode))
		if err != nil && strings.Contains(err.Error(), "permissions") {
			t.Fatalf("mode %o was refused on its permissions: %v", mode, err)
		}
	}
}

func TestAThresholdShareMustBeABoundedRegularFile(t *testing.T) {
	err := loadShare(t, t.TempDir())
	if err == nil {
		t.Fatal("a directory was accepted as a threshold share")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("a directory was refused for %q rather than for not being a regular file", err)
	}

	// A FIFO is the case the check exists for: not a directory, so a read does
	// not refuse it -- it blocks, or returns whatever a writer supplies, which
	// is a threshold share an attacker chooses the contents of.
	pipe := filepath.Join(t.TempDir(), "share.json")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("FIFOs are unavailable here: %v", err)
	}
	if err := loadShare(t, pipe); err == nil {
		t.Fatal("a FIFO was accepted as a threshold share")
	} else if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("a FIFO was refused for %q rather than for not being a regular file", err)
	}

	// An empty file is refused before it can decode to a zero-valued share.
	empty := filepath.Join(t.TempDir(), "share.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadShare(t, empty); err == nil {
		t.Fatal("an empty threshold share file was accepted")
	} else if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("an empty share was refused for %q rather than on its size", err)
	}
}

// Following a symlink would let anything that can write the directory point
// the loader at a file whose permissions it does not control.
func TestASymlinkToAThresholdShareIsNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the permission check is not applied on Windows, which uses its ACL model")
	}
	target := writeShare(t, 0o600)
	link := filepath.Join(filepath.Dir(target), "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable here: %v", err)
	}
	err := loadShare(t, link)
	if err == nil {
		t.Fatal("a symlink to a threshold share was followed")
	}
	if !strings.Contains(err.Error(), "permissions") && !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("a symlink was refused for %q rather than on its own mode", err)
	}
}
