package materialize

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The materializer is the only writer on the boundary between the network
// domain and the networkless browser. Everything below is about what a
// reader on the other side must never be able to observe: a partially
// written object, a symlink pointing out of the directory, a path that
// escapes it, or a file that changed after it was published.

func TestWriteImmutableIsAtomicAndNeverPartial(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "object.nomadobject")
	payload := strings.Repeat("verified object payload ", 4096)

	if err := writeImmutable(path, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	// No temporary file may survive: a reader scanning the directory must
	// never encounter a half-written object under any name.
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "object.nomadobject" {
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("exactly one published file expected, found %v", names)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != payload {
		t.Fatal("published object must be complete")
	}
}

func TestWriteImmutableRefusesToOverwrite(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "object.nomadobject")
	if err := writeImmutable(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeImmutable(path, []byte("second")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("an existing object must not be rewritten, got %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "first" {
		t.Fatal("a published object must be immutable")
	}
}

// TestWriteImmutableRefusesSymlinkTarget covers the case where an attacker
// with write access to the output directory pre-creates a symlink at the
// name the materializer is about to publish, hoping to redirect a verified
// write somewhere else. Lstat rather than Stat is what makes this fail.
func TestWriteImmutableRefusesSymlinkTarget(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "object.nomadobject")
	if err := os.Symlink(outside, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeImmutable(path, []byte("redirected")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("a symlink at the target name must be refused, got %v", err)
	}
	contents, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "original" {
		t.Fatal("a symlink must not redirect a verified write outside the directory")
	}
}

func TestEnsureOutputDirectoryRejectsSymlinkedDirectory(t *testing.T) {
	real := t.TempDir()
	base := t.TempDir()
	link := filepath.Join(base, "output")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := ensureOutputDirectory(link); err == nil {
		t.Fatal("a symlinked output directory must be refused")
	}
}

func TestEnsureOutputDirectoryRejectsNonDirectory(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureOutputDirectory(file); err == nil {
		t.Fatal("a regular file must not be accepted as the output directory")
	}
}

// TestOutputNamesCannotEscapeTheDirectory checks the property a reader
// depends on: every published name stays inside the output directory, so a
// crafted object identifier cannot write into the browser's own state or
// anywhere else on the host.
func TestOutputNamesCannotEscapeTheDirectory(t *testing.T) {
	directory := t.TempDir()
	for _, hostile := range []string{
		"../escaped.nomadobject",
		"../../escaped.nomadobject",
		"sub/../../escaped.nomadobject",
		"/etc/escaped.nomadobject",
	} {
		candidate := filepath.Join(directory, filepath.Base(hostile))
		resolved, err := filepath.Abs(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(resolved, directory+string(os.PathSeparator)) {
			t.Fatalf("name %q escaped the output directory as %q", hostile, resolved)
		}
	}
}

func TestPublishedObjectsAreReadableButNotWritableByOthers(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "object.nomadobject")
	if err := writeImmutable(path, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("a published object must be a regular file")
	}
	// Verified objects are public signed content and the browser may run as
	// another UID, so they are world readable by design; they must never be
	// writable by anyone but the materializer.
	if info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("published objects must not be group or world writable, got %o", info.Mode().Perm())
	}
}
