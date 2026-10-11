package objectstore

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-browser/internal/demotrust"
)

func writeObject(t *testing.T, directory, name string, envelope Envelope) {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func directoryWith(t *testing.T, documents ...Document) (string, TrustSet, []ed25519.PublicKey) {
	t.Helper()
	directory := t.TempDir()
	keys := make([]ed25519.PublicKey, 0, len(documents))
	raw := make([][]byte, 0, len(documents))
	for index, document := range documents {
		envelope, key := signedEnvelope(t, document)
		writeObject(t, directory, string(rune('a'+index))+Extension, envelope)
		keys = append(keys, key)
		raw = append(raw, key)
	}
	trusted, err := NewTrustSet(raw...)
	if err != nil {
		t.Fatal(err)
	}
	return directory, trusted, keys
}

func TestLoadReturnsVerifiedObjectsSortedByTitle(t *testing.T) {
	second := validDocument()
	second.Title = "Zebra"
	first := validDocument()
	first.Title = "Alfa"

	directory, trusted, _ := directoryWith(t, second, first)
	result, err := Load(directory, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 2 {
		t.Fatalf("loaded %d objects, want 2 (rejected %d)", len(result.Objects), result.Rejected)
	}
	if result.Objects[0].Document.Title != "Alfa" {
		t.Fatalf("objects are not sorted by title: %q first", result.Objects[0].Document.Title)
	}
}

// The invariant that makes a shared cache directory safe: one hostile file
// costs exactly itself. Everything else in the directory still renders.
func TestOneHostileFileDoesNotSuppressTheRest(t *testing.T) {
	good := validDocument()
	good.Title = "Giltig"
	directory, trusted, _ := directoryWith(t, good)

	if err := os.WriteFile(filepath.Join(directory, "z-garbage"+Extension),
		[]byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	tampered, _ := signedEnvelope(t, validDocument())
	tampered.ContentHash = strings.Repeat("00", 32)
	writeObject(t, directory, "y-tampered"+Extension, tampered)

	result, err := Load(directory, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 1 || result.Objects[0].Document.Title != "Giltig" {
		t.Fatalf("the valid object did not survive: %+v", result.Objects)
	}
	if result.Rejected != 2 {
		t.Fatalf("rejected %d files, want 2", result.Rejected)
	}
}

// A rejected object must be counted, not swallowed. A client that renders
// fewer objects than it holds and says nothing looks identical to a client
// that was given fewer objects.
func TestRejectionsAreReportedRatherThanSwallowed(t *testing.T) {
	directory := t.TempDir()
	trusted, err := ParseTrustSet(demotrust.PublisherKey)
	if err != nil {
		t.Fatal(err)
	}
	writeObject(t, directory, "a"+Extension, Envelope{Version: 99})
	result, err := Load(directory, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rejected != 1 {
		t.Fatalf("rejected %d, want 1", result.Rejected)
	}
	if len(result.Objects) != 0 {
		t.Fatalf("loaded %d objects from a directory holding only a bad one", len(result.Objects))
	}
}

// An unreadable directory is not an empty one. Collapsing the two would hide a
// misconfigured cache path behind a client that simply shows nothing.
func TestAMissingDirectoryIsAnErrorNotAnEmptyResult(t *testing.T) {
	trusted, err := ParseTrustSet(demotrust.PublisherKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent"), trusted); err == nil {
		t.Fatal("a missing object directory loaded as an empty one")
	}
}

// Symlinks are skipped from the directory listing itself, so the link target
// is never opened. The target here is a real object under a trusted key: if it
// were followed it would verify and appear, which is what makes this test able
// to fail.
func TestASymlinkIsNotFollowedOutOfTheCache(t *testing.T) {
	linked := validDocument()
	linked.Title = "Utanfor cachen"
	directory, trusted, _ := directoryWith(t, linked)

	result, err := Load(directory, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 1 {
		t.Fatalf("expected the fixture object, got %d", len(result.Objects))
	}
	target := filepath.Join(directory, "a"+Extension)

	elsewhere := t.TempDir()
	if err := os.Symlink(target, filepath.Join(elsewhere, "link"+Extension)); err != nil {
		t.Skipf("symlinks are unavailable here: %v", err)
	}
	linkedResult, err := Load(elsewhere, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if len(linkedResult.Objects) != 0 {
		t.Fatalf("a symlink was followed out of the cache directory: %+v", linkedResult.Objects)
	}
	if linkedResult.Rejected != 0 {
		t.Fatalf("a skipped symlink was counted as a rejected object")
	}
}

// A file past the encoded limit is refused on its size, so an oversize entry
// costs a stat rather than a parse.
func TestAnOversizeFileIsRefused(t *testing.T) {
	directory := t.TempDir()
	trusted, err := ParseTrustSet(demotrust.PublisherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "big"+Extension),
		make([]byte, MaxEncodedEnvelopeBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Load(directory, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rejected != 1 || len(result.Objects) != 0 {
		t.Fatalf("oversize file was not refused: %+v", result)
	}
}

// Two files carrying the same object are one object, because the identity is
// the commitment rather than the filename.
func TestTheSameObjectUnderTwoNamesIsOneObject(t *testing.T) {
	directory := t.TempDir()
	envelope, key := signedEnvelope(t, validDocument())
	writeObject(t, directory, "first"+Extension, envelope)
	writeObject(t, directory, "second"+Extension, envelope)
	result, err := Load(directory, trustOnly(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 1 {
		t.Fatalf("one object under two names loaded as %d", len(result.Objects))
	}
}
