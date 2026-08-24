package rawcache

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/hop"
)

func TestImmutableBoundedCacheCompletesCommittedStream(t *testing.T) {
	store, err := Open(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	payloads := make([][hop.CiphertextSize]byte, 2)
	payloads[0][0] = 1
	payloads[1][0] = 2
	stream, err := hop.StreamFor(payloads)
	if err != nil {
		t.Fatal(err)
	}
	for ordinal, payload := range payloads {
		metadata, _ := hop.WorkMetadata(stream, uint16(ordinal), 2)
		created, err := store.Put(metadata, payload)
		if err != nil || !created {
			t.Fatalf("put %d created=%v err=%v", ordinal, created, err)
		}
	}
	loaded, complete, err := store.Load(stream)
	if err != nil || !complete || loaded[0] != payloads[0] || loaded[1] != payloads[1] {
		t.Fatalf("complete=%v err=%v", complete, err)
	}
	metadata, _ := hop.WorkMetadata(stream, 0, 2)
	created, err := store.Put(metadata, payloads[0])
	if err != nil || created {
		t.Fatalf("idempotent put created=%v err=%v", created, err)
	}
	conflict := payloads[0]
	conflict[3] ^= 1
	if _, err := store.Put(metadata, conflict); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("conflicting coordinate: %v", err)
	}

	otherPayloads := make([][hop.CiphertextSize]byte, 2)
	otherPayloads[0][0] = 3
	otherPayloads[1][0] = 4
	otherStream, _ := hop.StreamFor(otherPayloads)
	otherMetadata, _ := hop.WorkMetadata(otherStream, 0, 2)
	if _, err := store.Put(otherMetadata, otherPayloads[0]); !errors.Is(err, ErrCacheFull) {
		t.Fatalf("bounded cache: %v", err)
	}
}

// Load re-derives the stream commitment from the bytes it actually read, so a
// cache directory altered outside Put -- filesystem access, a restored
// backup, a corrupted disk -- cannot feed uncommitted ciphertext to the
// materializer. Put's equivocation check cannot cover this: it only sees
// writes that go through it.
func TestLoadRejectsCacheContentThatIsNotTheCommittedStream(t *testing.T) {
	root := t.TempDir()
	store, err := Open(root, 4)
	if err != nil {
		t.Fatal(err)
	}
	payloads := make([][hop.CiphertextSize]byte, 2)
	payloads[0][0] = 11
	payloads[1][0] = 22
	stream, err := hop.StreamFor(payloads)
	if err != nil {
		t.Fatal(err)
	}
	for ordinal, payload := range payloads {
		metadata, err := hop.WorkMetadata(stream, uint16(ordinal), 2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Put(metadata, payload); err != nil {
			t.Fatal(err)
		}
	}
	if _, complete, err := store.Load(stream); err != nil || !complete {
		t.Fatalf("committed stream did not load: complete=%v err=%v", complete, err)
	}

	// Rewrite one cell behind the store's back, keeping the length valid.
	cellPath := filepath.Join(root, hex.EncodeToString(stream[:]), "00001.cell")
	tampered := payloads[1]
	tampered[0] ^= 0xFF
	if err := os.Chmod(cellPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cellPath, tampered[:], 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(root, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, complete, err := reopened.Load(stream); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("tampered cache accepted: complete=%v err=%v", complete, err)
	}
}
