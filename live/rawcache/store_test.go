package rawcache

import (
	"errors"
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
