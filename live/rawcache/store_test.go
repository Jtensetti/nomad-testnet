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

// A cache that refuses every new stream once it is full is bounded and unfair:
// the operator that fills it stops every other operator's work from being
// admitted at all. That is the state PROD-20 names, one layer above the relay
// queue, and it is the more binding of the two -- work refused here never
// reaches the queue to be scheduled fairly.
func TestAFloodingSenderCannotTakeAnotherSendersStreamShare(t *testing.T) {
	const maxStreams = 16
	store, err := OpenShared(t.TempDir(), maxStreams, []uint16{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	share := store.PerSource()
	if share != maxStreams/4 {
		t.Fatalf("share is %d, expected %d", share, maxStreams/4)
	}

	put := func(sender uint16, seed byte) error {
		var stream hop.StreamID
		stream[0], stream[1] = byte(sender), seed
		metadata, err := hop.WorkMetadata(stream, 0, 2)
		if err != nil {
			return err
		}
		metadata.Sender = sender
		var payload [hop.CiphertextSize]byte
		payload[0] = seed
		_, err = store.Put(metadata, payload)
		return err
	}

	// The flood arrives first and asks for four times the whole cache.
	floodAccepted := 0
	for seed := 0; seed < maxStreams*4; seed++ {
		if err := put(2, byte(seed)); err == nil {
			floodAccepted++
		} else if !errors.Is(err, ErrSourceShareFull) {
			t.Fatalf("flood stream %d: %v", seed, err)
		}
	}
	if floodAccepted != share {
		t.Fatalf("the flooding sender introduced %d streams, its share is %d",
			floodAccepted, share)
	}

	// Every other sender still has all of its own room.
	for _, quiet := range []uint16{1, 3, 4} {
		for seed := 0; seed < share; seed++ {
			if err := put(quiet, byte(seed)); err != nil {
				t.Errorf("sender %d was refused its own stream %d after a flood: %v",
					quiet, seed, err)
			}
		}
	}
	t.Logf("MEASURED: a sender asking for %d streams got %d, its exact share; the other "+
		"three senders each kept all %d of theirs", maxStreams*4, floodAccepted, share)
}

// The share must survive a restart, or a flood starts again from zero every
// time the node is restarted -- and a node under attack restarts often.
func TestTheSenderShareSurvivesReopening(t *testing.T) {
	root := t.TempDir()
	const maxStreams = 8
	// Distinct stream IDs on every call, so a second run asks for genuinely
	// new streams rather than re-offering ones the cache already holds.
	fill := func(store *Store, sender uint16, offset, seeds int) int {
		accepted := 0
		for seed := 0; seed < seeds; seed++ {
			var stream hop.StreamID
			stream[0], stream[1], stream[2] = byte(sender), byte(offset), byte(seed+1)
			metadata, err := hop.WorkMetadata(stream, 0, 2)
			if err != nil {
				t.Fatal(err)
			}
			metadata.Sender = sender
			var payload [hop.CiphertextSize]byte
			payload[0], payload[1] = byte(offset), byte(seed)
			if _, err := store.Put(metadata, payload); err == nil {
				accepted++
			}
		}
		return accepted
	}

	first, err := OpenShared(root, maxStreams, []uint16{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	share := first.PerSource()
	if got := fill(first, 2, 0, share*4); got != share {
		t.Fatalf("first run accepted %d of a share of %d", got, share)
	}

	second, err := OpenShared(root, maxStreams, []uint16{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := fill(second, 2, 1, share*4); got != 0 {
		t.Fatalf("a restart gave the same sender %d more streams", got)
	}
	if got := fill(second, 1, 1, share); got != share {
		t.Errorf("the other sender kept only %d of its %d streams across a restart",
			got, share)
	}
}

// A sender outside the signed set has no share and cannot make one.
func TestAnUnknownSenderGetsNoStreamShare(t *testing.T) {
	store, err := OpenShared(t.TempDir(), 8, []uint16{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	var stream hop.StreamID
	stream[0] = 9
	metadata, err := hop.WorkMetadata(stream, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Sender = 9
	var payload [hop.CiphertextSize]byte
	if _, err := store.Put(metadata, payload); !errors.Is(err, ErrSourceShareFull) {
		t.Fatalf("a sender outside the signed set was given cache space: %v", err)
	}
}

func TestASenderShareSmallerThanOneStreamIsRefused(t *testing.T) {
	if _, err := OpenShared(t.TempDir(), 3, []uint16{1, 2, 3, 4}); err == nil {
		t.Fatal("a stream limit smaller than the sender set was accepted")
	}
	if _, err := OpenShared(t.TempDir(), 8, nil); err == nil {
		t.Fatal("a shared cache with no senders was accepted")
	}
}

// A store opened without a sender set keeps the behaviour the read-side users
// rely on, and a test says so rather than leaving it to be discovered.
func TestAnUnsharedCacheKeepsOnlyTheTotalBound(t *testing.T) {
	store, err := Open(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if store.PerSource() != 0 {
		t.Fatalf("an unshared cache reports a per-sender share of %d", store.PerSource())
	}
	accepted := 0
	for seed := 0; seed < 16; seed++ {
		var stream hop.StreamID
		stream[0] = byte(seed + 1)
		metadata, err := hop.WorkMetadata(stream, 0, 2)
		if err != nil {
			t.Fatal(err)
		}
		metadata.Sender = 7
		var payload [hop.CiphertextSize]byte
		payload[0] = byte(seed)
		if _, err := store.Put(metadata, payload); err == nil {
			accepted++
		}
	}
	if accepted != 4 {
		t.Fatalf("an unshared cache admitted %d streams against a limit of 4", accepted)
	}
}
