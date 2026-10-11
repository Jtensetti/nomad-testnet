package hop

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
)

func TestAuthenticatedHeaderPreservesCiphertextAndRejectsTamper(t *testing.T) {
	var payload [CiphertextSize]byte
	for index := range payload {
		payload[index] = byte(index) ^ byte(index>>8)
	}
	stream, err := StreamFor([][CiphertextSize]byte{payload, payload})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := WorkMetadata(stream, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	cell, err := FromCiphertext(payload, metadata)
	if err != nil {
		t.Fatal(err)
	}
	original := Ciphertext(cell)
	key := [32]byte{1, 2, 3}
	context := Context{NetworkID: "test-network", Epoch: 7, Receiver: 1, TopologyDigest: [32]byte{9}}
	if err := Seal(&cell, metadata, 0, 42, key, context); err != nil {
		t.Fatal(err)
	}
	// The sealed cell is not the plaintext cell. If it were, the payload
	// would be readable on the wire, which is the whole point of version 2.
	if Ciphertext(cell) == original {
		t.Fatal("Seal left the payload in the clear")
	}
	sealed := cell

	opened := sealed
	verified, err := Open(&opened, 0, key, context)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Sequence != 42 || verified.Stream != stream || Ciphertext(opened) != original ||
		len(opened) != fabric.CellSize {
		t.Fatal("authenticated hop changed ciphertext or metadata")
	}

	tampered := sealed
	tampered[31] ^= 1
	if _, err := Open(&tampered, 0, key, context); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	// A refused cell must come back untouched, so that a caller ignoring the
	// error holds ciphertext rather than half-decrypted plaintext.
	expectedTamper := sealed
	expectedTamper[31] ^= 1
	if tampered != expectedTamper {
		t.Fatal("a cell that failed authentication was decrypted anyway")
	}

	wrongReceiver := context
	wrongReceiver.Receiver = 2
	other := sealed
	if _, err := Open(&other, 0, key, wrongReceiver); err == nil {
		t.Fatal("cell was accepted for a different receiver")
	}
}

func TestReplayWindowAllowsReorderingButRejectsDuplicates(t *testing.T) {
	window := &ReplayWindow{}
	for _, sequence := range []uint32{100, 102, 101, 99} {
		if err := window.Accept(sequence); err != nil {
			t.Fatalf("sequence %d: %v", sequence, err)
		}
	}
	if err := window.Accept(101); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate: got %v", err)
	}
	if err := window.Accept(1); !errors.Is(err, ErrReplay) {
		t.Fatalf("expired sequence: got %v", err)
	}
}

func TestFileSequenceNeverReusesReservedRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sequence")
	first, err := OpenFileSequence(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := first.Next()
	if err != nil || value != 1 {
		t.Fatalf("first value=%d err=%v", value, err)
	}
	second, err := OpenFileSequence(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := second.Next()
	if err != nil {
		t.Fatal(err)
	}
	if restarted <= sequenceReservation {
		t.Fatalf("restart reused reserved range: %d", restarted)
	}
}
