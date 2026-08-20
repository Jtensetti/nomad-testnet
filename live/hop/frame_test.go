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
	verified, err := Verify(cell, 0, key, context)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Sequence != 42 || verified.Stream != stream || Ciphertext(cell) != original || len(cell) != fabric.CellSize {
		t.Fatal("authenticated hop changed ciphertext or metadata")
	}
	tampered := cell
	tampered[31] ^= 1
	if _, err := Verify(tampered, 0, key, context); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	wrongReceiver := context
	wrongReceiver.Receiver = 2
	if _, err := Verify(cell, 0, key, wrongReceiver); err == nil {
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
