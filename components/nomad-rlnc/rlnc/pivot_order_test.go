package rlnc

import (
	"bytes"
	"testing"
)

// Pivot columns are not always discovered in order: a random row's entry at
// the next missing column can cancel to zero during reduction, landing its
// pivot later. A following symbol whose pivot lands earlier must still be
// reduced against that later pivot before it joins the basis, or it keeps a
// residue there and the decoder returns wrong bytes while claiming success.
func TestOutOfOrderPivotsDecodeExactly(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	enc, err := NewEncoder(data, 2)
	if err != nil {
		t.Fatal(err)
	}
	if enc.K() != 2 {
		t.Fatalf("want k=2, got %d", enc.K())
	}
	later := enc.encodeWith([]byte{0, 1}) // pivot lands at column 1 first
	mixed := enc.encodeWith([]byte{1, 1}) // pivot at column 0, residue at 1
	got, err := Decode([]Symbol{later, mixed}, enc.K(), enc.OriginalSize())
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("decode returned wrong bytes: got %x want %x", got, data)
	}
}
