package uplink

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
)

// The padding after the inner ciphertext must be zero, and the check that says
// so defends against the one party that can reach it.
//
// Every other malformation a cell can carry is caught by the AEAD: a forged or
// altered cell fails to authenticate and never gets as far as the padding. The
// only party who can produce a cell that authenticates and whose padding is not
// zero is the publisher holding the session key -- so this check is not about
// an outsider at all. It is what stops a publisher from using the space the
// fixed cell size buys as a side channel to the entry operator it is supposed
// to be anonymous to: fifty-odd bytes per cell, at the publisher's choosing,
// delivered to the one party that also sees its source address.
func TestAPublisherCannotSmuggleBytesInTheReservedPadding(t *testing.T) {
	committee, _, err := mix.GenerateDealerCommittee(mix.CommitteeID{2}, 1, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	context := Context{NetworkID: "padding-test", Epoch: 4, TopologyDigest: [32]byte{9}}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(secret[:], committee.PublicKey, context)
	if err != nil {
		t.Fatal(err)
	}

	// Sealed exactly as the production path seals, except for what goes in the
	// padding. Reaching past SealWork is the point: a publisher that wanted the
	// channel would write its own sealer, and a test that could only produce
	// cells through the honest one would be asserting that the honest one is
	// honest.
	sealWith := func(sequence uint64, padding []byte) fabric.Cell {
		t.Helper()
		var plain mix.PlainCell
		wire, err := mix.EncryptCell(committee.PublicKey, plain)
		if err != nil {
			t.Fatal(err)
		}
		inner := make([]byte, 0, InnerSize+paddingSize)
		inner = append(inner, wire[:InnerSize]...)
		inner = append(inner, padding...)
		aead, err := session.aead()
		if err != nil {
			t.Fatal(err)
		}
		var cell fabric.Cell
		binary.BigEndian.PutUint64(cell[:SequenceSize], sequence)
		copy(cell[SequenceSize:], aead.Seal(nil, session.nonce(sequence), inner, cell[:SequenceSize]))
		return cell
	}

	if paddingSize <= 0 {
		t.Fatal("there is no padding, so the zero check guards nothing")
	}
	smuggled := make([]byte, paddingSize)
	copy(smuggled, "publisher-to-operator")
	if _, _, err := session.Open(sealWith(1, smuggled)); err == nil {
		t.Fatal("a cell carrying data in its reserved padding was accepted")
	} else if got := err.Error(); got != "uplink padding must be zero" {
		t.Fatalf("refused for the wrong reason: %v", got)
	}

	// Vacuity: the same construction with zero padding opens, so what refused
	// the cell above was its padding and not the way it was built.
	if _, _, err := session.Open(sealWith(1, make([]byte, paddingSize))); err != nil {
		t.Fatalf("vacuity arm: an honestly padded cell built the same way was refused: %v", err)
	}

	// One non-zero byte anywhere in the padding is enough. A check that only
	// looked at the first byte, or only at a prefix, would leave the rest of
	// the channel open.
	for _, offset := range []int{0, paddingSize / 2, paddingSize - 1} {
		padding := make([]byte, paddingSize)
		padding[offset] = 1
		if _, _, err := session.Open(sealWith(2, padding)); err == nil {
			t.Fatalf("a single non-zero padding byte at offset %d was accepted", offset)
		}
	}
}
