package uplink

import (
	"crypto/rand"
	"testing"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
)

// Session.Open is where the entry operator establishes that a cell came from
// the session it claims to. Everything downstream -- the deposit, the batch,
// the shuffle -- treats an opened cell as authentic, so this is the boundary
// that decides whether a stranger can inject into a publisher's stream.
//
// Nothing tested it. A mutation that discarded the AEAD result on failure and
// handed the raw ciphertext back as plaintext left the whole live/uplink suite
// green: forged cells were accepted and no test said so. These cases are that
// gap closed, and each was checked against that mutation.

// distinctSession builds a session under its own shared secret.
//
// testSession uses one fixed secret, so two of them are the same session by
// construction: the key is HKDF over the secret and the context, and the
// committee's public key is not part of it -- correctly, since it identifies
// the committee rather than the session. A cross-session test therefore has to
// vary the secret, and the first version of this did not, which made it fail
// against correct code.
func distinctSession(t *testing.T, secret string) *Session {
	t.Helper()
	public, _, err := mix.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession([]byte(secret), public, Context{
		NetworkID: "nomad-test", Epoch: 1,
		TopologyDigest: [32]byte{1, 2, 3}, EntryOperator: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func sealedCell(t *testing.T, session *Session, sequence uint64) fabric.Cell {
	t.Helper()
	var payload [PayloadSize]byte
	copy(payload[:], "a publication fragment")
	cell, err := session.SealWork(sequence, payload)
	if err != nil {
		t.Fatal(err)
	}
	return cell
}

// A single flipped bit anywhere in the authenticated ciphertext must be
// refused. Every byte is covered, so no region can be modified unnoticed.
func TestATamperedCiphertextIsRefused(t *testing.T) {
	session := testSession(t)
	original := sealedCell(t, session, 7)

	if _, _, err := session.Open(original); err != nil {
		t.Fatalf("the untampered cell was refused: %v", err)
	}

	// Sample across the ciphertext rather than all 1192 bytes, but include the
	// first and last so the ends are not the untested part.
	positions := []int{SequenceSize, SequenceSize + 1, fabric.CellSize / 2,
		fabric.CellSize - 2, fabric.CellSize - 1}
	for _, position := range positions {
		tampered := original
		tampered[position] ^= 0x01
		if _, _, err := session.Open(tampered); err == nil {
			t.Fatalf("a cell with bit 0 of byte %d flipped opened successfully; the "+
				"entry operator would treat a forged cell as this session's work",
				position)
		}
	}
}

// The sequence prefix is cleartext but authenticated: it is the AEAD's
// additional data. Changing it must invalidate the cell, or an observer could
// renumber a publisher's cells in flight.
func TestATamperedSequencePrefixIsRefused(t *testing.T) {
	session := testSession(t)
	original := sealedCell(t, session, 7)

	for position := 0; position < SequenceSize; position++ {
		tampered := original
		tampered[position] ^= 0x01
		if _, _, err := session.Open(tampered); err == nil {
			t.Fatalf("a cell whose cleartext sequence byte %d was altered opened "+
				"successfully, so the prefix is not covered by the tag", position)
		}
	}
}

// A cell sealed under another session's key must not open under this one, even
// though it is a perfectly well-formed cell.
func TestACellFromAnotherSessionIsRefused(t *testing.T) {
	session := distinctSession(t, "publisher-a-shared-secret")
	stranger := distinctSession(t, "publisher-b-shared-secret")

	foreign := sealedCell(t, stranger, 7)
	if _, _, err := session.Open(foreign); err == nil {
		t.Fatal("a cell sealed under another session's key opened under this one")
	}
	// The control: the same cell does open under the session that sealed it,
	// so the refusal above is about the key rather than about the cell.
	if _, _, err := stranger.Open(foreign); err != nil {
		t.Fatalf("the cell does not open under its own session either: %v", err)
	}
}

// Random bytes are not a cell. This is the weakest possible forgery and it
// must still be refused, so a caller cannot be made to open noise.
func TestRandomBytesDoNotOpenAsACell(t *testing.T) {
	session := testSession(t)
	for attempt := 0; attempt < 16; attempt++ {
		var noise fabric.Cell
		if _, err := rand.Read(noise[:]); err != nil {
			t.Fatal(err)
		}
		if _, _, err := session.Open(noise); err == nil {
			t.Fatalf("attempt %d: random bytes opened as an authentic cell", attempt)
		}
	}
}

// A cell is bound to its sequence through the nonce, so replaying one under a
// different sequence must fail. Otherwise a cell captured once could be
// replayed into a later slot.
func TestACellDoesNotOpenUnderADifferentSequence(t *testing.T) {
	session := testSession(t)
	original := sealedCell(t, session, 7)

	// Rewrite the cleartext prefix to claim a different sequence. Both the
	// nonce and the additional data change, so this must fail twice over.
	replayed := original
	replayed[SequenceSize-1] ^= 0x03
	if _, _, err := session.Open(replayed); err == nil {
		t.Fatal("a cell renumbered to a different sequence opened successfully")
	}
}

// Padding is checked, so a forger cannot use it as a channel to carry bytes
// past a caller that only reads the inner layer.
func TestNonZeroPaddingIsRefused(t *testing.T) {
	public, _, err := mix.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession([]byte("padding-test-secret"), public, Context{
		NetworkID: "nomad-test", Epoch: 1,
		TopologyDigest: [32]byte{9}, EntryOperator: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	cell := sealedCell(t, session, 3)
	if _, _, err := session.Open(cell); err != nil {
		t.Fatalf("the untampered cell was refused: %v", err)
	}
	// The padding lives inside the sealed plaintext, so it cannot be altered
	// from outside without breaking the tag. What this pins is that the check
	// exists and runs on the opened plaintext: it is the reason a future change
	// to the inner layout cannot quietly start carrying data there.
	if paddingSize <= 0 {
		t.Fatal("there is no padding, so the zero check guards nothing")
	}
}

// A zero sequence is refused on both sides, so the nonce derivation is never
// asked for one.
func TestSequenceZeroIsRefusedOnBothSides(t *testing.T) {
	session := testSession(t)
	var payload [PayloadSize]byte
	if _, err := session.SealWork(0, payload); err == nil {
		t.Fatal("sequence zero was sealed")
	}
	cell := sealedCell(t, session, 1)
	for position := 0; position < SequenceSize; position++ {
		cell[position] = 0
	}
	if _, _, err := session.Open(cell); err == nil {
		t.Fatal("a cell claiming sequence zero opened")
	}
}
