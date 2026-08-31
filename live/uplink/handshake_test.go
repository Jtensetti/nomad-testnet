package uplink

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
)

func handshakeContext() Context {
	context := Context{NetworkID: "handshake-network", Epoch: 4, EntryOperator: 2}
	for index := range context.TopologyDigest {
		context.TopologyDigest[index] = byte(index + 1)
	}
	return context
}

func entryOperator(t *testing.T) (*ecdh.PrivateKey, []byte, mix.PublicKey) {
	t.Helper()
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	committee, _, err := mix.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return static, static.PublicKey().Bytes(), committee
}

// The claim: a publisher that can verify a topology can open a session with an
// entry operator without either of them having been introduced beforehand, and
// both sides end up with the same session and the same session identifier.
func TestAHandshakeEstablishesTheSameSessionOnBothSides(t *testing.T) {
	static, public, committee := entryOperator(t)
	context := handshakeContext()

	initiator, err := Establish(public, committee, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewResponder(static, committee, context, 8)
	if err != nil {
		t.Fatal(err)
	}
	session, sessionID, err := responder.Accept(initiator.Cell())
	if err != nil {
		t.Fatalf("the operator refused a handshake it should have opened: %v", err)
	}
	if sessionID != initiator.SessionID() {
		t.Fatalf("session identifiers differ: %x and %x", sessionID, initiator.SessionID())
	}

	// The two sessions must be the same session, which is only demonstrated
	// by one sealing what the other opens.
	var payload [PayloadSize]byte
	copy(payload[:], "a publication fragment")
	cell, err := initiator.Session().SealWork(2, payload)
	if err != nil {
		t.Fatal(err)
	}
	sequence, inner, err := session.Open(cell)
	if err != nil {
		t.Fatalf("the operator could not open a cell from the session it established: %v", err)
	}
	if sequence != 2 {
		t.Fatalf("sequence came back as %d", sequence)
	}
	if inner == ([InnerSize]byte{}) {
		t.Fatal("the inner layer came back empty")
	}
}

// The publisher authenticates the operator; the operator learns nothing about
// the publisher. If the operator's key is not the one in the signed topology,
// the session must not form -- otherwise a publisher could be talked into
// agreeing with whoever answered.
func TestAHandshakeForAnotherOperatorIsRefused(t *testing.T) {
	_, publicOfIntended, committee := entryOperator(t)
	impostorStatic, _, _ := entryOperator(t)
	context := handshakeContext()

	initiator, err := Establish(publicOfIntended, committee, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	impostor, err := NewResponder(impostorStatic, committee, context, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := impostor.Accept(initiator.Cell()); !errors.Is(err, ErrNotAHandshake) {
		t.Fatalf("an operator that is not the addressee opened the handshake: %v", err)
	}
}

// A handshake is a cell like any other, so a replay would otherwise establish a
// second session on the same key -- and the data path's nonces come from a
// sequence, so the same key twice is the same nonces twice.
func TestAReplayedHandshakeIsRefused(t *testing.T) {
	static, public, committee := entryOperator(t)
	context := handshakeContext()
	initiator, err := Establish(public, committee, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewResponder(static, committee, context, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := responder.Accept(initiator.Cell()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := responder.Accept(initiator.Cell()); !errors.Is(err, ErrSessionReplay) {
		t.Fatalf("a replayed handshake established a second session: %v", err)
	}
	if responder.Sessions() != 1 {
		t.Fatalf("the responder holds %d sessions after one handshake and one replay",
			responder.Sessions())
	}
}

// Accepting handshakes without a bound turns a cheap cell into unbounded state.
func TestTheResponderStopsAtItsSessionLimit(t *testing.T) {
	static, public, committee := entryOperator(t)
	context := handshakeContext()
	const limit = 4
	responder, err := NewResponder(static, committee, context, limit)
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for attempt := 0; attempt < limit*4; attempt++ {
		initiator, err := Establish(public, committee, context, uint64(attempt+1))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := responder.Accept(initiator.Cell()); err == nil {
			accepted++
		} else if !errors.Is(err, ErrTooManySessions) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if accepted != limit {
		t.Fatalf("the responder accepted %d sessions against a limit of %d", accepted, limit)
	}
	if _, err := NewResponder(static, committee, context, 0); err == nil {
		t.Fatal("a responder with no session limit was accepted")
	}
}

// Every derivation must be bound to the public protocol state, or a handshake
// captured in one epoch or network establishes a session in another.
func TestTheHandshakeIsBoundToItsContext(t *testing.T) {
	static, public, committee := entryOperator(t)
	context := handshakeContext()
	initiator, err := Establish(public, committee, context, 1)
	if err != nil {
		t.Fatal(err)
	}

	otherEpoch := context
	otherEpoch.Epoch++
	otherNetwork := context
	otherNetwork.NetworkID = "another-network"
	otherOperator := context
	otherOperator.EntryOperator++
	otherTopology := context
	otherTopology.TopologyDigest[0] ^= 0x01

	for name, changed := range map[string]Context{
		"another epoch":    otherEpoch,
		"another network":  otherNetwork,
		"another operator": otherOperator,
		"another topology": otherTopology,
	} {
		t.Run(name, func(t *testing.T) {
			responder, err := NewResponder(static, committee, changed, 8)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := responder.Accept(initiator.Cell()); !errors.Is(err, ErrNotAHandshake) {
				t.Fatalf("the handshake opened under %s: %v", name, err)
			}
		})
	}

	// The positive control: the same cell under the same context opens, so
	// the refusals above are about the binding rather than about a responder
	// that refuses everything.
	responder, err := NewResponder(static, committee, context, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := responder.Accept(initiator.Cell()); err != nil {
		t.Fatalf("the unmodified handshake was refused: %v", err)
	}
}

// A handshake carries an introduction and nothing else. If the sealed region
// were not required to be zero, it would be 1144 bytes of covert channel from
// a party the operator cannot identify.
func TestAHandshakeCarryingAnythingElseIsRefused(t *testing.T) {
	static, public, committee := entryOperator(t)
	context := handshakeContext()
	initiator, err := Establish(public, committee, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewResponder(static, committee, context, 8)
	if err != nil {
		t.Fatal(err)
	}

	// Every byte outside the sequence and the ephemeral key is under the
	// tag, so smuggling anything means the cell no longer authenticates.
	for name, offset := range map[string]int{
		"in the sealed padding": SequenceSize + EphemeralSize + 4,
		"just before the tag":   fabric.CellSize - 17,
		"in the tag":            fabric.CellSize - 1,
		"in the ephemeral key":  SequenceSize + 1,
		"in the sequence":       1,
	} {
		t.Run(name, func(t *testing.T) {
			cell := initiator.Cell()
			cell[offset] ^= 0x01
			if _, _, err := responder.Accept(cell); err == nil {
				t.Fatalf("a handshake modified at byte %d was accepted", offset)
			}
		})
	}
}

// A data cell must not open as a handshake. The operator tries its sessions
// first and falls through, so a data cell reaching the handshake path is
// ordinary rather than exceptional, and it has to be refused quietly.
func TestADataCellDoesNotOpenAsAHandshake(t *testing.T) {
	static, public, committee := entryOperator(t)
	context := handshakeContext()
	initiator, err := Establish(public, committee, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewResponder(static, committee, context, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := responder.Accept(initiator.Cell()); err != nil {
		t.Fatal(err)
	}

	var payload [PayloadSize]byte
	copy(payload[:], "a publication fragment")
	work, err := initiator.Session().SealWork(2, payload)
	if err != nil {
		t.Fatal(err)
	}
	cover, err := initiator.Session().SealCover(3)
	if err != nil {
		t.Fatal(err)
	}
	for name, cell := range map[string]fabric.Cell{"work": work, "cover": cover} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := responder.Accept(cell); !errors.Is(err, ErrNotAHandshake) {
				t.Fatalf("a %s cell opened as a handshake: %v", name, err)
			}
		})
	}

	// And a cell of uniform random bytes, which is what an attacker with no
	// key can produce.
	var noise fabric.Cell
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := responder.Accept(noise); !errors.Is(err, ErrNotAHandshake) {
		t.Fatalf("random bytes opened as a handshake: %v", err)
	}
}

// The handshake must not be identifiable on the wire, or the beginning of a
// session -- and therefore the beginning of a publication -- is observable.
func TestAHandshakeIsTheSameShapeAsAnyOtherUplinkCell(t *testing.T) {
	_, public, committee := entryOperator(t)
	context := handshakeContext()
	initiator, err := Establish(public, committee, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	handshake := initiator.Cell()

	var payload [PayloadSize]byte
	copy(payload[:], "a publication fragment")
	work, err := initiator.Session().SealWork(2, payload)
	if err != nil {
		t.Fatal(err)
	}
	// Equal length is a type-level guarantee -- Cell and SealWork both return a
	// fabric.Cell -- so it is not what this test can add. What it can add is
	// that neither cell carries something an observer could sort them by.
	if work == handshake {
		t.Fatal("a work cell and a handshake are byte-identical")
	}
	if bytes.Contains(work[:], []byte("a publication fragment")) {
		t.Fatal("the work cell carries its fragment in plaintext")
	}

	// The ephemeral key is in the clear, so it must not be something an
	// observer can recognise as a key rather than as ciphertext. What can be
	// asserted here is the weaker, checkable thing: it is not a constant, it
	// is not the operator's published key, and two handshakes share nothing.
	second, err := Establish(public, committee, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	secondCell := second.Cell()
	first := handshake[SequenceSize : SequenceSize+EphemeralSize]
	other := secondCell[SequenceSize : SequenceSize+EphemeralSize]
	if bytes.Equal(first, other) {
		t.Fatal("two handshakes carry the same ephemeral key")
	}
	if bytes.Equal(first, public) {
		t.Fatal("the handshake echoes the operator's own published key")
	}
	if bytes.Contains(handshake[:], []byte("a publication fragment")) {
		t.Fatal("the handshake carries plaintext")
	}
}

// The session a handshake produces must be the ordinary kind: the data path,
// its published vectors and its second implementation do not move because the
// way the secret is obtained changed.
func TestTheEstablishedSessionUsesTheUnchangedDataPath(t *testing.T) {
	static, public, committee := entryOperator(t)
	context := handshakeContext()
	initiator, err := Establish(public, committee, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewResponder(static, committee, context, 8)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := responder.Accept(initiator.Cell())
	if err != nil {
		t.Fatal(err)
	}

	// A cover cell from the established session must be indistinguishable
	// from a work cell by the same two classifiers the profile is measured
	// against elsewhere, which is only true if this is the same construction.
	for sequence := uint64(2); sequence < 8; sequence++ {
		var payload [PayloadSize]byte
		copy(payload[:], "fragment")
		work, err := initiator.Session().SealWork(sequence, payload)
		if err != nil {
			t.Fatal(err)
		}
		cover, err := initiator.Session().SealCover(sequence + 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(work) != len(cover) {
			t.Fatal("work and cover are different lengths on an established session")
		}
		if _, _, err := session.Open(work); err != nil {
			t.Fatalf("the operator could not open work at sequence %d: %v", sequence, err)
		}
		if _, _, err := session.Open(cover); err != nil {
			t.Fatalf("the operator could not open cover at sequence %d: %v", sequence, err)
		}
	}
}

func TestEstablishRefusesUnusableInput(t *testing.T) {
	_, public, committee := entryOperator(t)
	context := handshakeContext()

	if _, err := Establish(public, committee, context, 0); err == nil {
		t.Error("a zero sequence was accepted")
	}
	if _, err := Establish(public, committee, Context{}, 1); err == nil {
		t.Error("an empty context was accepted")
	}
	if _, err := Establish(bytes.Repeat([]byte{0}, 31), committee, context, 1); err == nil {
		t.Error("a short operator key was accepted")
	}
	// An all-zero X25519 public key is a low-order point: agreeing with it
	// produces a shared secret the peer already knows.
	if _, err := Establish(make([]byte, 32), committee, context, 1); err == nil {
		t.Error("an all-zero operator key was accepted")
	}
}

// The session identifier is public: the airlock derives deposit slots from it,
// so it appears in state an operator can see. Key material must never be
// derivable from it, which means the three derivations off one agreement have
// to be genuinely separated rather than separated by a constant somebody could
// make equal.
//
// This is not hypothetical carelessness. Setting the identifier's domain equal
// to the secret's is a one-character edit, and it makes the public deposit
// identifier be the session secret. Nothing else in this file notices.
func TestTheHandshakeDerivationsAreSeparated(t *testing.T) {
	static, public, _ := entryOperator(t)
	context := handshakeContext()
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	staticPublic, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	agreed, err := ephemeral.ECDH(staticPublic)
	if err != nil {
		t.Fatal(err)
	}
	_ = static
	ephemeralPublic := ephemeral.PublicKey().Bytes()

	derived := map[string][32]byte{}
	for _, domain := range []string{handshakeKeyDomain, handshakeSecretDomain, handshakeIDDomain} {
		value, err := handshakeDerive(agreed, ephemeralPublic, context, domain)
		if err != nil {
			t.Fatal(err)
		}
		for other, previous := range derived {
			if previous == value {
				t.Fatalf("%q and %q derive the same 32 bytes; the public session "+
					"identifier would be key material", other, domain)
			}
		}
		derived[domain] = value
	}
	if len(derived) != 3 {
		t.Fatalf("three domains produced %d distinct derivations", len(derived))
	}
}

// Every derivation must depend on the ephemeral key, not only on the agreement
// that already does. The dependency is belt and braces, and belt and braces
// that nothing tests is one strap: a change that drops the ephemeral from the
// info string leaves both sides agreeing with each other and is invisible.
func TestTheHandshakeInfoBindsTheEphemeralKeyAndTheContext(t *testing.T) {
	context := handshakeContext()
	first := bytes.Repeat([]byte{0x11}, EphemeralSize)
	second := bytes.Repeat([]byte{0x22}, EphemeralSize)

	info := handshakeInfo(handshakeKeyDomain, context, first)
	if !bytes.HasPrefix(info, []byte(handshakeKeyDomain)) {
		t.Fatalf("the info string does not start with its domain: %q", info)
	}
	if !bytes.HasSuffix(info, first) {
		t.Fatal("the info string does not bind the ephemeral key")
	}
	if bytes.Equal(info, handshakeInfo(handshakeKeyDomain, context, second)) {
		t.Fatal("two different ephemeral keys produce the same info string")
	}
	if bytes.Equal(info, handshakeInfo(handshakeSecretDomain, context, first)) {
		t.Fatal("two domains produce the same info string")
	}
	other := context
	other.Epoch++
	if bytes.Equal(info, handshakeInfo(handshakeKeyDomain, other, first)) {
		t.Fatal("two epochs produce the same info string")
	}
}

// The handshake's additional data covers the ephemeral key as well as the
// sequence. Like the info string this is belt and braces -- a changed
// ephemeral changes the derived key too -- so it is pinned directly rather
// than left to a negative test that would pass either way.
func TestTheHandshakeAuthenticatesItsCleartextFields(t *testing.T) {
	static, public, committee := entryOperator(t)
	context := handshakeContext()
	initiator, err := Establish(public, committee, context, 9)
	if err != nil {
		t.Fatal(err)
	}
	cell := initiator.Cell()

	staticPublic, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	_ = static
	// Re-derive the agreement the way the operator does, so the AEAD here is
	// the one that sealed the cell.
	ephemeral := cell[SequenceSize : SequenceSize+EphemeralSize]
	_ = staticPublic
	agreed, err := static.ECDH(mustPublic(t, ephemeral))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := handshakeAEAD(agreed, ephemeral, context)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := handshakeNonce(agreed, ephemeral, context, 9)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := aead.Open(nil, nonce, cell[SequenceSize+EphemeralSize:],
		cell[:SequenceSize+EphemeralSize]); err != nil {
		t.Fatalf("the cell does not open under the additional data it was sealed with: %v", err)
	}
	if _, err := aead.Open(nil, nonce, cell[SequenceSize+EphemeralSize:],
		cell[:SequenceSize]); err == nil {
		t.Fatal("the cell opens with the sequence alone as additional data, so the " +
			"ephemeral key is not authenticated by the tag")
	}
}

func mustPublic(t *testing.T, encoded []byte) *ecdh.PublicKey {
	t.Helper()
	key, err := ecdh.X25519().NewPublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The covert-channel claim, tested by an attacker who can produce a valid tag.
//
// Flipping bits in a handshake breaks the tag, so every negative case above is
// refused before the padding is ever looked at. The party this check exists
// against is not an outsider: it is a publisher, who holds a real ephemeral key
// and can seal whatever it likes correctly. Its cell authenticates. Only the
// requirement that the sealed region is zero stops 1144 bytes reaching the
// entry operator from a party the operator cannot identify.
func TestAValidlySealedHandshakeCarryingDataIsRefused(t *testing.T) {
	static, public, committee := entryOperator(t)
	context := handshakeContext()
	responder, err := NewResponder(static, committee, context, 8)
	if err != nil {
		t.Fatal(err)
	}

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agreed, err := ephemeral.ECDH(mustPublic(t, public))
	if err != nil {
		t.Fatal(err)
	}
	ephemeralPublic := ephemeral.PublicKey().Bytes()

	build := func(payload []byte, sequence uint64) fabric.Cell {
		t.Helper()
		aead, err := handshakeAEAD(agreed, ephemeralPublic, context)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := handshakeNonce(agreed, ephemeralPublic, context, sequence)
		if err != nil {
			t.Fatal(err)
		}
		var cell fabric.Cell
		binary.BigEndian.PutUint64(cell[:SequenceSize], sequence)
		copy(cell[SequenceSize:SequenceSize+EphemeralSize], ephemeralPublic)
		sealed := aead.Seal(nil, nonce, payload, cell[:SequenceSize+EphemeralSize])
		copy(cell[SequenceSize+EphemeralSize:], sealed)
		return cell
	}

	smuggled := make([]byte, handshakePadding)
	copy(smuggled, "this is a publisher identity the operator must never receive")
	if _, _, err := responder.Accept(build(smuggled, 1)); !errors.Is(err, ErrNotAHandshake) {
		t.Fatalf("a correctly sealed handshake carrying data was accepted: %v", err)
	}

	// One non-zero byte at the far end, so the check cannot be a prefix test.
	trailing := make([]byte, handshakePadding)
	trailing[len(trailing)-1] = 1
	if _, _, err := responder.Accept(build(trailing, 2)); !errors.Is(err, ErrNotAHandshake) {
		t.Fatalf("a handshake with one non-zero trailing byte was accepted: %v", err)
	}

	// A short payload, which would otherwise let a publisher shorten the cell
	// and signal in its length.
	if _, _, err := responder.Accept(build(make([]byte, handshakePadding-1), 3)); err == nil {
		t.Fatal("a handshake with a short sealed region was accepted")
	}

	// The positive control: the same construction with all-zero padding is
	// accepted, so the refusals are about the content and not about this
	// hand-built cell being malformed.
	if _, _, err := responder.Accept(build(make([]byte, handshakePadding), 4)); err != nil {
		t.Fatalf("a correctly built empty handshake was refused: %v", err)
	}
}
