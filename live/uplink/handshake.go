package uplink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"golang.org/x/crypto/hkdf"
)

// An uplink session used to begin with a secret both parties already had. The
// publisher read 32 bytes from a file, the entry operator read the same 32
// bytes from its own file, and how they came to be the same bytes was outside
// the protocol. That is a real deployment: it needs a channel to distribute a
// per-publisher secret to a specific operator before anything can be
// published, which is a channel that knows who publishes what.
//
// This establishes the session in band instead, from material already in the
// signed topology. Every operator publishes a static X25519 key there, and it
// is already the basis of the pairwise hop keys, so a publisher that can verify
// a topology can already reach an entry operator without being introduced.
//
// The construction is one-sided: the publisher authenticates the operator and
// stays anonymous. That is the correct direction here and worth stating
// plainly, because the usual instinct is to make a handshake mutual. The entry
// operator must not learn who is publishing -- that is the property the whole
// airlock exists for -- so the publisher proves nothing about itself, and the
// operator's only guarantee is that somebody who verified the topology is
// speaking to it. Everything that bounds abuse afterwards is per session, never
// per identity.

const (
	// EphemeralSize is the publisher's X25519 public key, carried in the
	// clear because the operator needs it to derive the key that opens the
	// rest of the cell.
	EphemeralSize = 32
	// handshakePadding is what remains of the cell once the sequence, the
	// ephemeral key and the tag are accounted for. It is sealed and must be
	// zero, so a handshake carries no room for anything else.
	handshakePadding = fabric.CellSize - SequenceSize - EphemeralSize - 16

	handshakeKeyDomain    = "nomad-uplink-handshake-v1"
	handshakeSecretDomain = "nomad-uplink-handshake-secret-v1"
	handshakeIDDomain     = "nomad-uplink-handshake-id-v1"
)

var (
	// ErrNotAHandshake reports a cell that does not open as a handshake for
	// this operator. It is one error for every cause: a data cell, a
	// handshake for another operator, a corrupted one and a forged one are
	// indistinguishable to the party that cannot open it, and saying which
	// would hand that distinction to whoever sent it.
	ErrNotAHandshake = errors.New("cell does not open as an uplink handshake")
	// ErrSessionReplay reports an ephemeral key that has already been used
	// in this epoch.
	ErrSessionReplay = errors.New("uplink handshake replays an ephemeral key")
	// ErrTooManySessions reports that the responder is holding as many
	// sessions as it will.
	ErrTooManySessions = errors.New("uplink responder is at its session limit")
)

// Initiator is the publisher's side. It holds an ephemeral key for exactly one
// session and nothing that identifies the publisher.
type Initiator struct {
	ephemeral *ecdh.PrivateKey
	session   *Session
	sessionID [32]byte
	cell      fabric.Cell
}

// Establish generates an ephemeral key, agrees with the entry operator's
// published static key, and produces both the session and the single cell that
// carries the handshake.
//
// operatorKEXKey is the entry operator's kex_key from the signed topology. A
// publisher that took it from anywhere else would be agreeing with whoever
// supplied it.
func Establish(operatorKEXKey []byte, committee mix.PublicKey, context Context,
	sequence uint64) (*Initiator, error) {
	if sequence == 0 {
		return nil, errors.New("uplink sequence must be non-zero")
	}
	if err := context.validate(); err != nil {
		return nil, err
	}
	static, err := ecdh.X25519().NewPublicKey(operatorKEXKey)
	if err != nil {
		return nil, errors.New("entry operator key-agreement key is invalid")
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	agreed, err := ephemeral.ECDH(static)
	if err != nil {
		return nil, errors.New("entry operator key agreement failed")
	}
	public := ephemeral.PublicKey().Bytes()

	session, sessionID, err := sessionFromAgreement(agreed, public, committee, context)
	if err != nil {
		return nil, err
	}
	cell, err := sealHandshake(agreed, public, context, sequence)
	if err != nil {
		return nil, err
	}
	return &Initiator{ephemeral: ephemeral, session: session, sessionID: sessionID, cell: cell}, nil
}

// Cell is the handshake cell to send. It is the same 1200 bytes as every other
// uplink cell and carries an 8-byte sequence like every other uplink cell, so
// an observer cannot tell a session beginning from a session continuing.
func (initiator *Initiator) Cell() fabric.Cell { return initiator.cell }

// Session is the session the handshake established.
func (initiator *Initiator) Session() *Session { return initiator.session }

// SessionID is the public identifier the airlock derives deposit slots from.
// It is a function of the agreement and the ephemeral key, so it identifies the
// session and nothing about the publisher.
func (initiator *Initiator) SessionID() [32]byte { return initiator.sessionID }

// Responder is the entry operator's side.
//
// It holds the operator's static key and remembers which ephemeral keys it has
// already accepted this epoch, because a handshake is a cell like any other and
// a replayed one would otherwise establish a second session on the same key --
// which means the same AEAD nonces under the same key, on a construction whose
// nonces come from a sequence.
type Responder struct {
	mu        sync.Mutex
	static    *ecdh.PrivateKey
	committee mix.PublicKey
	context   Context
	limit     int
	seen      map[[EphemeralSize]byte]struct{}
}

// NewResponder builds the operator side. limit bounds how many sessions it will
// hold, because accepting handshakes without one turns a cheap cell into
// unbounded state.
func NewResponder(static *ecdh.PrivateKey, committee mix.PublicKey, context Context,
	limit int) (*Responder, error) {
	if static == nil {
		return nil, errors.New("entry operator key-agreement private key is required")
	}
	if err := context.validate(); err != nil {
		return nil, err
	}
	if limit < 1 {
		return nil, errors.New("uplink session limit must be positive")
	}
	return &Responder{
		static: static, committee: committee, context: context, limit: limit,
		seen: make(map[[EphemeralSize]byte]struct{}, limit),
	}, nil
}

// Accept opens a handshake cell and returns the session it establishes.
//
// It returns ErrNotAHandshake for anything it cannot open, which includes an
// ordinary data cell. A caller holding existing sessions tries those first and
// falls through to here; the order is not observable, because a failure to open
// produces no output either way.
func (responder *Responder) Accept(cell fabric.Cell) (*Session, [32]byte, error) {
	sequence := binary.BigEndian.Uint64(cell[:SequenceSize])
	if sequence == 0 {
		return nil, [32]byte{}, ErrNotAHandshake
	}
	var public [EphemeralSize]byte
	copy(public[:], cell[SequenceSize:SequenceSize+EphemeralSize])

	ephemeral, err := ecdh.X25519().NewPublicKey(public[:])
	if err != nil {
		return nil, [32]byte{}, ErrNotAHandshake
	}
	agreed, err := responder.static.ECDH(ephemeral)
	if err != nil {
		// An all-zero agreement means a low-order point: the peer chose a
		// key that forces a known shared secret. Refused rather than used.
		return nil, [32]byte{}, ErrNotAHandshake
	}
	if err := openHandshake(agreed, public[:], responder.context, sequence, cell); err != nil {
		return nil, [32]byte{}, ErrNotAHandshake
	}

	responder.mu.Lock()
	if _, replayed := responder.seen[public]; replayed {
		responder.mu.Unlock()
		return nil, [32]byte{}, ErrSessionReplay
	}
	if len(responder.seen) >= responder.limit {
		responder.mu.Unlock()
		return nil, [32]byte{}, ErrTooManySessions
	}
	responder.seen[public] = struct{}{}
	responder.mu.Unlock()

	session, sessionID, err := sessionFromAgreement(agreed, public[:],
		responder.committee, responder.context)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return session, sessionID, nil
}

// Sessions is how many handshakes this responder has accepted.
func (responder *Responder) Sessions() int {
	responder.mu.Lock()
	defer responder.mu.Unlock()
	return len(responder.seen)
}

func (context Context) validate() error {
	if context.NetworkID == "" || context.Epoch == 0 || context.TopologyDigest == ([32]byte{}) {
		return errors.New("uplink context is incomplete")
	}
	return nil
}

// handshakeInfo binds a derivation to the exact public protocol state it
// belongs to, plus the ephemeral key, so nothing derived here can be reused in
// another network, epoch, topology or operator, or under another ephemeral key.
func handshakeInfo(domain string, context Context, public []byte) []byte {
	network := []byte(context.NetworkID)
	info := make([]byte, 0, len(domain)+len(network)+64)
	info = append(info, domain...)
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], uint64(len(network)))
	info = append(info, integer[:]...)
	info = append(info, network...)
	binary.BigEndian.PutUint64(integer[:], context.Epoch)
	info = append(info, integer[:]...)
	binary.BigEndian.PutUint16(integer[:2], context.EntryOperator)
	info = append(info, integer[:2]...)
	return append(info, public...)
}

func handshakeDerive(agreed, public []byte, context Context, domain string) ([32]byte, error) {
	var out [32]byte
	reader := hkdf.New(sha256.New, agreed, context.TopologyDigest[:],
		handshakeInfo(domain, context, public))
	if _, err := io.ReadFull(reader, out[:]); err != nil {
		return [32]byte{}, err
	}
	return out, nil
}

// sessionFromAgreement turns the agreement into exactly what the pre-shared
// file used to supply: a 32-byte session secret, which then goes through the
// unchanged SessionKey derivation. Keeping that step intact is deliberate --
// the data path, its published test vectors and its second implementation do
// not move because the way the secret is obtained changed.
func sessionFromAgreement(agreed, public []byte, committee mix.PublicKey,
	context Context) (*Session, [32]byte, error) {
	secret, err := handshakeDerive(agreed, public, context, handshakeSecretDomain)
	if err != nil {
		return nil, [32]byte{}, err
	}
	session, err := NewSession(secret[:], committee, context)
	if err != nil {
		return nil, [32]byte{}, err
	}
	sessionID, err := handshakeDerive(agreed, public, context, handshakeIDDomain)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return session, sessionID, nil
}

func handshakeAEAD(agreed, public []byte, context Context) (cipher.AEAD, error) {
	key, err := handshakeDerive(agreed, public, context, handshakeKeyDomain)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// handshakeNonce is derived from the sequence exactly as the data path's is,
// and from a key that already depends on the ephemeral. One handshake per
// ephemeral key is enforced by the responder, so this nonce is used once.
func handshakeNonce(agreed, public []byte, context Context, sequence uint64) ([]byte, error) {
	key, err := handshakeDerive(agreed, public, context, handshakeKeyDomain)
	if err != nil {
		return nil, err
	}
	return Nonce(key, sequence), nil
}

func sealHandshake(agreed, public []byte, context Context, sequence uint64) (fabric.Cell, error) {
	aead, err := handshakeAEAD(agreed, public, context)
	if err != nil {
		return fabric.Cell{}, err
	}
	nonce, err := handshakeNonce(agreed, public, context, sequence)
	if err != nil {
		return fabric.Cell{}, err
	}
	var cell fabric.Cell
	binary.BigEndian.PutUint64(cell[:SequenceSize], sequence)
	copy(cell[SequenceSize:SequenceSize+EphemeralSize], public)

	// The sealed region is all zero. A handshake is an introduction and
	// carries nothing else, so there is no room in it for a covert channel
	// and the responder checks that there is none.
	padding := make([]byte, handshakePadding)
	sealed := aead.Seal(nil, nonce, padding, cell[:SequenceSize+EphemeralSize])
	if len(sealed) != fabric.CellSize-SequenceSize-EphemeralSize {
		return fabric.Cell{}, fmt.Errorf("unexpected sealed handshake length %d", len(sealed))
	}
	copy(cell[SequenceSize+EphemeralSize:], sealed)
	return cell, nil
}

func openHandshake(agreed, public []byte, context Context, sequence uint64, cell fabric.Cell) error {
	aead, err := handshakeAEAD(agreed, public, context)
	if err != nil {
		return err
	}
	nonce, err := handshakeNonce(agreed, public, context, sequence)
	if err != nil {
		return err
	}
	opened, err := aead.Open(nil, nonce, cell[SequenceSize+EphemeralSize:],
		cell[:SequenceSize+EphemeralSize])
	if err != nil {
		return ErrNotAHandshake
	}
	if len(opened) != handshakePadding {
		return ErrNotAHandshake
	}
	if subtle.ConstantTimeCompare(opened, make([]byte, handshakePadding)) != 1 {
		return ErrNotAHandshake
	}
	return nil
}
