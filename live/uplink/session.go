// Package uplink carries publisher-facing cells from a client to an entry
// operator at a fixed public rate.
//
// It exists because the operator-to-operator cell profile cannot carry
// publication traffic: there, a cell's hop header states in cleartext
// whether it holds work, and a work payload is a batch of compressed group
// elements while cover is uniform random, so two independent passive
// classifiers separate work from cover perfectly. On an operator link that
// is consistent with the reader claim, since relay work follows public
// replication policy. On a publisher link the existence of work is exactly
// the private fact that must not be observable.
//
// An uplink cell is therefore a cleartext sequence counter followed by one
// authenticated ciphertext covering everything else. Work and cover differ
// only inside that ciphertext, and inside it they differ only within a
// second layer encrypted to the epoch committee, so neither a network
// observer nor the entry operator can tell whether a user published.
package uplink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"golang.org/x/crypto/hkdf"
)

const (
	// PayloadSize is one publication fragment, exactly one mix plaintext.
	PayloadSize = mix.PlainCellSize
	// InnerSize is the committee ciphertext carried by every cell.
	InnerSize = 1152
	// SequenceSize is the cleartext counter prefix.
	SequenceSize = 8
	// paddingSize keeps every sealed cell exactly fabric.CellSize.
	paddingSize = fabric.CellSize - SequenceSize - InnerSize - 16
)

// Context binds a session to the exact public protocol state it belongs to.
// A key derived for one network, epoch, topology or role cannot be used in
// another, so a captured uplink session cannot be replayed elsewhere.
type Context struct {
	NetworkID      string
	Epoch          uint64
	TopologyDigest [32]byte
	EntryOperator  uint16
}

// Session holds one client-to-entry-operator uplink key plus the epoch
// committee key that the inner layer is encrypted to.
type Session struct {
	key       [32]byte
	committee mix.PublicKey
	context   Context
}

// NewSession derives the outer session key from a shared secret. The shared
// secret comes from the client's key agreement with the entry operator; the
// derivation binds network, epoch, topology digest and operator slot.
func NewSession(sharedSecret []byte, committee mix.PublicKey, context Context) (*Session, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("uplink shared secret is required")
	}
	if context.NetworkID == "" || context.Epoch == 0 || context.TopologyDigest == ([32]byte{}) {
		return nil, errors.New("uplink context is incomplete")
	}
	info := make([]byte, 0, 64+len(context.NetworkID))
	info = append(info, []byte("nomad-uplink-session-v1")...)
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], uint64(len(context.NetworkID)))
	info = append(info, integer[:]...)
	info = append(info, context.NetworkID...)
	binary.BigEndian.PutUint64(integer[:], context.Epoch)
	info = append(info, integer[:]...)
	binary.BigEndian.PutUint16(integer[:2], context.EntryOperator)
	info = append(info, integer[:2]...)
	reader := hkdf.New(sha256.New, sharedSecret, context.TopologyDigest[:], info)
	session := &Session{committee: committee, context: context}
	if _, err := io.ReadFull(reader, session.key[:]); err != nil {
		return nil, err
	}
	return session, nil
}

// SealWork produces the cell for one publication fragment.
func (session *Session) SealWork(sequence uint64, payload [PayloadSize]byte) (fabric.Cell, error) {
	return session.seal(sequence, payload)
}

// SealCover produces a cell carrying no publication work. It follows the
// identical code path and produces an identically distributed cell: the
// inner layer is a real committee encryption of the reserved empty
// fragment, which the committee discards after threshold decryption. The
// entry operator therefore cannot tell cover from work either.
func (session *Session) SealCover(sequence uint64) (fabric.Cell, error) {
	var empty [PayloadSize]byte
	return session.seal(sequence, empty)
}

// IsCoverPayload reports the reserved empty fragment. Only a party that has
// completed threshold decryption of the inner layer can evaluate this.
func IsCoverPayload(payload [PayloadSize]byte) bool {
	for _, value := range payload {
		if value != 0 {
			return false
		}
	}
	return true
}

func (session *Session) seal(sequence uint64, payload [PayloadSize]byte) (fabric.Cell, error) {
	if session == nil {
		return fabric.Cell{}, errors.New("uplink session is required")
	}
	if sequence == 0 {
		return fabric.Cell{}, errors.New("uplink sequence must be non-zero")
	}
	var plain mix.PlainCell
	copy(plain[:], payload[:])
	// A mix batch requires at least two columns. ElGamal encryption is
	// per-column with independent randomness, so column zero of a two-column
	// batch is exactly the ciphertext for this fragment; the discarded
	// companion column never leaves this function.
	var companion mix.PlainCell
	batch, err := mix.Encrypt(session.committee, []mix.PlainCell{plain, companion})
	if err != nil {
		return fabric.Cell{}, err
	}
	wire, err := batch.MarshalWire()
	if err != nil {
		return fabric.Cell{}, err
	}
	if len(wire) != 2 {
		return fabric.Cell{}, errors.New("unexpected uplink batch size")
	}

	inner := make([]byte, 0, InnerSize+paddingSize)
	inner = append(inner, wire[0][:InnerSize]...)
	inner = append(inner, make([]byte, paddingSize)...)

	aead, err := session.aead()
	if err != nil {
		return fabric.Cell{}, err
	}
	var cell fabric.Cell
	binary.BigEndian.PutUint64(cell[:SequenceSize], sequence)
	sealed := aead.Seal(nil, session.nonce(sequence), inner, cell[:SequenceSize])
	if len(sealed) != fabric.CellSize-SequenceSize {
		return fabric.Cell{}, errors.New("unexpected sealed uplink length")
	}
	copy(cell[SequenceSize:], sealed)
	return cell, nil
}

// Open authenticates and decrypts one uplink cell, returning the inner
// committee ciphertext. The entry operator learns nothing beyond "a
// well-formed cell arrived from this session": the returned ciphertext is
// identically distributed for work and cover.
func (session *Session) Open(cell fabric.Cell) (uint64, [InnerSize]byte, error) {
	var inner [InnerSize]byte
	if session == nil {
		return 0, inner, errors.New("uplink session is required")
	}
	sequence := binary.BigEndian.Uint64(cell[:SequenceSize])
	if sequence == 0 {
		return 0, inner, errors.New("uplink sequence must be non-zero")
	}
	aead, err := session.aead()
	if err != nil {
		return 0, inner, err
	}
	opened, err := aead.Open(nil, session.nonce(sequence), cell[SequenceSize:], cell[:SequenceSize])
	if err != nil {
		return 0, inner, errors.New("uplink cell failed authentication")
	}
	if len(opened) != InnerSize+paddingSize {
		return 0, inner, errors.New("uplink cell has unexpected length")
	}
	for _, value := range opened[InnerSize:] {
		if value != 0 {
			return 0, inner, errors.New("uplink padding must be zero")
		}
	}
	copy(inner[:], opened[:InnerSize])
	return sequence, inner, nil
}

func (session *Session) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(session.key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// nonce is derived deterministically from the cleartext sequence, so a
// nonce never repeats under one session key without a sequence repeat, and
// no random nonce needs to be transmitted.
func (session *Session) nonce(sequence uint64) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-uplink-nonce-v1"))
	_, _ = h.Write(session.key[:])
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], sequence)
	_, _ = h.Write(integer[:])
	return h.Sum(nil)[:12]
}
