// Package hop authenticates and encrypts one fixed-size UDP hop without
// changing Nomad's 1200-byte cell size. The mix ciphertext occupies bytes
// 0..1151; its existing 48-byte padding is replaced by a versioned routing
// header. Mix parsing intentionally ignores that padding region.
//
// # Why the header is encrypted
//
// Version 1 authenticated the header and sent it in the clear. That put the
// work flag and a 16-byte stream ID on the wire, and the stream ID is a hash
// of the batch payloads, so it was the same value at every hop the batch took.
// A passive observer did not need a correlation attack to follow a batch
// across the relay fabric, or to tell a work cell from a cover cell: both were
// written on the outside of the envelope. live/node/linkability_test.go
// measured the first and live/uplink/distinguisher_test.go measured the
// second.
//
// Constant-rate cover traffic is the mechanism this system spends its entire
// bandwidth budget on, and a readable work flag is a direct answer to the
// question that cover traffic exists to make unanswerable.
//
// Encrypting the header alone would not have been enough. A work cell carries
// mix ciphertext and a cover cell carries uniform random bytes, and mix
// ciphertext parses as compressed group elements while random bytes almost
// never do -- a second distinguisher, independent of the header, that
// separated the two perfectly. So version 2 encrypts the whole cell under the
// pairwise link key: payload and routing metadata alike. What goes on the wire
// is a uniform pseudorandom string, the same length every time, whatever it
// carries.
//
// # What is still visible, and why
//
// The sequence number stays in the clear because it is the keystream input:
// the receiver must derive the keystream before it can decrypt, and it must
// verify the tag before it derives anything. It is a per-link counter that
// advances once per cell on a fixed cadence, so it says nothing a packet count
// does not already say, and it is unrelated between links -- a relayed cell
// gets a fresh number from the sending link's own sequence, so it cannot be
// followed across a hop.
//
// The sender's identity is not in the header at all any more. The receiver
// already knows which peer a datagram came from, and the peer's address is in
// the IP header regardless; putting the slot index in the payload as well only
// gave an observer a second copy. It is carried encrypted and checked against
// the expected peer after decryption, so a peer still cannot claim to be
// another.
package hop

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
)

const (
	CiphertextSize = 1152
	HeaderSize     = 48
	TagSize        = 16
	MaximumBatch   = 256
	FlagWork       = uint16(1)

	// sealedSize is the encrypted routing metadata: sender, ordinal, batch
	// size, flags and the stream ID.
	sealedSize = 24
	// sequenceOffset, sealedOffset and tagOffset are relative to the start
	// of the header, which begins at CiphertextSize in the cell. Only the
	// magic and the sequence are in the clear.
	sequenceOffset = 4
	sealedOffset   = 8
	tagOffset      = HeaderSize - TagSize

	streamKeyLabel = "nomad-hop-link-stream-v2"
	headerTagLabel = "nomad-hop-cell-v2"
)

// wireMagic marks a header that has been sealed for a specific peer.
// localMagic marks one that has not and must never reach a socket. They differ
// so that a cell cannot be read with the wrong reader by accident: the
// unauthenticated reader refuses a wire header outright rather than returning
// ciphertext interpreted as metadata.
var (
	wireMagic  = [4]byte{'N', 'H', 'C', 2}
	localMagic = [4]byte{'N', 'H', 'L', 2}
)

type StreamID [16]byte

type Metadata struct {
	Sender    uint16
	Ordinal   uint16
	BatchSize uint16
	Flags     uint16
	Stream    StreamID
	Sequence  uint32
}

type Context struct {
	TopologyDigest [32]byte
	NetworkID      string
	Epoch          uint64
	Receiver       uint16
}

func WorkMetadata(stream StreamID, ordinal, batchSize uint16) (Metadata, error) {
	metadata := Metadata{Ordinal: ordinal, BatchSize: batchSize, Flags: FlagWork, Stream: stream}
	if err := validateMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func CoverMetadata() Metadata { return Metadata{} }

func IsWork(metadata Metadata) bool { return metadata.Flags&FlagWork != 0 }

// SetMetadata prepares a locally supplied cell for the fixed scheduler. The
// header it writes is in the clear and carries the local magic: it is not a
// wire header, and Seal replaces it with one before the cell can be sent.
func SetMetadata(cell *fabric.Cell, metadata Metadata) error {
	if cell == nil {
		return errors.New("cell is required")
	}
	if err := validateMetadata(metadata); err != nil {
		return err
	}
	encodeLocalHeader(cell[CiphertextSize:], metadata)
	return nil
}

// LocalMetadata reads the routing metadata of a cell that has not been sealed.
//
// It refuses a wire header rather than returning what it finds there. In
// version 1 the equivalent function read a sealed cell's header perfectly well
// and carried a comment asking callers not to trust it, which is the kind of
// contract that holds until someone is in a hurry. Now the only way to read a
// sealed cell is Verify, which authenticates first.
func LocalMetadata(cell fabric.Cell) (Metadata, error) {
	return decodeLocalHeader(cell[CiphertextSize:])
}

// WireSequence reads the one field a sealed header leaves in the clear.
//
// It is for diagnostics and for the receiver's own logging, and it is
// deliberately the only unauthenticated read a wire cell offers.
func WireSequence(cell fabric.Cell) (uint32, error) {
	header := cell[CiphertextSize:]
	if string(header[0:4]) != string(wireMagic[:]) {
		return 0, errors.New("not a sealed hop header")
	}
	return binary.BigEndian.Uint32(header[sequenceOffset : sequenceOffset+4]), nil
}

// Seal encrypts the routing metadata for one peer and authenticates the whole
// cell to it.
//
// The order is encrypt-then-MAC: the tag covers the ciphertext, so a modified
// cell fails authentication without anything being decrypted, and a peer never
// becomes a decryption oracle for cells it did not receive intact.
func Seal(cell *fabric.Cell, metadata Metadata, sender uint16, sequence uint32, key [32]byte, context Context) error {
	if cell == nil {
		return errors.New("cell is required")
	}
	if err := validateAuthentication(key, context); err != nil {
		return err
	}
	metadata.Sender = sender
	metadata.Sequence = sequence
	if sequence == 0 {
		return errors.New("hop sequence must be non-zero")
	}
	if err := validateMetadata(metadata); err != nil {
		return err
	}

	header := cell[CiphertextSize:]
	copy(header[0:4], wireMagic[:])
	binary.BigEndian.PutUint32(header[sequenceOffset:sequenceOffset+4], sequence)
	encodeSealed(header[sealedOffset:sealedOffset+sealedSize], metadata)

	stream, err := linkStream(key, context, sequence)
	if err != nil {
		return err
	}
	// One keystream over both regions, in this order, every time. They are
	// not contiguous in the cell -- the magic and sequence sit between them
	// in the clear -- so the order is what both sides have to agree on.
	stream.XORKeyStream(cell[:CiphertextSize], cell[:CiphertextSize])
	stream.XORKeyStream(header[sealedOffset:sealedOffset+sealedSize],
		header[sealedOffset:sealedOffset+sealedSize])

	tag := authenticationTag(*cell, key, context)
	copy(header[tagOffset:], tag[:])
	return nil
}

// Open authenticates a received cell and only then decrypts it, in place.
//
// It takes a pointer because it rewrites the cell: on return the payload is
// the plaintext the sender put there and the header is a local one, which is
// the form the scheduler and the cache expect. A caller that only wanted to
// look would have to authenticate first anyway, so there is no read-only
// variant to reach for by mistake.
//
// The cell is left untouched whenever Open returns an error -- not only on a
// failed tag, but on a wrong sender slot or malformed metadata, which are
// checked after decryption. A caller that ignores the error therefore holds
// ciphertext, never plaintext it was refused.
func Open(cell *fabric.Cell, expectedSender uint16, key [32]byte, context Context) (Metadata, error) {
	if cell == nil {
		return Metadata{}, errors.New("cell is required")
	}
	if err := validateAuthentication(key, context); err != nil {
		return Metadata{}, err
	}
	header := cell[CiphertextSize:]
	if string(header[0:4]) != string(wireMagic[:]) {
		return Metadata{}, errors.New("unsupported hop header")
	}
	expectedTag := authenticationTag(*cell, key, context)
	if subtle.ConstantTimeCompare(header[tagOffset:], expectedTag[:]) != 1 {
		return Metadata{}, errors.New("hop authentication failed")
	}
	sequence := binary.BigEndian.Uint32(header[sequenceOffset : sequenceOffset+4])
	if sequence == 0 {
		return Metadata{}, errors.New("hop sequence must be non-zero")
	}

	stream, err := linkStream(key, context, sequence)
	if err != nil {
		return Metadata{}, err
	}
	// Decrypt into a copy and commit only once every check has passed. The
	// tag is not the last check -- the sender slot and the metadata shape are
	// still ahead -- and a caller that ignores the error must not be left
	// holding plaintext it was told it could not have.
	decrypted := *cell
	decryptedHeader := decrypted[CiphertextSize:]
	stream.XORKeyStream(decrypted[:CiphertextSize], decrypted[:CiphertextSize])
	stream.XORKeyStream(decryptedHeader[sealedOffset:sealedOffset+sealedSize],
		decryptedHeader[sealedOffset:sealedOffset+sealedSize])

	metadata := decodeSealed(decryptedHeader[sealedOffset : sealedOffset+sealedSize])
	metadata.Sequence = sequence
	if metadata.Sender != expectedSender {
		return Metadata{}, errors.New("authenticated sender slot mismatch")
	}
	if err := validateMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	// An opened cell is a local cell: Seal turns a local header into a wire
	// header, and Open turns it back. Rewriting it here is what lets a
	// relayed cell go straight into the scheduler, and it means no cell in
	// memory ever carries a wire header that nothing will re-seal.
	encodeLocalHeader(decrypted[CiphertextSize:], metadata)
	*cell = decrypted
	return metadata, nil
}

func Ciphertext(cell fabric.Cell) [CiphertextSize]byte {
	var payload [CiphertextSize]byte
	copy(payload[:], cell[:CiphertextSize])
	return payload
}

// FromCiphertext rebuilds a local, unsealed cell from a payload that arrived
// on another link. Relaying it means sealing it again for the next peer, under
// that link's own key and its own sequence number, which is what stops a
// relayed cell from carrying anything recognisable from the hop it came in on.
func FromCiphertext(payload [CiphertextSize]byte, metadata Metadata) (fabric.Cell, error) {
	var cell fabric.Cell
	copy(cell[:CiphertextSize], payload[:])
	if err := SetMetadata(&cell, metadata); err != nil {
		return fabric.Cell{}, err
	}
	return cell, nil
}

func StreamFor(payloads [][CiphertextSize]byte) (StreamID, error) {
	if len(payloads) < 2 || len(payloads) > MaximumBatch {
		return StreamID{}, errors.New("stream payload count is outside the supported batch range")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("nomad-live-stream-v1"))
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], uint16(len(payloads)))
	_, _ = hash.Write(count[:])
	for _, payload := range payloads {
		_, _ = hash.Write(payload[:])
	}
	var stream StreamID
	copy(stream[:], hash.Sum(nil))
	return stream, nil
}

func encodeSealed(destination []byte, metadata Metadata) {
	binary.BigEndian.PutUint16(destination[0:2], metadata.Sender)
	binary.BigEndian.PutUint16(destination[2:4], metadata.Ordinal)
	binary.BigEndian.PutUint16(destination[4:6], metadata.BatchSize)
	binary.BigEndian.PutUint16(destination[6:8], metadata.Flags)
	copy(destination[8:24], metadata.Stream[:])
}

func decodeSealed(source []byte) Metadata {
	metadata := Metadata{
		Sender:    binary.BigEndian.Uint16(source[0:2]),
		Ordinal:   binary.BigEndian.Uint16(source[2:4]),
		BatchSize: binary.BigEndian.Uint16(source[4:6]),
		Flags:     binary.BigEndian.Uint16(source[6:8]),
	}
	copy(metadata.Stream[:], source[8:24])
	return metadata
}

func encodeLocalHeader(destination []byte, metadata Metadata) {
	copy(destination[0:4], localMagic[:])
	binary.BigEndian.PutUint16(destination[4:6], metadata.Ordinal)
	binary.BigEndian.PutUint16(destination[6:8], metadata.BatchSize)
	binary.BigEndian.PutUint16(destination[8:10], metadata.Flags)
	copy(destination[10:26], metadata.Stream[:])
	clear(destination[26:HeaderSize])
}

func decodeLocalHeader(source []byte) (Metadata, error) {
	if len(source) != HeaderSize || string(source[0:4]) != string(localMagic[:]) {
		return Metadata{}, errors.New("not an unsealed hop header")
	}
	metadata := Metadata{
		Ordinal:   binary.BigEndian.Uint16(source[4:6]),
		BatchSize: binary.BigEndian.Uint16(source[6:8]),
		Flags:     binary.BigEndian.Uint16(source[8:10]),
	}
	copy(metadata.Stream[:], source[10:26])
	if err := validateMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func validateMetadata(metadata Metadata) error {
	if metadata.Flags&^FlagWork != 0 {
		return errors.New("unsupported hop flags")
	}
	if IsWork(metadata) {
		if metadata.Stream == (StreamID{}) {
			return errors.New("work cell has an empty stream ID")
		}
		if metadata.BatchSize < 2 || metadata.BatchSize > MaximumBatch || metadata.Ordinal >= metadata.BatchSize {
			return errors.New("work cell has invalid batch coordinates")
		}
		return nil
	}
	if metadata.Stream != (StreamID{}) || metadata.Ordinal != 0 || metadata.BatchSize != 0 {
		return errors.New("cover cell carries work metadata")
	}
	return nil
}

// bindContext writes the fields that must be identical on both sides for a
// cell to authenticate. Every variable-length field is length prefixed, so no
// two different contexts produce the same bytes.
func bindContext(mac interface{ Write([]byte) (int, error) }, context Context) {
	_, _ = mac.Write(context.TopologyDigest[:])
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], context.Epoch)
	_, _ = mac.Write(integer[:])
	binary.BigEndian.PutUint16(integer[:2], context.Receiver)
	_, _ = mac.Write(integer[:2])
	binary.BigEndian.PutUint16(integer[:2], uint16(len(context.NetworkID)))
	_, _ = mac.Write(integer[:2])
	_, _ = mac.Write([]byte(context.NetworkID))
}

// linkStream derives the keystream one cell is encrypted with.
//
// A counter-mode stream is safe here precisely because no two cells on one
// link share an input. The sequence number comes from a durable reservation
// that never reissues a value within an epoch -- that is what FileSequence
// exists for, and why exhaustion rotates the epoch rather than wrapping -- and
// the epoch, receiver and topology digest are bound alongside it. Reusing a
// sequence would reuse a keystream, which is why the sequence is the one thing
// this package refuses to be flexible about.
//
// The label differs from the tag's, so the same pairwise key serves both
// without either being derivable from the other.
//
// The keystream is HMAC-SHA-256 in counter mode rather than a block cipher.
// That is a protocol decision, not a performance one: it means an
// implementation needs SHA-256 and nothing else to speak this wire format --
// no AES, no cipher library. The second implementation in
// conformance/reference/ is written against the Python standard library, which
// has HMAC and no AES, and a wire format only implementable by importing a
// crypto library is a wire format with a hidden dependency. At twenty cells
// per second per link the arithmetic is free.
func linkStream(key [32]byte, context Context, sequence uint32) (cipher.Stream, error) {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(streamKeyLabel))
	bindContext(mac, context)
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], sequence)
	_, _ = mac.Write(encoded[:])
	var cellKey [32]byte
	copy(cellKey[:], mac.Sum(nil))
	return &counterStream{key: cellKey, offset: keystreamBlockSize}, nil
}

const keystreamBlockSize = sha256.Size

// counterStream expands one per-cell key into as many bytes as the cell needs.
// Block i is HMAC-SHA-256(cellKey, i), and the stream keeps its position
// across calls so that two regions of one cell are encrypted as though they
// were contiguous.
type counterStream struct {
	key     [32]byte
	counter uint32
	block   [keystreamBlockSize]byte
	offset  int
}

func (stream *counterStream) XORKeyStream(destination, source []byte) {
	for index := range source {
		if stream.offset == keystreamBlockSize {
			mac := hmac.New(sha256.New, stream.key[:])
			var encoded [4]byte
			binary.BigEndian.PutUint32(encoded[:], stream.counter)
			_, _ = mac.Write(encoded[:])
			copy(stream.block[:], mac.Sum(nil))
			stream.counter++
			stream.offset = 0
		}
		destination[index] = source[index] ^ stream.block[stream.offset]
		stream.offset++
	}
}

func authenticationTag(cell fabric.Cell, key [32]byte, context Context) [TagSize]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(headerTagLabel))
	bindContext(mac, context)
	_, _ = mac.Write(cell[:CiphertextSize+tagOffset])
	full := mac.Sum(nil)
	var tag [TagSize]byte
	copy(tag[:], full)
	return tag
}

func validateAuthentication(key [32]byte, context Context) error {
	if key == ([32]byte{}) {
		return errors.New("all-zero hop key is forbidden")
	}
	if context.TopologyDigest == ([32]byte{}) || context.NetworkID == "" || context.Epoch == 0 {
		return errors.New("hop authentication context is incomplete")
	}
	return nil
}

func (metadata Metadata) String() string {
	return fmt.Sprintf("sender=%d stream=%x ordinal=%d/%d sequence=%d", metadata.Sender, metadata.Stream, metadata.Ordinal, metadata.BatchSize, metadata.Sequence)
}
