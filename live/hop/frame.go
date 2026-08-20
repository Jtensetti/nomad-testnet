// Package hop authenticates one fixed-size UDP hop without changing Nomad's
// 1200-byte cell size. The mix ciphertext occupies bytes 0..1151; its existing
// 48-byte padding is replaced by a versioned routing header and a truncated
// HMAC-SHA-256 tag. Mix parsing intentionally ignores that padding region.
package hop

import (
	"crypto/hmac"
	"crypto/sha256"
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
)

var magic = [4]byte{'N', 'H', 'C', 1}

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
// tag is deliberately zero; Seal must authenticate it for a concrete peer.
func SetMetadata(cell *fabric.Cell, metadata Metadata) error {
	if cell == nil {
		return errors.New("cell is required")
	}
	if err := validateMetadata(metadata); err != nil {
		return err
	}
	encodeHeader(cell[CiphertextSize:], metadata)
	clear(cell[CiphertextSize+HeaderSize-TagSize:])
	return nil
}

// MetadataFromCell reads only routing metadata. It never authenticates input;
// network callers must use Verify before acting on the returned values.
func MetadataFromCell(cell fabric.Cell) (Metadata, error) {
	metadata, _, err := decodeHeader(cell[CiphertextSize:])
	return metadata, err
}

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
	encodeHeader(cell[CiphertextSize:], metadata)
	tag := authenticationTag(*cell, key, context)
	copy(cell[CiphertextSize+HeaderSize-TagSize:], tag[:])
	return nil
}

func Verify(cell fabric.Cell, expectedSender uint16, key [32]byte, context Context) (Metadata, error) {
	if err := validateAuthentication(key, context); err != nil {
		return Metadata{}, err
	}
	metadata, observedTag, err := decodeHeader(cell[CiphertextSize:])
	if err != nil {
		return Metadata{}, err
	}
	if metadata.Sender != expectedSender {
		return Metadata{}, errors.New("authenticated sender slot mismatch")
	}
	if metadata.Sequence == 0 {
		return Metadata{}, errors.New("hop sequence must be non-zero")
	}
	if err := validateMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	expectedTag := authenticationTag(cell, key, context)
	if !hmac.Equal(observedTag, expectedTag[:]) {
		return Metadata{}, errors.New("hop authentication failed")
	}
	return metadata, nil
}

func Ciphertext(cell fabric.Cell) [CiphertextSize]byte {
	var payload [CiphertextSize]byte
	copy(payload[:], cell[:CiphertextSize])
	return payload
}

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

func encodeHeader(destination []byte, metadata Metadata) {
	copy(destination[0:4], magic[:])
	binary.BigEndian.PutUint16(destination[4:6], metadata.Sender)
	binary.BigEndian.PutUint16(destination[6:8], metadata.Ordinal)
	binary.BigEndian.PutUint16(destination[8:10], metadata.BatchSize)
	binary.BigEndian.PutUint16(destination[10:12], metadata.Flags)
	copy(destination[12:28], metadata.Stream[:])
	binary.BigEndian.PutUint32(destination[28:32], metadata.Sequence)
	clear(destination[32:48])
}

func decodeHeader(source []byte) (Metadata, []byte, error) {
	if len(source) != HeaderSize || string(source[0:4]) != string(magic[:]) {
		return Metadata{}, nil, errors.New("unsupported hop header")
	}
	metadata := Metadata{
		Sender:    binary.BigEndian.Uint16(source[4:6]),
		Ordinal:   binary.BigEndian.Uint16(source[6:8]),
		BatchSize: binary.BigEndian.Uint16(source[8:10]),
		Flags:     binary.BigEndian.Uint16(source[10:12]),
		Sequence:  binary.BigEndian.Uint32(source[28:32]),
	}
	copy(metadata.Stream[:], source[12:28])
	return metadata, source[32:48], nil
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

func authenticationTag(cell fabric.Cell, key [32]byte, context Context) [TagSize]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("nomad-hop-cell-v1"))
	_, _ = mac.Write(context.TopologyDigest[:])
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], context.Epoch)
	_, _ = mac.Write(integer[:])
	binary.BigEndian.PutUint16(integer[:2], context.Receiver)
	_, _ = mac.Write(integer[:2])
	binary.BigEndian.PutUint16(integer[:2], uint16(len(context.NetworkID)))
	_, _ = mac.Write(integer[:2])
	_, _ = mac.Write([]byte(context.NetworkID))
	_, _ = mac.Write(cell[:CiphertextSize+HeaderSize-TagSize])
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
