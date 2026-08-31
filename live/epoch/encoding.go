// Package epoch implements the EpochDescriptor v1 lifecycle from
// nomad-protocol docs/EPOCH_LIFECYCLE.md: canonical binary digests, chained
// descriptors wrapping the unchanged signed topology v3 and DKG certificate,
// activation/approval signatures, a persisted fail-closed chain store and the
// operator single-signature journal. Nothing in this package accepts reader
// queries, semantic identifiers or any other private state; every decision is
// a function of signed public documents and the caller-supplied clock.
package epoch

import (
	"encoding/binary"
	"errors"
)

// Canonical binary encoding for lifecycle digests and signatures: fixed field
// order, big-endian fixed-width integers, uint64 length prefixes for byte
// strings and lists, no floats, absent optional fields encode as zero length.
// JSON is transport/storage only and is never hashed or signed directly.

func appendUint64(out []byte, value uint64) []byte {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], value)
	return append(out, buffer[:]...)
}

func appendBytes(out, value []byte) []byte {
	out = appendUint64(out, uint64(len(value)))
	return append(out, value...)
}

func appendString(out []byte, value string) []byte {
	return appendBytes(out, []byte(value))
}

const maxCanonicalBytes = 4 << 20

func validCanonicalLength(length int) error {
	if length < 0 || length > maxCanonicalBytes {
		return errors.New("canonical field length is outside the supported range")
	}
	return nil
}
