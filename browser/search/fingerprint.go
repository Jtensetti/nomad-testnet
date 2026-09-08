package search

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// FingerprintLength is the hex width of a fingerprint, which is a SHA-256.
const FingerprintLength = 2 * sha256.Size

// ValidFingerprint refuses anything that is not a lowercase hex SHA-256.
//
// The check is strict because a fingerprint names a directory. Anything that
// can carry a separator, a dot segment or an uppercase spelling is either a
// path that escapes the index root or a second spelling of one identity, and
// the second is how two names end up pointing at one index.
func ValidFingerprint(fingerprint string) error {
	if fingerprint == "" {
		return errors.New("a search index requires a fingerprint; without one, two " +
			"models' embeddings would share a store and be compared with each other")
	}
	if len(fingerprint) != FingerprintLength {
		return fmt.Errorf("fingerprint is %d characters, want %d hex",
			len(fingerprint), FingerprintLength)
	}
	for index := 0; index < len(fingerprint); index++ {
		character := fingerprint[index]
		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'f':
		default:
			return fmt.Errorf("fingerprint is not lowercase hex at position %d", index)
		}
	}
	return nil
}

// lexicalDomain separates the baseline's fingerprint from any model's.
var lexicalDomain = []byte("nomad-search-lexical-v1")

// LexicalFingerprint identifies the lexical baseline.
//
// The baseline gets a fingerprint like anything else, so that an index always
// has one and no code path has to special-case its absence. It depends on the
// width, because a baseline at one width does not produce vectors comparable
// with the same baseline at another.
func LexicalFingerprint(dimensions int) string {
	digest := sha256.New()
	digest.Write(lexicalDomain)
	var width [8]byte
	binary.BigEndian.PutUint64(width[:], uint64(dimensions))
	digest.Write(width[:])
	return hex.EncodeToString(digest.Sum(nil))
}
