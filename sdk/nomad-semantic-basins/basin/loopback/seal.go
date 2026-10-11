package loopback

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// The embedding service is the one component in this system that is handed a
// reader's query in the clear, and until now nothing established who it was.
// The client sent the query, and a bearer token meant to protect it, to
// whatever process happened to be listening on the configured loopback port.
// A process that binds that port first -- after a crash, on a shared machine,
// or simply by starting earlier -- received every query and the credential.
// The URL checks in embedder.go establish that the destination is loopback;
// they say nothing about who is listening there.
//
// A challenge-response handshake before the query is sent looks like the
// answer and is not one. It proves that somebody holding the key is reachable,
// not that the party about to receive the query is that somebody: an impostor
// on the configured port can forward the challenge to the real service on
// another port, return the real answer, and then take the query. It also
// leaves the other direction untouched, and that direction matters -- an
// impostor that answers with a chosen vector chooses the reader's basin, and
// so chooses which part of the catalogue that reader fetches. basin.Attest
// checks that the service behaves consistently; it assumes the answers came
// from the service.
//
// So the query is sealed to the service key rather than gated on it. An
// impostor that does not hold the key cannot read the request and cannot forge
// a response, whether it relays the traffic or invents it, and the same
// mechanism authenticates both directions.
//
// This makes the service a Nomad-aware component rather than an off-the-shelf
// model server. That is already true of any deployment that wants the property
// at all, and Service in service.go is the shim that provides it.

const (
	// SealedPath is where a service accepts sealed embedding requests.
	SealedPath = "/nomad-embed"

	// MinimumServiceKeyBytes is the shortest service key accepted. It is the
	// HKDF secret behind every request and response, so it is the strength of
	// the whole arrangement, and a short one is guessable offline from a
	// single captured request.
	MinimumServiceKeyBytes = 32

	sealVersion  = 0x01
	sealLabel    = "nomad-embed-v1"
	requestInfo  = "nomad-embed-request-v1"
	responseInfo = "nomad-embed-response-v1"
	saltBytes    = 32

	// paddingBlock rounds every sealed plaintext up to a multiple of this
	// many bytes. AEAD hides the content and not the length, and the length
	// of a query is information about the query.
	paddingBlock = 256

	// maxSealedBytes bounds what either side will attempt to open, so a
	// malformed or hostile peer cannot make the other allocate without limit.
	maxSealedBytes = 1 << 20
)

// ErrUnsealFailed reports that a sealed payload did not open under the service
// key. It is one error for every cause on purpose: which check failed is
// information for whoever produced the payload, and they are not entitled to
// it.
var ErrUnsealFailed = errors.New("sealed embedding payload could not be opened with the service key")

func checkServiceKey(serviceKey []byte) error {
	if len(serviceKey) < MinimumServiceKeyBytes {
		return fmt.Errorf("embedding service key must be at least %d bytes, and no "+
			"query is sent without one", MinimumServiceKeyBytes)
	}
	return nil
}

// newSalt draws the per-request salt that makes each derived key unique.
func newSalt() ([]byte, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("sealed embedding salt: %w", err)
	}
	return salt, nil
}

// sealedAEAD derives the key for one direction of one request.
//
// The salt is fresh per request and the info string differs per direction, so
// no two messages share a key: a request key never opens a response, and a
// response captured from one request never opens under another's key. That is
// what allows the fixed all-zero GCM nonce below -- the nonce must not repeat
// under a given key, and no key here is used for a second message.
func sealedAEAD(serviceKey, salt []byte, info string) (cipher.AEAD, error) {
	if err := checkServiceKey(serviceKey); err != nil {
		return nil, err
	}
	if len(salt) != saltBytes {
		return nil, fmt.Errorf("sealed embedding salt must be %d bytes", saltBytes)
	}
	derived, err := hkdf.Key(sha256.New, serviceKey, salt, info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealedAAD(direction string, salt []byte) []byte {
	aad := make([]byte, 0, len(sealLabel)+1+len(direction)+len(salt))
	aad = append(aad, sealLabel...)
	aad = append(aad, 0)
	aad = append(aad, direction...)
	return append(aad, salt...)
}

func seal(serviceKey, salt []byte, info, direction string, payload []byte) ([]byte, error) {
	aead, err := sealedAEAD(serviceKey, salt, info)
	if err != nil {
		return nil, err
	}
	padded, err := pad(payload)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, padded, sealedAAD(direction, salt)), nil
}

func unseal(serviceKey, salt []byte, info, direction string, sealed []byte) ([]byte, error) {
	aead, err := sealedAEAD(serviceKey, salt, info)
	if err != nil {
		return nil, err
	}
	if len(sealed) > maxSealedBytes {
		return nil, ErrUnsealFailed
	}
	nonce := make([]byte, aead.NonceSize())
	padded, err := aead.Open(nil, nonce, sealed, sealedAAD(direction, salt))
	if err != nil {
		return nil, ErrUnsealFailed
	}
	payload, err := unpad(padded)
	if err != nil {
		return nil, ErrUnsealFailed
	}
	return payload, nil
}

// pad prefixes the true length and rounds up to a whole number of blocks, so
// the sealed size reveals only which block the payload fell in.
func pad(payload []byte) ([]byte, error) {
	if len(payload) > maxSealedBytes {
		return nil, errors.New("sealed embedding payload is too large")
	}
	total := 4 + len(payload)
	if remainder := total % paddingBlock; remainder != 0 {
		total += paddingBlock - remainder
	}
	padded := make([]byte, total)
	binary.BigEndian.PutUint32(padded[:4], uint32(len(payload)))
	copy(padded[4:], payload)
	return padded, nil
}

func unpad(padded []byte) ([]byte, error) {
	if len(padded) < 4 || len(padded)%paddingBlock != 0 {
		return nil, errors.New("sealed embedding payload is malformed")
	}
	length := int(binary.BigEndian.Uint32(padded[:4]))
	if length < 0 || 4+length > len(padded) {
		return nil, errors.New("sealed embedding payload length is out of range")
	}
	return padded[4 : 4+length], nil
}
