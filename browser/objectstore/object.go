// Package objectstore reads and verifies the signed objects a Nomad client
// renders.
//
// It is a second implementation of a boundary the Swift client already
// implements in macos/Sources/NomadBrowser/Models.swift. The two are written
// against the same corpus -- macos/Sources/NomadBrowser/Resources/demo-catalog.json,
// which conformance_test.go reads directly -- so an object accepted by one
// and refused by the other is visible rather than latent. Where the two are
// not identical the difference is stated at the constant or check that causes
// it, together with which direction it can fail in.
//
// Nothing here opens a file by a name the object supplied, follows a link, or
// consults the network. An object is a sequence of bytes on local disk that
// either verifies against a trusted publisher key or is discarded.
package objectstore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Limits on the encoded form. They bound the work an unverified object can
// cause before its signature has been checked, so they are deliberately
// applied while the bytes are still untrusted.
const (
	MaxEncodedEnvelopeBytes = 400_000
	MaxPayloadBytes         = 262_144
)

// Limits on the decoded document, counted in runes.
//
// The Swift verifier counts Swift Characters, which are grapheme clusters, and
// a grapheme cluster is one or more runes. A rune count is therefore never
// below the grapheme count, so a document this package accepts is one the
// Swift verifier also accepts: the two can disagree only by this side being
// stricter. conformance_test.go pins that direction.
const (
	MaxBodyRunes          = 200_000
	MaxTitleRunes         = 300
	MaxSummaryRunes       = 2_000
	MaxPublisherNameRunes = 200
	MaxPublishedAtRunes   = 64
	MaxTags               = 64
	MaxTagRunes           = 100
)

// RenderableMediaType is the only media type the client renders. The signed
// bundle binds it; a media type outside this set is refused rather than
// guessed at, because guessing is how a text object becomes an executable one.
const RenderableMediaType = "text/plain; charset=utf-8"

// objectDomain separates object signatures from every other Ed25519 signature
// in Nomad, so a signature minted for one purpose cannot be replayed as another.
var objectDomain = []byte("nomad-object-v1")

var (
	ErrUnsupportedVersion = errors.New("object version is not supported")
	ErrMalformedEncoding  = errors.New("object encoding is malformed")
	ErrObjectTooLarge     = errors.New("object exceeds its size limit")
	ErrCommitmentMismatch = errors.New("object does not match its SHA-256 commitment")
	ErrInvalidSignature   = errors.New("object signature is invalid")
	ErrUntrustedPublisher = errors.New("object publisher is not trusted by this client")
	ErrUnsupportedMedia   = errors.New("object media type is not renderable")
	ErrInvalidDocument    = errors.New("object document is invalid")
)

// Envelope is the on-disk form of a .nomadobject file.
type Envelope struct {
	Version      int    `json:"version"`
	Payload      string `json:"payload"`
	ContentHash  string `json:"contentHash"`
	PublisherKey string `json:"publisherKey"`
	Signature    string `json:"signature"`
}

// Document is the payload an envelope carries once verified.
type Document struct {
	Title         string   `json:"title"`
	Summary       string   `json:"summary"`
	Body          string   `json:"body"`
	Tags          []string `json:"tags"`
	PublishedAt   string   `json:"publishedAt"`
	PublisherName string   `json:"publisherName"`
	MediaType     string   `json:"mediaType"`
}

// Object is a document whose bytes, commitment, signature and publisher have
// all been checked. There is no constructor that produces one without those
// checks having run.
type Object struct {
	ID                   string
	Document             Document
	PublisherFingerprint string
}

// TrustSet is the set of publisher keys a client will render.
//
// It is a required argument rather than a package default: a client that
// rendered whatever was on disk when it had no anchors configured would be
// the silent fallback this design exists to remove.
type TrustSet struct {
	keys map[[ed25519.PublicKeySize]byte]struct{}
}

// NewTrustSet builds a trust set from raw 32-byte Ed25519 public keys.
func NewTrustSet(keys ...[]byte) (TrustSet, error) {
	if len(keys) == 0 {
		return TrustSet{}, errors.New("a trust set needs at least one publisher key")
	}
	set := TrustSet{keys: make(map[[ed25519.PublicKeySize]byte]struct{}, len(keys))}
	for _, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			return TrustSet{}, fmt.Errorf("publisher key is %d bytes, want %d",
				len(key), ed25519.PublicKeySize)
		}
		var fixed [ed25519.PublicKeySize]byte
		copy(fixed[:], key)
		set.keys[fixed] = struct{}{}
	}
	return set, nil
}

// ParseTrustSet builds a trust set from base64 publisher keys.
func ParseTrustSet(encoded ...string) (TrustSet, error) {
	raw := make([][]byte, 0, len(encoded))
	for _, text := range encoded {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
		if err != nil {
			return TrustSet{}, fmt.Errorf("publisher key is not base64: %w", err)
		}
		raw = append(raw, key)
	}
	return NewTrustSet(raw...)
}

func (t TrustSet) trusts(key []byte) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	var fixed [ed25519.PublicKeySize]byte
	copy(fixed[:], key)
	_, ok := t.keys[fixed]
	return ok
}

// Size reports how many publisher keys the set holds.
func (t TrustSet) Size() int { return len(t.keys) }

// Verify checks one envelope end to end and returns the object it carries.
//
// Every failure returns a sentinel error and no object. There is no partial
// result and no "verified except for" state: a caller cannot render bytes this
// function rejected, because it never receives them.
func Verify(envelope Envelope, trusted TrustSet) (Object, error) {
	if trusted.Size() == 0 {
		return Object{}, errors.New("verification requires a configured trust set")
	}
	if envelope.Version != 1 {
		return Object{}, ErrUnsupportedVersion
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return Object{}, ErrMalformedEncoding
	}
	if len(payload) > MaxPayloadBytes {
		return Object{}, ErrObjectTooLarge
	}
	publisherKey, err := base64.StdEncoding.DecodeString(envelope.PublisherKey)
	if err != nil || len(publisherKey) != ed25519.PublicKeySize {
		return Object{}, ErrMalformedEncoding
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Object{}, ErrMalformedEncoding
	}

	digest := sha256.Sum256(payload)
	commitment, err := hex.DecodeString(strings.ToLower(envelope.ContentHash))
	if err != nil || len(commitment) != sha256.Size {
		return Object{}, ErrMalformedEncoding
	}
	if subtle.ConstantTimeCompare(digest[:], commitment) != 1 {
		return Object{}, ErrCommitmentMismatch
	}

	// The signature covers the commitment, not the payload, so it binds the
	// exact bytes just checked against it.
	message := make([]byte, 0, len(objectDomain)+sha256.Size)
	message = append(message, objectDomain...)
	message = append(message, digest[:]...)
	if !ed25519.Verify(publisherKey, message, signature) {
		return Object{}, ErrInvalidSignature
	}
	if !trusted.trusts(publisherKey) {
		return Object{}, ErrUntrustedPublisher
	}

	document, err := parseDocument(payload)
	if err != nil {
		return Object{}, err
	}

	fingerprint := sha256.Sum256(publisherKey)
	return Object{
		ID:                   hex.EncodeToString(digest[:]),
		Document:             document,
		PublisherFingerprint: hex.EncodeToString(fingerprint[:])[:16],
	}, nil
}

func parseDocument(payload []byte) (Document, error) {
	var document Document
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, ErrInvalidDocument
	}
	// A payload carrying a second JSON value would let one object mean two
	// things to two parsers, which is the differential this rejects outright.
	if decoder.More() {
		return Document{}, ErrInvalidDocument
	}
	if document.MediaType != RenderableMediaType {
		return Document{}, ErrUnsupportedMedia
	}
	if strings.TrimSpace(document.Title) == "" {
		return Document{}, ErrInvalidDocument
	}
	for _, bound := range []struct {
		text  string
		limit int
	}{
		{document.Title, MaxTitleRunes},
		{document.Summary, MaxSummaryRunes},
		{document.Body, MaxBodyRunes},
		{document.PublisherName, MaxPublisherNameRunes},
		{document.PublishedAt, MaxPublishedAtRunes},
	} {
		if utf8.RuneCountInString(bound.text) > bound.limit {
			return Document{}, ErrInvalidDocument
		}
	}
	if len(document.Tags) > MaxTags {
		return Document{}, ErrInvalidDocument
	}
	for _, tag := range document.Tags {
		if utf8.RuneCountInString(tag) > MaxTagRunes {
			return Document{}, ErrInvalidDocument
		}
	}
	return document, nil
}
