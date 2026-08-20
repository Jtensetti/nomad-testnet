// Package conformance emits the golden-vector corpus for Nomad's wire
// protocol.
//
// It exists so that the frozen specification can be checked mechanically
// rather than read: every vector is produced by the production encoder, and
// the accompanying schema states the layout the vector must satisfy. A second
// implementation built from the specification alone (PROD-03) reproduces the
// same bytes or it is not conformant.
//
// Every vector is deterministic. Key material comes from a fixed seed and no
// vector depends on a clock or on system randomness, so regenerating the
// corpus on any machine yields byte-identical output and CI can diff it.
package conformance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Version is the corpus format version. It changes only when the shape of a
// vector record changes, never when a vector is added.
const Version = "nomad-conformance-v1"

// Vector is one golden encoding. Bytes is the authoritative artifact; Fields
// records what a conformant parser must recover from it, so a vector states
// both directions of the encoding.
type Vector struct {
	Name        string            `json:"name"`
	Message     string            `json:"message"`
	Description string            `json:"description"`
	Bytes       string            `json:"bytes_hex"`
	Length      int               `json:"length"`
	Digest      string            `json:"sha256"`
	Fields      map[string]string `json:"fields,omitempty"`
}

// Corpus is the full published set.
type Corpus struct {
	Version string   `json:"version"`
	Vectors []Vector `json:"vectors"`
	Digest  string   `json:"corpus_sha256"`
}

// NewVector builds a vector and computes its digest.
func NewVector(message, name, description string, payload []byte, fields map[string]string) Vector {
	digest := sha256.Sum256(payload)
	return Vector{
		Name:        name,
		Message:     message,
		Description: description,
		Bytes:       hex.EncodeToString(payload),
		Length:      len(payload),
		Digest:      hex.EncodeToString(digest[:]),
		Fields:      fields,
	}
}

// Build assembles the corpus in a stable order and seals it with a digest
// over the ordered vector digests, so a single value pins the whole set.
func Build(vectors []Vector) (Corpus, error) {
	ordered := append([]Vector(nil), vectors...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Message != ordered[j].Message {
			return ordered[i].Message < ordered[j].Message
		}
		return ordered[i].Name < ordered[j].Name
	})
	seen := map[string]struct{}{}
	hash := sha256.New()
	_, _ = hash.Write([]byte(Version))
	for _, vector := range ordered {
		key := vector.Message + "/" + vector.Name
		if _, duplicate := seen[key]; duplicate {
			return Corpus{}, fmt.Errorf("duplicate vector %s", key)
		}
		seen[key] = struct{}{}
		_, _ = hash.Write([]byte(key))
		raw, err := hex.DecodeString(vector.Digest)
		if err != nil {
			return Corpus{}, err
		}
		_, _ = hash.Write(raw)
	}
	return Corpus{
		Version: Version,
		Vectors: ordered,
		Digest:  hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

// Encode renders the corpus as the published JSON artifact.
func Encode(corpus Corpus) ([]byte, error) {
	encoded, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// DeterministicKey derives a stable Ed25519 key from a label. Vectors must be
// reproducible on any machine, so no vector may use system randomness.
func DeterministicKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("nomad-conformance-key-v1:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// DeterministicBytes fills a buffer from a labelled counter stream, so filler
// content is reproducible and obviously not meaningful.
func DeterministicBytes(label string, length int) []byte {
	out := make([]byte, 0, length)
	var counter uint64
	for len(out) < length {
		block := sha256.New()
		_, _ = block.Write([]byte("nomad-conformance-bytes-v1:" + label))
		var suffix [8]byte
		binary.BigEndian.PutUint64(suffix[:], counter)
		_, _ = block.Write(suffix[:])
		out = append(out, block.Sum(nil)...)
		counter++
	}
	return out[:length]
}
