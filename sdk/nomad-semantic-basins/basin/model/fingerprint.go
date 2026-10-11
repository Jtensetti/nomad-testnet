package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// fingerprintDomain separates this digest from every other SHA-256 in Nomad,
// so a fingerprint can never be mistaken for, or replayed as, another digest.
var fingerprintDomain = []byte("nomad-model-fingerprint-v1")

// Fingerprint identifies a model by what it computes, not by what it is called.
//
// A name is not enough. Two installations can both say "embeddinggemma-300m"
// and hold different weights, a different tokenizer, a different quantization
// or a different output width, and their embeddings are then not comparable at
// all -- while every label agrees. Anything that can move a vector is folded in
// here, so a change to any of it produces a different fingerprint and therefore
// a different index.
//
// Deliberately excluded: the model's id, version string, license, source,
// requirements and manifest revision. None of them changes a vector, and
// including them would force a reindex for an edited download URL.
func (m Manifest) Fingerprint() string {
	digest := sha256.Sum256(m.canonical())
	return hex.EncodeToString(digest[:])
}

// canonical is the byte string the fingerprint is taken over.
//
// Fixed field order, uint64 length prefixes, big-endian integers, no map
// iteration order. JSON is how a manifest is stored and moved; it is never
// what is hashed, because two JSON encodings of one manifest would otherwise
// be two fingerprints.
func (m Manifest) canonical() []byte {
	out := make([]byte, 0, 512)
	out = append(out, fingerprintDomain...)
	out = appendUint64(out, uint64(m.Schema))

	// What the model is.
	out = appendString(out, string(m.Runtime))
	out = appendString(out, m.Quantization)
	out = appendString(out, m.WeightsSHA256)
	out = appendString(out, m.TokenizerSHA256)

	// How it is driven. The adapter version is here because a change to how a
	// query is prefixed changes every vector the adapter has ever produced,
	// while leaving the weights and the tokenizer untouched.
	out = appendString(out, m.Adapter)
	out = appendUint64(out, uint64(m.AdapterVersion))

	// What comes out.
	out = appendUint64(out, uint64(m.NativeDimensions))
	out = appendUint64(out, uint64(m.Dimensions))
	out = appendBool(out, m.Normalize)
	out = appendUint64(out, uint64(m.MaxInputTokens))

	// Everything else that moves a vector. Sorted, so the map's iteration
	// order cannot reach the digest.
	keys := sortedKeys(m.InferenceSettings)
	out = appendUint64(out, uint64(len(keys)))
	for _, key := range keys {
		out = appendString(out, key)
		out = appendString(out, m.InferenceSettings[key])
	}
	return out
}

func appendUint64(out []byte, value uint64) []byte {
	return binary.BigEndian.AppendUint64(out, value)
}

func appendBytes(out, value []byte) []byte {
	out = appendUint64(out, uint64(len(value)))
	return append(out, value...)
}

func appendString(out []byte, value string) []byte {
	return appendBytes(out, []byte(value))
}

func appendBool(out []byte, value bool) []byte {
	if value {
		return append(out, 1)
	}
	return append(out, 0)
}
