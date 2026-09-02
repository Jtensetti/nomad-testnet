package conformance

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// decodeVector maps a corpus message type to the production decoder for it.
// It returns whether the bytes were accepted and, when they were, the identity
// the decoder assigned them. Only formats whose decoder needs no external key
// material are listed; the rest are covered by their own packages' negative
// tests.
func decodeVector(message string, payload []byte) (bool, [32]byte) {
	switch message {
	case "topology-document-v3":
		authority := DeterministicKey("topology-authority").Public().(ed25519.PublicKey)
		verified, err := topology.Verify(payload, authority, time.Time{})
		return err == nil, verified.Digest
	default:
		return false, [32]byte{}
	}
}

func accepts(message string, payload []byte) bool {
	ok, _ := decodeVector(message, payload)
	return ok
}

func corpusVectors(t *testing.T) []Vector {
	t.Helper()
	vectors, err := All()
	if err != nil {
		t.Fatal(err)
	}
	return vectors
}

// Truncation. Every proper prefix of a published vector must be refused. A
// decoder that accepts a short message has read a field that is not there.
func TestTruncatedVectorsAreRefused(t *testing.T) {
	for _, vector := range corpusVectors(t) {
		if !accepts(vector.Message, mustHex(t, vector.Bytes)) {
			continue
		}
		payload := mustHex(t, vector.Bytes)
		// Sample prefixes rather than all of them: every eighth byte plus the
		// last, which is where an off-by-one lands.
		for cut := 0; cut < len(payload); cut += max(1, len(payload)/64) {
			if accepts(vector.Message, payload[:cut]) {
				t.Fatalf("%s: a %d-byte prefix of a %d-byte message was accepted",
					vector.Name, cut, len(payload))
			}
		}
		if accepts(vector.Message, payload[:len(payload)-1]) {
			t.Fatalf("%s: dropping the last byte was accepted", vector.Name)
		}
	}
}

// Extension. Trailing bytes after a complete message must be refused, or two
// different byte strings carry one meaning and a digest over the message no
// longer identifies it.
func TestExtendedVectorsAreRefused(t *testing.T) {
	for _, vector := range corpusVectors(t) {
		payload := mustHex(t, vector.Bytes)
		if !accepts(vector.Message, payload) {
			continue
		}
		_, identity := decodeVector(vector.Message, payload)
		for _, suffix := range [][]byte{{0x00}, []byte("{}"), []byte("null"), []byte("0")} {
			if accepts(vector.Message, append(append([]byte{}, payload...), suffix...)) {
				t.Fatalf("%s: trailing %q was accepted, so two documents share one encoding",
					vector.Name, suffix)
			}
		}
		// Incidental whitespace is a different matter. A document's identity
		// is its canonical form, not the bytes it arrived in, so tolerating a
		// stray newline is safe -- provided it really does not change what the
		// document is taken to be.
		for _, suffix := range [][]byte{{' '}, {'\n'}, []byte("\t\r\n")} {
			padded := append(append([]byte{}, payload...), suffix...)
			ok, paddedIdentity := decodeVector(vector.Message, padded)
			if ok && paddedIdentity != identity {
				t.Fatalf("%s: trailing %q changed the document's identity", vector.Name, suffix)
			}
		}
	}
}

// Mutation. Flipping any single bit of a signed message must be refused: the
// signature covers the content, so acceptance means something is outside it.
func TestSingleBitMutationsAreRefused(t *testing.T) {
	for _, vector := range corpusVectors(t) {
		payload := mustHex(t, vector.Bytes)
		if !accepts(vector.Message, payload) {
			continue
		}
		for index := 0; index < len(payload); index += max(1, len(payload)/128) {
			for _, bit := range []byte{0x01, 0x80} {
				mutated := append([]byte{}, payload...)
				mutated[index] ^= bit
				if accepts(vector.Message, mutated) {
					t.Fatalf("%s: flipping bit %#x of byte %d was accepted",
						vector.Name, bit, index)
				}
			}
		}
	}
}

// Ambiguity. A JSON document has many byte strings for one value. Reordering
// keys or re-indenting is harmless: every parser reads the same document, and
// identity here is the canonical form rather than the received bytes, so those
// must either be refused or map to the same identity.
//
// A duplicate key is not harmless. Go keeps the last occurrence; other parsers
// keep the first, reject, or error. A signature check cannot catch it, because
// each implementation verifies against whatever it parsed -- so one accepts a
// document another refuses, and they cannot agree on what was signed. It must
// be refused outright.
func TestAmbiguousJSONRepresentationsAreRefusedOrCanonical(t *testing.T) {
	for _, vector := range corpusVectors(t) {
		payload := mustHex(t, vector.Bytes)
		if vector.Message != "topology-document-v3" {
			continue
		}
		accepted, identity := decodeVector(vector.Message, payload)
		if !accepted {
			t.Fatalf("%s: the published vector does not verify", vector.Name)
		}
		text := string(payload)

		var value map[string]any
		if err := json.Unmarshal(payload, &value); err != nil {
			t.Fatalf("%s: published vector is not JSON: %v", vector.Name, err)
		}
		// Go sorts map keys when marshalling, which is a different order from
		// the struct field order the document was produced in.
		reordered, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for name, variant := range map[string][]byte{
			"key order changed":    reordered,
			"indented re-encoding": mustIndent(t, payload),
			"leading whitespace":   append([]byte("  \n\t"), payload...),
		} {
			if string(variant) == text {
				t.Fatalf("%s: %s produced identical bytes; the case proves nothing",
					vector.Name, name)
			}
			ok, variantIdentity := decodeVector(vector.Message, variant)
			if ok && variantIdentity != identity {
				t.Fatalf("%s: %s verified as a different document", vector.Name, name)
			}
		}

		// A base64 field with a newline in it. Go's decoder ignores CR and LF
		// wherever they appear and Strict() does not change that, so this
		// verified here while the reference -- which decodes with
		// validate=True -- refused it: one signed topology, two answers. The
		// signature cannot object, because the signature field is not covered
		// by the signature. See EVIDENCE_INDEX F-18.
		//
		// Built by re-serialising the parsed document rather than by editing
		// the text: the vector is pretty-printed, and a replace aimed at
		// compact JSON matches nothing and reports success for it.
		signature, ok := value["signature"].(string)
		if !ok || signature == "" {
			t.Fatalf("%s: the vector carries no signature to mutate", vector.Name)
		}
		withNewline := map[string]any{}
		for key, held := range value {
			withNewline[key] = held
		}
		withNewline["signature"] = signature[:8] + "\n" + signature[8:]
		spaced, err := json.Marshal(withNewline)
		if err != nil {
			t.Fatal(err)
		}
		if accepts(vector.Message, spaced) {
			t.Fatalf("%s: a topology whose signature field carries a newline was "+
				"accepted; the reference refuses it, so the two implementations "+
				"disagree about whether this document is valid", vector.Name)
		}

		duplicate := "{\n  \"document\": null,\n" + text[2:]
		if duplicate == text {
			t.Fatalf("%s: could not build a duplicate-key case", vector.Name)
		}
		if accepts(vector.Message, []byte(duplicate)) {
			t.Fatalf("%s: a document carrying \"document\" twice was accepted; a parser "+
				"that keeps the first occurrence would read a different document from "+
				"the same signed bytes", vector.Name)
		}
	}
}

func mustHex(t *testing.T, encoded string) []byte {
	t.Helper()
	payload, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func mustIndent(t *testing.T, payload []byte) []byte {
	t.Helper()
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(value, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	return indented
}
