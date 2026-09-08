package topology

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

// The signed topology is the trust boundary: it is the document that decides
// who the peers are, and it arrives from the network. It had no fuzz target.
//
// What is fuzzed is not the signature. The signature covers the canonical form
// rather than the transmitted bytes -- deliberately, so the format survives
// whitespace and key order -- which means byte-canonicality of the input is
// not a property this design has and asserting it would assert the wrong
// thing.
//
// What is asserted is that canonicalisation is deterministic and a fixed
// point: canonicalDocument must give the same bytes twice, its output must
// parse as a document, and canonicalising that must give those bytes again.
// A signer signs canonicalDocument(d) and a verifier checks against
// canonicalDocument(d') for the d' it parsed; if either step is unstable the
// two disagree about what was signed while believing they agree.
//
// Both halves were checked by mutation rather than by reading. Making the key
// comparator depend on how much had been written already fails on the seed
// corpus in under a second, printing the two orderings.
//
// **What this cannot see, established the same way.** Changing the escaper to
// write \u0009 where Go writes \t survived ninety seconds and two million
// executions, because that difference is internally consistent: the canonical
// form round-trips through it perfectly. An escaper that disagrees with
// another implementation is caught by the conformance corpus and its Python
// reader, not here. This target guards stability; that one guards agreement,
// and neither substitutes for the other.

// The seeds do not need a valid signature: this target is about
// canonicalisation, which happens before the signature is checked and does not
// depend on it. They need to be documents the strict decoder accepts, so the
// fuzzer starts from inside the shape rather than having to discover it.
func fuzzSeeds(f *testing.F) {
	f.Helper()
	document := Document{
		Version: Version, NetworkID: "fuzz", Epoch: 1,
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
		Traffic: TrafficClass{
			CellSize: CellSize, CellIntervalMillis: 25,
			MaxLatenessMillis: 100, QueueCapacity: 32,
		},
		DKG: DKGProfile{
			Threshold: 2, SessionID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			StartAt: "2026-01-01T00:00:00Z", PhaseDurationMillis: 1_000,
		},
		Operators: []Operator{{
			ID: "operator-a", Index: 0, Endpoint: "127.0.0.1:4200",
			PartialEndpoint: "http://127.0.0.1:4300",
			DKGEndpoint:     "http://127.0.0.1:4400",
			PeerPlan:        []uint16{0},
		}},
	}
	encoded, err := json.Marshal(Signed{Document: document})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		encoded,
		append(append([]byte{}, encoded...), ' '),
		[]byte(`{"document":{},"signature":""}`),
		[]byte("{}"),
		[]byte(""),
	} {
		f.Add(seed)
	}
}

func FuzzCanonicalisationIsIdempotent(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, encoded []byte) {
		// Whatever it is handed, the verifier must decide rather than panic.
		// The key is deliberately not the one the seed was signed with: this
		// arm is about the parse, and the parse happens first.
		_, _ = Verify(encoded, make(ed25519.PublicKey, ed25519.PublicKeySize), time.Unix(1_700_000_000, 0))

		var signed Signed
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&signed) != nil {
			return
		}

		once, err := canonicalDocument(signed.Document)
		if err != nil {
			// Canonicalisation refusing is a decision, not a defect. What it
			// must not do is refuse sometimes and accept sometimes.
			if _, second := canonicalDocument(signed.Document); second == nil {
				t.Fatalf("canonicalDocument refused once (%v) and accepted the same "+
					"document the next time", err)
			}
			return
		}
		twice, err := canonicalDocument(signed.Document)
		if err != nil {
			t.Fatalf("canonicalDocument accepted a document and then refused it: %v", err)
		}
		if !bytes.Equal(once, twice) {
			t.Fatalf("canonicalDocument is not deterministic:\n%s\n%s", once, twice)
		}

		// The signer signs this. A verifier parses the canonical bytes and
		// canonicalises what it parsed. If that is not the same bytes, the two
		// sign and check different messages while believing they agree.
		var reparsed Document
		if err := json.Unmarshal(once, &reparsed); err != nil {
			t.Fatalf("the canonical form of a document does not parse as one: %v\n%s",
				err, once)
		}
		again, err := canonicalDocument(reparsed)
		if err != nil {
			t.Fatalf("the canonical form of a document is not itself canonicalisable: %v", err)
		}
		if !bytes.Equal(once, again) {
			t.Fatalf("canonicalisation is not idempotent, so a signer and a verifier "+
				"can disagree about what was signed:\nfirst:  %s\nsecond: %s", once, again)
		}
	})
}
