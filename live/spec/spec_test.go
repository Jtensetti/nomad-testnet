// Package spec holds the test that keeps nomad-protocol docs/STATE_MACHINES.md
// honest.
//
// A specification nobody checks is a specification that drifts, and this
// project has already found two formats described wrongly in its own
// normative document -- the hop header, called padding, and the signed
// topology, not described at all. Both were found by trying to build a second
// implementation, which is an expensive way to discover that a number changed.
//
// So every value STATE_MACHINES.md states is asserted here against the code it
// describes. A change to either fails, and the failure names the document.
package spec

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/publish"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

const document_ = "nomad-protocol docs/STATE_MACHINES.md"

func equal[T comparable](t *testing.T, section string, actual, documented T) {
	t.Helper()
	if actual != documented {
		t.Errorf("%s: the code says %v and %s says %v", section, actual, document_, documented)
	}
}

// "A range of 2^20 is reserved durably before any number in it is used."
func TestSequenceReservationMatchesTheDocument(t *testing.T) {
	// Both nonce spaces are documented as behaving identically, so both are
	// checked. The values are unexported, so this measures them through the
	// only thing that can: how far a fresh sequence advances on reopening.
	directory := t.TempDir()
	for name, first := range map[string]func(string) (uint64, error){
		"hop": func(path string) (uint64, error) {
			sequence, err := hop.OpenFileSequence(path)
			if err != nil {
				return 0, err
			}
			value, err := sequence.Next()
			return uint64(value), err
		},
		"uplink": func(path string) (uint64, error) {
			sequence, err := uplink.OpenFileSequence(path)
			if err != nil {
				return 0, err
			}
			return sequence.Next()
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := directory + "/" + name
			opening, err := first(path)
			if err != nil {
				t.Fatal(err)
			}
			if opening != 1 {
				t.Errorf("a fresh %s sequence starts at %d, and zero is refused by seal "+
					"so it must start at 1", name, opening)
			}
			reopened, err := first(path)
			if err != nil {
				t.Fatal(err)
			}
			equal(t, "sequence reservation range", reopened-opening, uint64(1<<20))
		})
	}
}

// "The replay window holds the highest sequence seen and a 64-bit bitmap
// below it. Above the highest advances the window; within 64 below is
// accepted once; 64 or more below is refused."
func TestReplayWindowMatchesTheDocument(t *testing.T) {
	var window hop.ReplayWindow
	if err := window.Accept(1000); err != nil {
		t.Fatal(err)
	}
	if err := window.Accept(1001); err != nil {
		t.Fatal(err)
	}
	if err := window.Accept(1000); err == nil {
		t.Error("a sequence within the window was accepted twice")
	}
	// The documented edge: 63 below the highest is inside, 64 is not.
	if err := window.Accept(1001 - 63); err != nil {
		t.Errorf("63 below the highest was refused, and %s says within 64 is accepted "+
			"once: %v", document_, err)
	}
	if err := window.Accept(1001 - 64); err == nil {
		t.Errorf("64 below the highest was accepted, and %s says 64 or more below is "+
			"refused", document_)
	}
	if err := window.Accept(0); err == nil {
		t.Error("a zero sequence was accepted")
	}
}

// "The hop header is 48 bytes... the tag is 16." Sizes the document states in
// its wire section and that every second implementation depends on.
func TestWireSizesMatchTheDocument(t *testing.T) {
	equal(t, "mix ciphertext", hop.CiphertextSize, 1152)
	equal(t, "hop header", hop.HeaderSize, 48)
	equal(t, "hop tag", hop.TagSize, 16)
	equal(t, "cell", hop.CiphertextSize+hop.HeaderSize, 1200)
	equal(t, "maximum batch", hop.MaximumBatch, 256)
	equal(t, "publication fragment", publish.FragmentSize, 504)
	equal(t, "uplink payload", uplink.PayloadSize, publish.FragmentSize)
	equal(t, "uplink inner ciphertext", uplink.InnerSize, hop.CiphertextSize)
	equal(t, "uplink sequence prefix", uplink.SequenceSize, 8)
	equal(t, "topology cell size", topology.CellSize, 1200)
}

// "A release needs approvals from at least two distinct trusted keys." The
// browser's constant is not importable from here, so the document's own claim
// about the minimum is pinned where the value it constrains lives; this
// asserts the one this module owns.
func TestPublicationBoundsMatchTheDocument(t *testing.T) {
	equal(t, "maximum object", publish.MaximumObjectBytes, 262_144)
}

// "Four phases of equal, policy-set duration." The document says the DKG
// window is four phases long; topology validation is what enforces it. This
// checks the enforcement rather than the arithmetic -- an earlier version of
// this test asserted that four thirty-second phases are two minutes, which is
// true of arithmetic and says nothing about the code.
func TestTheDKGWindowIsFourPhasesInTheValidator(t *testing.T) {
	// A topology whose validity window ends exactly one phase short of four
	// must be refused; one that covers four must be accepted. Anything else
	// means the validator and the document disagree about the window.
	for name, phases := range map[string]int{"three phases": 3, "four phases": 4} {
		t.Run(name, func(t *testing.T) {
			draft, authority, identities := specTopology(t, phases)
			signed, err := topology.Sign(draft, authority, identities)
			refused := err != nil
			if !refused {
				encoded, encodeErr := topology.Encode(signed)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				_, verifyErr := topology.Verify(encoded,
					authority.Public().(ed25519.PublicKey), time.Time{})
				refused = verifyErr != nil
			}
			if phases < 4 && !refused {
				t.Errorf("a validity window covering %d DKG phases was accepted, and %s "+
					"says the window is four", phases, document_)
			}
			if phases >= 4 && refused {
				t.Errorf("a validity window covering %d DKG phases was refused, and %s "+
					"says four is enough", phases, document_)
			}
		})
	}
}
