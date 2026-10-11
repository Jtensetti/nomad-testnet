package objectstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Jtensetti/nomad-browser/internal/demotrust"
)

func demoCatalog(t *testing.T) []Envelope {
	t.Helper()
	path := filepath.Join("..", "macos", "Sources", "NomadBrowser", "Resources", "demo-catalog.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the corpus the Swift client ships: %v", err)
	}
	var envelopes []Envelope
	if err := json.Unmarshal(data, &envelopes); err != nil {
		t.Fatal(err)
	}
	if len(envelopes) == 0 {
		t.Fatal("the shared corpus is empty, so it proves nothing about either implementation")
	}
	return envelopes
}

// The corpus the Swift client renders must be a corpus this implementation
// renders. A second implementation that refuses the first one's catalog is a
// parser differential, whichever of the two is right.
func TestTheGoVerifierAcceptsTheCorpusTheSwiftClientShips(t *testing.T) {
	trusted, err := ParseTrustSet(demotrust.PublisherKey)
	if err != nil {
		t.Fatal(err)
	}
	envelopes := demoCatalog(t)
	seen := map[string]struct{}{}
	for index, envelope := range envelopes {
		object, err := Verify(envelope, trusted)
		if err != nil {
			t.Fatalf("corpus entry %d was refused: %v", index, err)
		}
		if _, duplicate := seen[object.ID]; duplicate {
			t.Fatalf("corpus entry %d repeats an earlier object", index)
		}
		seen[object.ID] = struct{}{}
	}
	t.Logf("verified %d shared corpus objects", len(envelopes))
}

// Both implementations bound the same document fields, but count differently:
// Swift counts grapheme clusters, this counts runes, and a grapheme cluster is
// one or more runes. So this side's count is never lower, which makes it the
// stricter of the two -- a document accepted here is accepted there.
//
// The direction is what matters. If it ever inverted, this implementation
// could render a document the Swift client rejects as oversize, and the two
// clients would disagree about what a valid object is.
func TestTheRuneBoundIsNeverLooserThanAGraphemeBound(t *testing.T) {
	// Each string below is one grapheme cluster made of several runes: a
	// combining sequence, an emoji with a modifier, and a regional indicator
	// pair. Swift would count 1 for each; this counts what utf8 reports.
	for _, cluster := range []string{"é", "\U0001F468\u200d\U0001F4BB", "\U0001F1F8\U0001F1EA"} {
		runes := utf8.RuneCountInString(cluster)
		if runes < 1 {
			t.Fatalf("%q counts %d runes", cluster, runes)
		}
		// One grapheme, so Swift's count is 1. The rune count must be at
		// least that, or this side would be the looser of the two.
		if runes < 1 {
			t.Fatalf("rune count %d is below the grapheme count for %q", runes, cluster)
		}
	}

	// The bound itself: a title of MaxTitleRunes combining sequences is
	// MaxTitleRunes graphemes, which Swift accepts, and 2*MaxTitleRunes runes,
	// which this refuses. Being stricter is allowed; the test records that it
	// happens so it is a known divergence rather than a surprise.
	title := strings.Repeat("é", MaxTitleRunes)
	document := validDocument()
	document.Title = title
	if _, err := parseDocument(mustPayload(t, document)); err == nil {
		t.Fatal("a title of MaxTitleRunes graphemes was accepted; this side is " +
			"supposed to be the stricter one, so the bound has moved")
	}
}

func mustPayload(t *testing.T, document Document) []byte {
	t.Helper()
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// This implementation refuses unknown fields; Swift's JSONDecoder ignores
// them. That is a real divergence in the accept direction, and it is recorded
// here rather than left to be discovered: an object with an extra field
// renders on macOS and does not render on Linux.
//
// Refusing is the correct behaviour -- an unknown field in a signed document
// is how one object grows a second meaning -- so the fix belongs on the Swift
// side. Until it lands, this test is the statement of what differs.
func TestUnknownPayloadFieldsAreRefusedHereAndAcceptedBySwift(t *testing.T) {
	var raw map[string]any
	if err := json.Unmarshal(mustPayload(t, validDocument()), &raw); err != nil {
		t.Fatal(err)
	}
	raw["futureField"] = "value"
	payload, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseDocument(payload); err == nil {
		t.Fatal("an unknown payload field was accepted, so the two implementations " +
			"now differ in the other direction and this note is stale")
	}
}
