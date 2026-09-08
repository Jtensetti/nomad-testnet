package topology

import (
	"encoding/json"
	"strings"
	"testing"
)

func canonicalise(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(encoded)
	if err != nil {
		t.Fatalf("canonicalJSON(%s): %v", encoded, err)
	}
	return string(canonical)
}

// The defect this encoding exists to remove. Go escapes these three characters
// by default and no JSON specification asks for it, so a second implementation
// signing the same document computed a different digest -- and only for
// documents containing one of three characters, which is the kind of bug that
// ships.
func TestCanonicalStringsDoNotCarryGosHTMLEscaping(t *testing.T) {
	raw, err := json.Marshal(map[string]string{"network_id": "a<b>c&d"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\\u003c") {
		t.Skip("encoding/json no longer escapes HTML by default; this test guarded a " +
			"defect that no longer exists")
	}
	got := canonicalise(t, map[string]string{"network_id": "a<b>c&d"})
	if got != `{"network_id":"a<b>c&d"}` {
		t.Fatalf("canonical form is %s", got)
	}
}

// Member order must come from the names, not from the order a struct happens
// to declare its fields, or inserting a field in the middle of a struct
// silently changes the signed bytes of every document.
func TestCanonicalMembersAreSortedByName(t *testing.T) {
	type declarationOrder struct {
		Zebra  string `json:"zebra"`
		Apple  string `json:"apple"`
		Middle string `json:"middle"`
	}
	got := canonicalise(t, declarationOrder{"z", "a", "m"})
	if got != `{"apple":"a","middle":"m","zebra":"z"}` {
		t.Fatalf("canonical form is %s", got)
	}

	// Order is by UTF-16 code unit, so a shorter name that is a prefix comes
	// first and case matters in the ASCII way.
	got = canonicalise(t, map[string]int{"a": 1, "ab": 2, "B": 3, "": 4})
	if got != `{"":4,"B":3,"a":1,"ab":2}` {
		t.Fatalf("canonical form is %s", got)
	}
}

func TestCanonicalAbsentArrayIsEmptyNotNull(t *testing.T) {
	type withSlice struct {
		Operators []string `json:"operators"`
	}
	if got := canonicalise(t, withSlice{}); got != `{"operators":[]}` {
		t.Fatalf("an absent array encoded as %s", got)
	}
	if got := canonicalise(t, withSlice{Operators: []string{}}); got != `{"operators":[]}` {
		t.Fatalf("an empty array encoded as %s", got)
	}
}

func TestCanonicalStringEscaping(t *testing.T) {
	cases := map[string]string{
		"plain":            `"plain"`,
		"quote\"inside":    `"quote\"inside"`,
		"back\\slash":      `"back\\slash"`,
		"tab\there":        `"tab\there"`,
		"line\nbreak":      `"line\nbreak"`,
		"return\rhere":     `"return\rhere"`,
		"\b\f":             `"\b\f"`,
		"unicode åäö":      "\"unicode åäö\"",
		"emoji \U0001F600": "\"emoji \U0001F600\"",
		"solidus/slash":    `"solidus/slash"`,
	}
	for input, expected := range cases {
		if got := canonicalise(t, input); got != expected {
			t.Errorf("%q encoded as %s, expected %s", input, got, expected)
		}
	}

	// Control characters without a short form take lowercase \u00xx.
	if got := canonicalise(t, "\x00\x1f"); got != "\"\\u0000\\u001f\"" {
		t.Errorf("control characters encoded as %s", got)
	}
}

// Refusing non-integers is what keeps this encoding out of the floating-point
// half of JSON canonicalization, where the subtleties are.
func TestCanonicalNumbersMustBeIntegers(t *testing.T) {
	for _, encoded := range []string{
		`{"epoch":1.5}`,
		`{"epoch":1e2}`,
		`{"epoch":1E2}`,
		`{"epoch":1.0}`,
		`{"epoch":-0}`,
		`{"epoch":01}`,
	} {
		if _, err := canonicalJSON([]byte(encoded)); err == nil {
			t.Errorf("%s was given a canonical form", encoded)
		}
	}
	for _, encoded := range []string{
		`{"epoch":0}`,
		`{"epoch":1}`,
		`{"epoch":-7}`,
		`{"epoch":18446744073709551615}`,
	} {
		canonical, err := canonicalJSON([]byte(encoded))
		if err != nil {
			t.Errorf("%s was refused: %v", encoded, err)
			continue
		}
		if string(canonical) != encoded {
			t.Errorf("%s canonicalised to %s", encoded, canonical)
		}
	}
}

// A uint64 above 2^53 must survive exactly. Decoding through float64 would
// silently round it, and an epoch is a uint64.
func TestCanonicalPreservesLargeIntegersExactly(t *testing.T) {
	type document struct {
		Epoch uint64 `json:"epoch"`
	}
	const large = uint64(9007199254740993) // 2^53 + 1
	got := canonicalise(t, document{Epoch: large})
	if got != `{"epoch":9007199254740993}` {
		t.Fatalf("a large epoch canonicalised to %s", got)
	}
}

func TestCanonicalRefusesTrailingContent(t *testing.T) {
	if _, err := canonicalJSON([]byte(`{"a":1}{"b":2}`)); err == nil {
		t.Fatal("two values were accepted as one")
	}
}

// The encoding is a fixed point: canonicalising a canonical form changes
// nothing. Without this, a document could round-trip into a different digest
// than the one it was signed under.
func TestCanonicalFormIsAFixedPoint(t *testing.T) {
	type nested struct {
		Zebra   string            `json:"zebra"`
		Apple   map[string]string `json:"apple"`
		Numbers []int             `json:"numbers"`
		Absent  []string          `json:"absent"`
		Awkward string            `json:"awkward"`
	}
	first := canonicalise(t, nested{
		Zebra:   "z",
		Apple:   map[string]string{"b": "2", "a": "1"},
		Numbers: []int{3, 1, 2},
		Awkward: "a<b>c&d\t\"\\",
	})
	second, err := canonicalJSON([]byte(first))
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != first {
		t.Fatalf("canonicalising twice changed the bytes:\n%s\n%s", first, second)
	}
	// Array order is data, not something to sort.
	if !strings.Contains(first, `"numbers":[3,1,2]`) {
		t.Fatalf("array order was not preserved: %s", first)
	}
}

// The escaping rule is currently unreachable through a valid document, and
// saying so is part of the specification rather than a reason to skip it.
//
// Every free-form string in a topology is constrained: the network identifier
// and operator identifiers by operatorIDPattern, endpoints by host:port and
// URL parsing, timestamps by RFC 3339, keys and the session identifier by
// base64. None of those alphabets contains <, > or &. So the escaping defect
// was latent, not live, and no corpus vector can exercise it without first
// loosening validation.
//
// It is still fixed, because "the canonical encoding is whatever this
// language's library does, and validation happens to keep the difference out
// of reach" is two invariants pretending to be one. Loosening a field is a
// change someone will make; a canonical encoding is not something they will
// check first.
func TestNoValidDocumentCanContainTheEscapedCharacters(t *testing.T) {
	for _, candidate := range []string{"a<b", "a>b", "a&b", "nomad<conformance>&test"} {
		if operatorIDPattern.MatchString(candidate) {
			t.Errorf("%q passes the identifier pattern, so the escaping rule is "+
				"reachable and the corpus should carry a vector for it", candidate)
		}
	}
}
