package strictjson

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestABase64FieldHasExactlyOneEncoding(t *testing.T) {
	// Bytes chosen so the encoding contains both + and /, or the URL-safe case
	// below replaces nothing and passes for that reason.
	raw := []byte{0xfb, 0xef, 0xbe, 0xff, 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92}
	canonical := base64.StdEncoding.EncodeToString(raw)
	if !strings.ContainsAny(canonical, "+/") {
		t.Fatalf("the fixture encodes to %q, which has no + or /", canonical)
	}
	decoded, err := DecodeBase64(canonical)
	if err != nil {
		t.Fatalf("the canonical encoding was refused: %v", err)
	}
	if string(decoded) != string(raw) {
		t.Fatal("the canonical encoding did not round-trip")
	}

	// Each of these decodes to the same bytes under Go's decoder, and is
	// refused by the Python reference's validate=True. A document that means
	// one thing to one implementation and nothing to another is the ambiguity
	// this package exists to remove.
	for name, variant := range map[string]string{
		"an embedded newline":   canonical[:4] + "\n" + canonical[4:],
		"an embedded CRLF":      canonical[:4] + "\r\n" + canonical[4:],
		"a trailing newline":    canonical + "\n",
		"a leading newline":     "\n" + canonical,
		"embedded spaces":       canonical[:4] + " " + canonical[4:],
		"the URL-safe alphabet": strings.NewReplacer("+", "-", "/", "_").Replace(canonical),
	} {
		if variant == canonical {
			t.Fatalf("%s did not change the encoding, so the case tests nothing", name)
		}
		if _, err := DecodeBase64(variant); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// The control: without this package's check, Go accepts the newline. A test
// that only showed DecodeBase64 refusing would not establish that there was
// anything to refuse.
func TestGoesBeyondWhatStrictAlreadyRejects(t *testing.T) {
	canonical := base64.StdEncoding.EncodeToString([]byte("the bytes a field carries"))
	variant := canonical[:4] + "\n" + canonical[4:]
	if _, err := base64.StdEncoding.Strict().DecodeString(variant); err != nil {
		t.Skipf("the standard decoder already refuses an embedded newline (%v), "+
			"so this package adds nothing and should be reconsidered", err)
	}
}
