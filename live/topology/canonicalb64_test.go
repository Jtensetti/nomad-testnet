package topology

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// A base64 field must have exactly one encoding, for the same reason a JSON
// object must not carry a key twice.
//
// Go's base64 decoder ignores \r and \n wherever they appear, and Strict()
// does not change that. The Python reference decodes with validate=True and
// refuses them. So before this was closed, a topology carrying a newline
// inside its authority signature verified here and was refused there: two
// implementations disagreeing about whether a signed topology is valid, which
// is a split view of the operator set created by whoever distributes the file.
//
// The signature does not catch it. A newline inside a field that is part of
// the signed document changes the canonical form and fails the signature --
// that half was already safe. The signature field itself is excluded from
// what it signs, so nothing above it could object.
func TestABase64FieldInsideASignedTopologyHasOneEncoding(t *testing.T) {
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document, identities := unattestedDocument(t, "canonical-b64", 3)
	attested := document
	for _, operator := range document.Operators {
		attested, err = Attest(attested, operator.ID, identities[operator.ID])
		if err != nil {
			t.Fatal(err)
		}
	}
	signed, err := Finalize(attested, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(encoded, authorityPublic, time.Now()); err != nil {
		t.Fatalf("the unmodified topology must verify, or the cases below prove nothing: %v", err)
	}

	for name, field := range map[string]string{
		"the authority signature":  signed.Signature,
		"an operator identity key": signed.Document.Operators[0].IdentityKey,
		"an operator attestation":  signed.Document.Operators[0].Attestation,
	} {
		for variant, injected := range map[string]string{
			"a newline": field[:8] + "\n" + field[8:],
			"a CRLF":    field[:8] + "\r\n" + field[8:],
			"a space":   field[:8] + " " + field[8:],
		} {
			document := strings.Replace(string(encoded), field, injected, 1)
			if document == string(encoded) {
				t.Fatalf("injecting %s into %s changed nothing", variant, name)
			}
			if _, err := Verify([]byte(document), authorityPublic, time.Now()); err == nil {
				t.Fatalf("a topology carrying %s inside %s verified", variant, name)
			}
		}
	}
}
