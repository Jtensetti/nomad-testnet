package objectstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// signedEnvelope mints a real envelope, so the negative cases below start from
// something that verifies and break exactly one thing.
func signedEnvelope(t *testing.T, document Document) (Envelope, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	message := append(append([]byte{}, objectDomain...), digest[:]...)
	return Envelope{
		Version:      1,
		Payload:      base64.StdEncoding.EncodeToString(payload),
		ContentHash:  hex.EncodeToString(digest[:]),
		PublisherKey: base64.StdEncoding.EncodeToString(public),
		Signature:    base64.StdEncoding.EncodeToString(ed25519.Sign(private, message)),
	}, public
}

func validDocument() Document {
	return Document{
		Title:         "En signerad artikel",
		Summary:       "Kort sammanfattning",
		Body:          "Brodtext utan nagon natverksreferens.",
		Tags:          []string{"nomad", "test"},
		PublishedAt:   "2026-08-31",
		PublisherName: "Nomad Test Publisher",
		MediaType:     RenderableMediaType,
	}
}

func trustOnly(t *testing.T, key ed25519.PublicKey) TrustSet {
	t.Helper()
	set, err := NewTrustSet(key)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestAWellFormedObjectVerifies(t *testing.T) {
	envelope, key := signedEnvelope(t, validDocument())
	object, err := Verify(envelope, trustOnly(t, key))
	if err != nil {
		t.Fatalf("a correctly signed object was refused: %v", err)
	}
	if object.Document.Title != "En signerad artikel" {
		t.Fatalf("document did not survive verification: %+v", object.Document)
	}
	// The ID is the commitment, so it is reproducible from the payload alone.
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if object.ID != hex.EncodeToString(digest[:]) {
		t.Fatalf("object ID %q is not the payload commitment", object.ID)
	}
	if len(object.PublisherFingerprint) != 16 {
		t.Fatalf("publisher fingerprint is %q", object.PublisherFingerprint)
	}
}

// Each case breaks exactly one thing about an otherwise valid object, so a
// failure names the check that stopped working rather than "something".
func TestEveryVerificationFailureIsRefused(t *testing.T) {
	oversizeTitle := validDocument()
	oversizeTitle.Title = strings.Repeat("a", MaxTitleRunes+1)

	wrongMedia := validDocument()
	wrongMedia.MediaType = "text/html; charset=utf-8"

	blankTitle := validDocument()
	blankTitle.Title = "   \n\t "

	tooManyTags := validDocument()
	tooManyTags.Tags = make([]string, MaxTags+1)
	for i := range tooManyTags.Tags {
		tooManyTags.Tags[i] = "tag"
	}

	for _, testcase := range []struct {
		name    string
		mutate  func(*Envelope)
		docSwap *Document
		want    error
	}{
		{name: "an unsupported version", want: ErrUnsupportedVersion,
			mutate: func(e *Envelope) { e.Version = 2 }},
		{name: "a payload that is not base64", want: ErrMalformedEncoding,
			mutate: func(e *Envelope) { e.Payload = "!!!not base64!!!" }},
		{name: "a publisher key of the wrong length", want: ErrMalformedEncoding,
			mutate: func(e *Envelope) { e.PublisherKey = base64.StdEncoding.EncodeToString([]byte("short")) }},
		{name: "a signature of the wrong length", want: ErrMalformedEncoding,
			mutate: func(e *Envelope) { e.Signature = base64.StdEncoding.EncodeToString([]byte("short")) }},
		{name: "a commitment that is not hex", want: ErrMalformedEncoding,
			mutate: func(e *Envelope) { e.ContentHash = "zz" }},
		{name: "a commitment for different bytes", want: ErrCommitmentMismatch,
			mutate: func(e *Envelope) { e.ContentHash = strings.Repeat("ab", sha256.Size) }},
		{name: "a signature over a different object", want: ErrInvalidSignature,
			mutate: func(e *Envelope) {
				other, _ := signedEnvelope(t, Document{Title: "annat", MediaType: RenderableMediaType})
				e.Signature = other.Signature
			}},
		{name: "a title past its limit", want: ErrInvalidDocument, docSwap: &oversizeTitle},
		{name: "a blank title", want: ErrInvalidDocument, docSwap: &blankTitle},
		{name: "more tags than allowed", want: ErrInvalidDocument, docSwap: &tooManyTags},
		{name: "a media type the renderer does not accept", want: ErrUnsupportedMedia, docSwap: &wrongMedia},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			document := validDocument()
			if testcase.docSwap != nil {
				document = *testcase.docSwap
			}
			envelope, key := signedEnvelope(t, document)
			if testcase.mutate != nil {
				testcase.mutate(&envelope)
			}
			if _, err := Verify(envelope, trustOnly(t, key)); !errors.Is(err, testcase.want) {
				t.Fatalf("got %v, want %v", err, testcase.want)
			}
		})
	}
}

// A valid signature from a key this client does not anchor is still refused.
// Signature validity is not trust: anyone can mint a valid signature.
func TestAValidSignatureFromAnUnanchoredKeyIsRefused(t *testing.T) {
	envelope, _ := signedEnvelope(t, validDocument())
	stranger, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(envelope, trustOnly(t, stranger)); !errors.Is(err, ErrUntrustedPublisher) {
		t.Fatalf("got %v, want ErrUntrustedPublisher", err)
	}
}

// A client with nothing anchored renders nothing. The dangerous reading of an
// empty trust set is "no restriction configured"; this pins the other one.
func TestAnEmptyTrustSetVerifiesNothing(t *testing.T) {
	envelope, _ := signedEnvelope(t, validDocument())
	if _, err := Verify(envelope, TrustSet{}); err == nil {
		t.Fatal("an object verified against an empty trust set")
	}
	if _, err := NewTrustSet(); err == nil {
		t.Fatal("an empty trust set was constructed")
	}
}

// The object signature is domain-separated, so a signature minted over the
// bare commitment for some other purpose cannot be replayed as an object.
func TestASignatureWithoutTheObjectDomainIsRefused(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(validDocument())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	envelope := Envelope{
		Version:      1,
		Payload:      base64.StdEncoding.EncodeToString(payload),
		ContentHash:  hex.EncodeToString(digest[:]),
		PublisherKey: base64.StdEncoding.EncodeToString(public),
		Signature:    base64.StdEncoding.EncodeToString(ed25519.Sign(private, digest[:])),
	}
	if _, err := Verify(envelope, trustOnly(t, public)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v, want ErrInvalidSignature", err)
	}
}

// A payload carrying a trailing second JSON value is one object that means two
// things to two parsers. It is refused rather than read up to the first value.
func TestAPayloadWithATrailingValueIsRefused(t *testing.T) {
	body, err := json.Marshal(validDocument())
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{`{"title":"second"}`, `null`, `[]`} {
		payload := append(append([]byte{}, body...), []byte(suffix)...)
		if _, err := parseDocument(payload); !errors.Is(err, ErrInvalidDocument) {
			t.Fatalf("payload with trailing %s returned %v", suffix, err)
		}
	}
}

// An oversize payload is refused on its length, before it is parsed.
func TestAnOversizePayloadIsRefusedBeforeParsing(t *testing.T) {
	envelope, key := signedEnvelope(t, validDocument())
	envelope.Payload = base64.StdEncoding.EncodeToString(make([]byte, MaxPayloadBytes+1))
	if _, err := Verify(envelope, trustOnly(t, key)); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("got %v, want ErrObjectTooLarge", err)
	}
}
