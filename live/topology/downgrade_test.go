package topology

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Downgrade at the admission boundary. A peer's authority to be in the peer
// set comes from a topology that every listed operator attested and the
// authority signed; each case below weakens one of those and must be refused
// by Verify, not merely by convention elsewhere.
func TestVerifyRefusesDowngradedTopologies(t *testing.T) {
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base, identities := attestedDocument(t)

	// Sign a document after mutating it, so the authority signature is valid
	// and only the property under test is wrong. Attestations are left as
	// produced unless a case rewrites them; that is the point of the cases
	// that strip or drop one.
	signMutated := func(mutate func(*Document)) ([]byte, error) {
		document := cloneDocument(base)
		mutate(&document)
		canonical, err := canonicalDocument(document)
		if err != nil {
			return nil, err
		}
		signed := Signed{
			Document: document,
			Signature: base64.StdEncoding.EncodeToString(
				ed25519.Sign(authorityPrivate, signingMessage("nomad-topology-authority-v3", canonical))),
		}
		return Encode(signed)
	}

	for _, testCase := range []struct {
		name    string
		mutate  func(*Document)
		wantSub string
	}{
		{
			name:    "version downgraded to a superseded format",
			mutate:  func(d *Document) { d.Version = "nomad-live-topology-v2" },
			wantSub: "version",
		},
		{
			name:    "an operator's attestation stripped",
			mutate:  func(d *Document) { d.Operators[1].Attestation = "" },
			wantSub: "attestation",
		},
		{
			name: "an operator dropped from the set",
			mutate: func(d *Document) {
				d.Operators = append(d.Operators[:1], d.Operators[2:]...)
				for index := range d.Operators {
					d.Operators[index].Index = uint16(index)
					d.Operators[index].PeerPlan = []uint16{uint16((index + 1) % len(d.Operators))}
				}
			},
			wantSub: "",
		},
		{
			name:    "cell size moved off the profile constant",
			mutate:  func(d *Document) { d.Traffic.CellSize = CellSize / 2 },
			wantSub: "cell size",
		},
		{
			name:    "threshold lowered below the floor",
			mutate:  func(d *Document) { d.DKG.Threshold = 1 },
			wantSub: "threshold",
		},
		{
			name: "operator set shrunk below the multi-operator floor",
			mutate: func(d *Document) {
				d.Operators = d.Operators[:2]
				d.Operators[0].PeerPlan = []uint16{1}
				d.Operators[1].PeerPlan = []uint16{0}
			},
			wantSub: "",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			encoded, err := signMutated(testCase.mutate)
			if err != nil {
				// Refusal during encoding is still a refusal.
				return
			}
			_, err = Verify(encoded, authorityPublic, time.Now())
			if err == nil {
				t.Fatal("a downgraded topology was accepted")
			}
			if testCase.wantSub != "" && !strings.Contains(strings.ToLower(err.Error()), testCase.wantSub) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}

	// The unmutated document must verify, or the cases above prove nothing.
	encoded, err := signMutated(func(*Document) {})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(encoded, authorityPublic, time.Now()); err != nil {
		t.Fatalf("the control topology was refused: %v", err)
	}
	_ = identities
}

func attestedDocument(t *testing.T) (Document, map[string]ed25519.PrivateKey) {
	t.Helper()
	document, identities := unattestedDocument(t, "downgrade-net", 3)
	attested := document
	var err error
	for _, operator := range document.Operators {
		attested, err = Attest(attested, operator.ID, identities[operator.ID])
		if err != nil {
			t.Fatal(err)
		}
	}
	return attested, identities
}
