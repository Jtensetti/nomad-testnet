package ceremony

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func TestIndependentOperatorTopologyCeremony(t *testing.T) {
	operatorIDs := []string{"operator-c", "operator-a", "operator-b"}
	secrets := make(map[string]topology.Secrets, len(operatorIDs))
	private := make(map[string]topology.PrivateKeys, len(operatorIDs))
	enrollments := make([]Enrollment, 0, len(operatorIDs))
	for index, id := range operatorIDs {
		secret, err := topology.GenerateSecrets(id)
		if err != nil {
			t.Fatal(err)
		}
		encodedSecret, err := topology.EncodeSecrets(secret)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := topology.DecodePrivateKeys(encodedSecret)
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := NewEnrollment(
			keys,
			[]string{"127.0.0.1:4203", "127.0.0.1:4201", "127.0.0.1:4202"}[index],
			[]string{"http://127.0.0.1:4303", "http://127.0.0.1:4301", "http://127.0.0.1:4302"}[index],
		)
		if err != nil {
			t.Fatal(err)
		}
		encodedEnrollment, err := EncodeEnrollment(enrollment)
		if err != nil {
			t.Fatal(err)
		}
		decodedEnrollment, err := DecodeEnrollment(encodedEnrollment)
		if err != nil {
			t.Fatal(err)
		}
		secrets[id], private[id] = secret, keys
		enrollments = append(enrollments, decodedEnrollment)
	}

	now := time.Now().UTC().Truncate(time.Second)
	draft, err := BuildDraft(enrollments, DraftConfig{
		NetworkID: "ceremony-test", Epoch: 9,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: 20,
			MaxLatenessMillis: 80, QueueCapacity: 64,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if draft.Operators[0].ID != "operator-a" || draft.Operators[2].ID != "operator-c" {
		t.Fatal("draft membership is not deterministically ordered")
	}
	encodedDraft, err := EncodeDraft(draft)
	if err != nil {
		t.Fatal(err)
	}
	draft, err = DecodeDraft(encodedDraft)
	if err != nil {
		t.Fatal(err)
	}

	attestations := make([]Attestation, 0, len(draft.Operators))
	for _, operator := range draft.Operators {
		attestation, err := CreateAttestation(draft, private[operator.ID])
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeAttestation(attestation)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeAttestation(encoded)
		if err != nil {
			t.Fatal(err)
		}
		attestations = append(attestations, decoded)
	}
	attested, err := ApplyAttestations(draft, attestations)
	if err != nil {
		t.Fatal(err)
	}
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := topology.Finalize(attested, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encodedTopology, err := topology.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	network, err := topology.Verify(encodedTopology, authorityPublic, now)
	if err != nil {
		t.Fatal(err)
	}

	encodedA, _ := topology.EncodeSecrets(secrets["operator-a"])
	encodedB, _ := topology.EncodeSecrets(secrets["operator-b"])
	verifiedA, err := topology.VerifySecrets(encodedA, network)
	if err != nil {
		t.Fatal(err)
	}
	verifiedB, err := topology.VerifySecrets(encodedB, network)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedA.OutboundKeys[1] != verifiedB.InboundKeys[0] {
		t.Fatal("independent operators did not derive the same directed hop key")
	}

	tamperedEnrollment := enrollments[0]
	tamperedEnrollment.Endpoint = "127.0.0.1:4999"
	if err := VerifyEnrollment(tamperedEnrollment); err == nil {
		t.Fatal("tampered self-signed enrollment was accepted")
	}
	tamperedDraft := draft
	tamperedDraft.Operators = append([]topology.Operator(nil), draft.Operators...)
	tamperedDraft.Operators[0].Endpoint = "127.0.0.1:4998"
	if _, err := ApplyAttestations(tamperedDraft, attestations); err == nil {
		t.Fatal("attestations for a different topology draft were accepted")
	}
	duplicate := append([]Attestation(nil), attestations...)
	duplicate[2] = duplicate[1]
	if _, err := ApplyAttestations(draft, duplicate); err == nil {
		t.Fatal("duplicate operator attestation was accepted")
	}
}
