package dkgnet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/ceremony"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"go.dedis.ch/kyber/v4/encrypt/ecies"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

// TestRetainedDealResistsLaterEpochCredentialCompromise is the adversarial
// forward-secrecy experiment for persisted live DKG traffic. It retains the
// exact canonical deal payload written inside a Store envelope, proves that
// the retired epoch identity can decrypt its addressed ciphertext (control),
// then gives the attacker the same operator's complete next-epoch secret file.
// The rotated DKG identity cannot decrypt or join the retired membership.
func TestRetainedDealResistsLaterEpochCredentialCompromise(t *testing.T) {
	const members = 3
	oldKeys := make([]topology.PrivateKeys, members)
	publics := make([]mix.DKGPublicIdentity, members)
	enrollments := make([]ceremony.Enrollment, members)
	for index := range oldKeys {
		secrets, err := topology.GenerateSecrets("operator-" + string(rune('a'+index)))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := topology.EncodeSecrets(secrets)
		if err != nil {
			t.Fatal(err)
		}
		oldKeys[index], err = topology.DecodePrivateKeys(encoded)
		if err != nil {
			t.Fatal(err)
		}
		publics[index], err = mix.DKGPublicFromPrivate(oldKeys[index].DKG)
		if err != nil {
			t.Fatal(err)
		}
		enrollments[index], err = ceremony.NewEnrollment(
			oldKeys[index], fmt.Sprintf("127.0.0.1:%d", 4200+index),
			fmt.Sprintf("http://127.0.0.1:%d", 4300+index),
			fmt.Sprintf("http://127.0.0.1:%d", 4400+10*index),
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	nonce := sha256.Sum256([]byte("retained-live-dkg-forward-secrecy"))
	now := time.Now().UTC().Truncate(time.Second)
	draft, err := ceremony.BuildDraft(enrollments, ceremony.DraftConfig{
		NetworkID: "forward-secrecy-test", Epoch: 1,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: 50,
			MaxLatenessMillis: 200, QueueCapacity: 64,
		},
		DKGStart: now.Add(time.Minute), DKGPhaseDuration: time.Second,
		DKGThreshold: 2, DKGSessionID: nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := range oldKeys {
		draft, err = topology.Attest(draft, oldKeys[index].OperatorID, oldKeys[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := topology.Finalize(draft, authorityPrivate)
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
	bundles := make([]*dkg.DealBundle, members)
	for index := range oldKeys {
		config, err := mix.NewPedersenDKGConfig(oldKeys[index].DKG, publics, 2, nonce[:])
		if err != nil {
			t.Fatal(err)
		}
		handler, err := dkg.NewDistKeyHandler(config)
		if err != nil {
			t.Fatal(err)
		}
		bundles[index], err = handler.Deals()
		if err != nil {
			t.Fatal(err)
		}
	}

	phase, _, payload, err := EncodePacket(bundles[1])
	if err != nil || phase != DealPhase {
		t.Fatalf("encode retained deal: phase=%s err=%v", phase, err)
	}
	envelope, err := NewEnvelope(network, network.Document.Operators[1], oldKeys[1].Identity, DealPhase, payload)
	if err != nil {
		t.Fatal(err)
	}
	encodedEnvelope, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	store, err := NewStore(stateRoot, network)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, fresh, err := store.Accept(encodedEnvelope); err != nil || !fresh {
		t.Fatalf("persist live DKG deal: fresh=%v err=%v", fresh, err)
	}
	transcriptPath := filepath.Join(stateRoot, "messages", string(DealPhase), "01.json")
	retainedEnvelope, err := os.ReadFile(transcriptPath)
	if err != nil {
		t.Fatal(err)
	}
	_, retained, err := DecodeEnvelope(retainedEnvelope, network)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := DecodePacket(DealPhase, retained)
	if err != nil {
		t.Fatal(err)
	}
	bundle := packet.(*dkg.DealBundle)
	var ciphertext []byte
	for _, deal := range bundle.Deals {
		if deal.ShareIndex == 0 {
			ciphertext = append([]byte(nil), deal.EncryptedShare...)
			break
		}
	}
	if len(ciphertext) == 0 {
		t.Fatal("retained dealer payload omitted operator A's encrypted share")
	}

	suite := edwards25519.NewBlakeSHA256Ed25519()
	retiredPrivate := suite.Scalar()
	if err := retiredPrivate.UnmarshalBinary(oldKeys[0].DKG[:]); err != nil {
		t.Fatal(err)
	}
	controlPlaintext, err := ecies.Decrypt(suite, retiredPrivate, ciphertext, sha256.New)
	if err != nil || len(controlPlaintext) == 0 {
		t.Fatalf("control: retired identity did not decrypt its retained deal: %v", err)
	}

	rotated, err := topology.RotateEpochSecrets(oldKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	rotatedEncoded, err := topology.EncodeSecrets(rotated)
	if err != nil {
		t.Fatal(err)
	}
	compromised, err := topology.DecodePrivateKeys(rotatedEncoded)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(compromised.DKG[:], oldKeys[0].DKG[:]) {
		t.Fatal("test setup did not rotate the DKG identity")
	}
	laterPrivate := suite.Scalar()
	if err := laterPrivate.UnmarshalBinary(compromised.DKG[:]); err != nil {
		t.Fatal(err)
	}
	if plaintext, err := ecies.Decrypt(suite, laterPrivate, ciphertext, sha256.New); err == nil {
		t.Fatalf("later-compromised DKG identity decrypted a retired deal: %x", plaintext)
	}
	if _, err := mix.NewPedersenDKGConfig(compromised.DKG, publics, 2, nonce[:]); err == nil {
		t.Fatal("later-compromised DKG identity was admitted to retired membership")
	}
}
