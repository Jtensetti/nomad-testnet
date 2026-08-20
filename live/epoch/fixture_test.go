package epoch

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

type fixtureOperator struct {
	ID       string
	Identity ed25519.PrivateKey
	KEX      *ecdh.PrivateKey
	DKG      mix.DKGPrivateIdentity
}

type fixture struct {
	AuthorityPublic  ed25519.PublicKey
	AuthorityPrivate ed25519.PrivateKey
	Operators        []fixtureOperator
}

func newFixture(t *testing.T, operatorCount int) *fixture {
	t.Helper()
	return newNamedFixture(t, "set", operatorCount)
}

// newNamedFixture derives keys from the set name as well as the operator
// index, so two fixtures created in one test have genuinely distinct
// operator identities. Sharing identity keys across fixtures would make any
// test of "an operator outside this set cannot approve" silently vacuous.
func newNamedFixture(t *testing.T, setName string, operatorCount int) *fixture {
	t.Helper()
	_, authority, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	operators := make([]fixtureOperator, operatorCount)
	for index := range operators {
		id := fmt.Sprintf("op-%c", 'a'+index)
		seed := sha256.Sum256([]byte("nomad-epoch-test-identity-" + setName + "-" + id))
		identity := ed25519.NewKeyFromSeed(seed[:])
		kexSeed := sha256.Sum256([]byte("nomad-epoch-test-kex-" + setName + "-" + id))
		kex, err := ecdh.X25519().NewPrivateKey(kexSeed[:])
		if err != nil {
			t.Fatal(err)
		}
		_, dkgPrivate, err := mix.GenerateDKGIdentity()
		if err != nil {
			t.Fatal(err)
		}
		operators[index] = fixtureOperator{ID: id, Identity: identity, KEX: kex, DKG: dkgPrivate}
	}
	return &fixture{AuthorityPublic: authority.Public().(ed25519.PublicKey), AuthorityPrivate: authority, Operators: operators}
}

type epochTimes struct {
	NotBefore time.Time
	NotAfter  time.Time
	DKGStart  time.Time
	Activate  time.Time
	Retire    time.Time
}

func canonicalTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// buildSignedTopology creates a fully attested and authority-signed topology
// for the fixture membership, returning its encoded bytes and verification.
func (f *fixture) buildSignedTopology(t *testing.T, epochNumber uint64, threshold uint32, times epochTimes, session [32]byte, basePort int) ([]byte, topology.Verified) {
	t.Helper()
	return f.buildSignedTopologyWithNetwork(t, "nomad-test", epochNumber, threshold, times, session, basePort)
}

func (f *fixture) buildSignedTopologyWithNetwork(t *testing.T, networkID string, epochNumber uint64, threshold uint32, times epochTimes, session [32]byte, basePort int) ([]byte, topology.Verified) {
	t.Helper()
	document := topology.Document{
		Version:   topology.Version,
		NetworkID: networkID,
		Epoch:     epochNumber,
		NotBefore: canonicalTime(times.NotBefore),
		NotAfter:  canonicalTime(times.NotAfter),
		Traffic:   topology.TrafficClass{CellSize: topology.CellSize, CellIntervalMillis: 50, MaxLatenessMillis: 500, QueueCapacity: 64},
		DKG: topology.DKGProfile{
			Threshold: threshold, SessionID: base64.StdEncoding.EncodeToString(session[:]),
			StartAt: canonicalTime(times.DKGStart), PhaseDurationMillis: 1_000,
		},
		Operators: make([]topology.Operator, len(f.Operators)),
	}
	identities := make(map[string]ed25519.PrivateKey, len(f.Operators))
	for index, operator := range f.Operators {
		dkgPublic, err := mix.DKGPublicFromPrivate(operator.DKG)
		if err != nil {
			t.Fatal(err)
		}
		document.Operators[index] = topology.Operator{
			ID: operator.ID, Index: uint16(index),
			Endpoint:        fmt.Sprintf("10.9.%d.%d:4200", basePort, index+1),
			PartialEndpoint: fmt.Sprintf("http://127.0.0.1:%d/", basePort+100+index),
			DKGEndpoint:     fmt.Sprintf("http://127.0.0.1:%d/", basePort+200+index),
			IdentityKey:     base64.StdEncoding.EncodeToString(operator.Identity.Public().(ed25519.PublicKey)),
			KEXKey:          base64.StdEncoding.EncodeToString(operator.KEX.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        []uint16{uint16((index + 1) % len(f.Operators))},
		}
		identities[operator.ID] = operator.Identity
	}
	signed, err := topology.Sign(document, f.AuthorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := topology.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := topology.Verify(encoded, f.AuthorityPublic, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return encoded, verified
}

// buildCertificate runs the in-process authenticated DKG for the topology and
// assembles the operator-attested certificate.
func (f *fixture) buildCertificate(t *testing.T, network topology.Verified) ([]byte, []mix.MemberSecret) {
	t.Helper()
	committeeID, err := committee.IDForTopology(network)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(network.Document.DKG.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	privates := make([]mix.DKGPrivateIdentity, len(f.Operators))
	for index, operator := range f.Operators {
		privates[index] = operator.DKG
	}
	publicCommittee, secrets, transcript, err := mix.RunAuthenticatedDKGWithIdentities(
		committeeID, network.Document.Epoch, privates, network.Document.DKG.Threshold, nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := committee.NewManifest(network, publicCommittee, transcript)
	if err != nil {
		t.Fatal(err)
	}
	attestations := make([]committee.Attestation, len(network.Document.Operators))
	for index, operator := range network.Document.Operators {
		attestations[index], err = committee.CreateAttestation(manifest, operator, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := committee.Assemble(manifest, attestations, network)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := committee.Encode(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, secrets
}

// buildDescriptor assembles, approves and activates a complete descriptor.
// previousFixture supplies approvals for non-genesis transitions; pass nil
// with previous == nil for genesis.
func (f *fixture) buildDescriptor(t *testing.T, previous *Verified, previousFixture *fixture, transition string, times epochTimes, network topology.Verified, topologyBytes, certificateBytes []byte) ([]byte, Verified) {
	t.Helper()
	descriptor, err := New(previous, transition, canonicalTime(times.Activate), canonicalTime(times.Retire), topologyBytes, certificateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if previous != nil {
		quorum := ApprovalQuorum(*previous)
		for index := 0; index < quorum; index++ {
			operator, err := previous.Topology.Operator(uint16(index))
			if err != nil {
				t.Fatal(err)
			}
			approval, err := Approve(descriptor, *previous, operator, previousFixture.Operators[index].Identity)
			if err != nil {
				t.Fatal(err)
			}
			descriptor.Approvals = append(descriptor.Approvals, approval)
		}
	}
	for index, operator := range network.Document.Operators {
		activation, err := Activate(descriptor, operator, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Activations = append(descriptor.Activations, activation)
	}
	encoded, err := Encode(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(encoded, f.AuthorityPublic, previous, nil)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, verified
}

var fixtureBase = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

func genesisTimes() epochTimes {
	return epochTimes{
		NotBefore: fixtureBase,
		NotAfter:  fixtureBase.Add(10 * time.Hour),
		DKGStart:  fixtureBase.Add(2 * time.Minute),
		Activate:  fixtureBase.Add(10 * time.Minute),
		Retire:    fixtureBase.Add(2 * time.Hour),
	}
}

func successorTimes() epochTimes {
	return epochTimes{
		NotBefore: fixtureBase.Add(30 * time.Minute),
		NotAfter:  fixtureBase.Add(12 * time.Hour),
		DKGStart:  fixtureBase.Add(32 * time.Minute),
		Activate:  fixtureBase.Add(2 * time.Hour),
		Retire:    fixtureBase.Add(4 * time.Hour),
	}
}

// buildTwoEpochChain creates a genesis (epoch 1) and scheduled successor
// (epoch 2) with the same membership.
func buildTwoEpochChain(t *testing.T) (*fixture, []byte, Verified, []byte, Verified) {
	t.Helper()
	f := newFixture(t, 3)
	session1 := sha256.Sum256([]byte("nomad-epoch-test-session-1"))
	topologyBytes1, network1 := f.buildSignedTopology(t, 1, 2, genesisTimes(), session1, 10)
	certificateBytes1, _ := f.buildCertificate(t, network1)
	genesisEncoded, genesis := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network1, topologyBytes1, certificateBytes1)

	session2 := sha256.Sum256([]byte("nomad-epoch-test-session-2"))
	topologyBytes2, network2 := f.buildSignedTopology(t, 2, 2, successorTimes(), session2, 30)
	certificateBytes2, _ := f.buildCertificate(t, network2)
	successorEncoded, successor := f.buildDescriptor(t, &genesis, f, TransitionScheduled, successorTimes(), network2, topologyBytes2, certificateBytes2)
	return f, genesisEncoded, genesis, successorEncoded, successor
}
