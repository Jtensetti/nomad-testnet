package fetchplan

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"

	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// The fetch plan is the signed statement that steers the fixed-rate partial
// fetcher. Nothing in this package had a test: Sign, Encode, Load and Verify
// were all at zero coverage across the repository, so the signature check
// could have been removed without failing anything -- and a fetcher that
// accepted an unsigned plan is one an attacker points wherever it likes.

type fixture struct {
	network   topology.Verified
	authority ed25519.PublicKey
	private   ed25519.PrivateKey
	plan      Plan
	signed    Plan
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities := map[string]ed25519.PrivateKey{}
	session := [32]byte{1}
	now := time.Now().UTC().Truncate(time.Second)
	document := topology.Document{
		Version: topology.Version, NetworkID: "fetchplan-test", Epoch: 4,
		NotBefore: now.Add(-time.Hour).Format(time.RFC3339),
		NotAfter:  now.Add(time.Hour).Format(time.RFC3339),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: 25,
			MaxLatenessMillis: 100, QueueCapacity: 32,
		},
		DKG: topology.DKGProfile{
			Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(session[:]),
			StartAt: now.Format(time.RFC3339), PhaseDurationMillis: 1_000,
		},
		Operators: make([]topology.Operator, 3),
	}
	plans := [][]uint16{{1, 2}, {0, 2}, {0, 1}}
	for index := range document.Operators {
		id := []string{"operator-a", "operator-b", "operator-c"}[index]
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		kexKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		dkgPublic, _, err := mix.GenerateDKGIdentity()
		if err != nil {
			t.Fatal(err)
		}
		identities[id] = privateKey
		port := []string{"4311", "4312", "4313"}[index]
		document.Operators[index] = topology.Operator{
			ID: id, Index: uint16(index), Endpoint: "127.0.0.1:" + port,
			PartialEndpoint: "http://127.0.0.1:" + port,
			DKGEndpoint:     "http://127.0.0.1:5" + port[1:],
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey),
			KEXKey:          base64.StdEncoding.EncodeToString(kexKey.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        plans[index],
		}
	}
	signedDocument, err := topology.Sign(document, authorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := topology.Encode(signedDocument)
	if err != nil {
		t.Fatal(err)
	}
	network, err := topology.Verify(encoded, authorityPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// A value whose hex encoding contains letters, so the case check below has
	// something to be upper-cased: ToUpper of an all-digit string is itself,
	// and the first version of that assertion was vacuous for exactly that
	// reason.
	stream := hop.StreamID{0xab, 0xcd, 0xef}
	plan := Plan{
		Version: Version, NetworkID: network.Document.NetworkID,
		TopologyEpoch:  network.Document.Epoch,
		TopologyDigest: hex.EncodeToString(network.Digest[:]),
		StreamID:       hex.EncodeToString(stream[:]),
	}
	signed, err := Sign(plan, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{network: network, authority: authorityPublic,
		private: authorityPrivate, plan: plan, signed: signed}
}

func (f fixture) verify(t *testing.T, plan Plan) error {
	t.Helper()
	encoded, err := Encode(plan)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(encoded, f.authority, f.network)
	return err
}

func TestASignedPlanRoundTripsAndVerifies(t *testing.T) {
	f := newFixture(t)
	if err := f.verify(t, f.signed); err != nil {
		t.Fatalf("a plan this authority signed did not verify: %v", err)
	}
	if f.signed.AuthoritySignature == "" {
		t.Fatal("Sign returned a plan with no signature")
	}
}

// Every field is covered by the signature, so changing any of them after
// signing must break it. A field left out of the signed message is a field an
// attacker rewrites in transit.
func TestEveryFieldIsUnderTheSignature(t *testing.T) {
	f := newFixture(t)
	for name, mutate := range map[string]func(*Plan){
		"version":         func(p *Plan) { p.Version = "nomad-partial-fetch-plan-v2" },
		"network":         func(p *Plan) { p.NetworkID = "other-network" },
		"topology epoch":  func(p *Plan) { p.TopologyEpoch++ },
		"topology digest": func(p *Plan) { p.TopologyDigest = hex.EncodeToString(make([]byte, 32)) },
		"stream":          func(p *Plan) { other := hop.StreamID{9}; p.StreamID = hex.EncodeToString(other[:]) },
	} {
		tampered := f.signed
		mutate(&tampered)
		if err := f.verify(t, tampered); err == nil {
			t.Fatalf("a plan whose %s was changed after signing verified", name)
		}
	}
}

func TestAPlanSignedByAnotherAuthorityIsRefused(t *testing.T) {
	f := newFixture(t)
	_, impostor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := Sign(f.plan, impostor)
	if err != nil {
		t.Fatal(err)
	}
	err = f.verify(t, forged)
	if err == nil {
		t.Fatal("a plan signed by another key verified")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("refused for %q rather than the signature", err)
	}
}

func TestAPlanWithNoSignatureIsRefused(t *testing.T) {
	f := newFixture(t)
	if err := f.verify(t, f.plan); err == nil {
		t.Fatal("an unsigned plan verified")
	}
}

// The plan is bound to one topology. A plan that is genuinely signed but
// belongs to another epoch would otherwise steer a fetcher using a peer set
// that has since changed.
func TestAPlanForAnotherTopologyIsRefused(t *testing.T) {
	f := newFixture(t)
	for name, mutate := range map[string]func(*Plan){
		"network":         func(p *Plan) { p.NetworkID = "other-network" },
		"topology epoch":  func(p *Plan) { p.TopologyEpoch = 99 },
		"topology digest": func(p *Plan) { p.TopologyDigest = hex.EncodeToString(make([]byte, 32)) },
	} {
		other := f.plan
		mutate(&other)
		signed, err := Sign(other, f.private)
		if err != nil {
			t.Fatal(err)
		}
		err = f.verify(t, signed)
		if err == nil {
			t.Fatalf("a correctly signed plan with a different %s verified", name)
		}
		if !strings.Contains(err.Error(), "different topology") {
			t.Fatalf("a plan with a different %s was refused for %q rather than "+
				"for the topology it names", name, err)
		}
	}
}

// Two encodings that decode to one plan are a place two implementations
// disagree about what was signed.
func TestNonCanonicalEncodingsAreRefused(t *testing.T) {
	f := newFixture(t)
	encoded, err := Encode(f.signed)
	if err != nil {
		t.Fatal(err)
	}
	for name, document := range map[string][]byte{
		"an unknown member": append([]byte(`{"surprise":1,`), encoded[1:]...),
		"trailing data":     append(append([]byte{}, encoded...), []byte("{}")...),
		"empty":             {},
	} {
		if _, err := Verify(document, f.authority, f.network); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	// A signature that is not strict base64 decodes under a lenient decoder to
	// the same bytes, which is a second encoding of one signature.
	lenient := f.signed
	lenient.AuthoritySignature = strings.TrimRight(lenient.AuthoritySignature, "=")
	if err := f.verify(t, lenient); err == nil {
		t.Fatal("a signature missing its base64 padding was accepted")
	}
}

func TestAMalformedStreamIDIsRefused(t *testing.T) {
	f := newFixture(t)
	for name, value := range map[string]string{
		"too short":  hex.EncodeToString(make([]byte, 8)),
		"not hex":    strings.Repeat("z", 64),
		"upper case": strings.ToUpper(f.plan.StreamID),
		"empty":      "",
	} {
		plan := f.plan
		plan.StreamID = value
		signed, err := Sign(plan, f.private)
		if err != nil {
			t.Fatal(err)
		}
		err = f.verify(t, signed)
		if err == nil {
			t.Fatalf("a plan whose stream ID is %s verified", name)
		}
		if !strings.Contains(err.Error(), "stream ID") {
			t.Fatalf("a %s stream ID was refused for %q rather than for the stream ID", name, err)
		}
	}
}

func TestLoadRequiresABoundedRegularFile(t *testing.T) {
	f := newFixture(t)
	encoded, err := Encode(f.signed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, f.authority, f.network); err != nil {
		t.Fatalf("a written plan did not load: %v", err)
	}

	if _, err := Load(t.TempDir(), f.authority, f.network); err == nil {
		t.Fatal("a directory was accepted as a fetch plan")
	} else if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("a directory was refused for %q rather than for not being a regular file", err)
	}

	oversized := filepath.Join(t.TempDir(), "plan.json")
	padded := f.signed
	padded.StreamID = strings.Repeat("0", MaximumFileBytes)
	big, err := json.Marshal(padded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oversized, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(oversized, f.authority, f.network); err == nil {
		t.Fatal("a plan past the size bound was accepted")
	}
}
