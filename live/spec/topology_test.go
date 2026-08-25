package spec

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// specTopology builds a three-operator document whose validity window covers
// exactly the given number of DKG phases, so a test can ask where the
// validator draws the line.
func specTopology(t *testing.T, phases int) (topology.Document, ed25519.PrivateKey,
	map[string]ed25519.PrivateKey) {
	t.Helper()
	const phaseMillis = 30_000
	_, authority, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	start := now.Add(time.Minute)
	phase := time.Duration(phaseMillis) * time.Millisecond

	identities := map[string]ed25519.PrivateKey{}
	var session [32]byte
	document := topology.Document{
		Version: topology.Version, NetworkID: "spec-window", Epoch: 3,
		NotBefore: now.Format(time.RFC3339),
		// The window ends exactly `phases` phases after the DKG starts.
		NotAfter: start.Add(time.Duration(phases) * phase).Format(time.RFC3339),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: 50,
			MaxLatenessMillis: 500, QueueCapacity: 32,
		},
		DKG: topology.DKGProfile{
			Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(session[:]),
			StartAt: start.Format(time.RFC3339), PhaseDurationMillis: phaseMillis,
		},
		Operators: make([]topology.Operator, 3),
	}
	names := []string{"operator-a", "operator-b", "operator-c"}
	for index := range document.Operators {
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
		identities[names[index]] = privateKey
		document.Operators[index] = topology.Operator{
			ID: names[index], Index: uint16(index),
			Endpoint:        "127.0.0.1:" + []string{"4201", "4202", "4203"}[index],
			PartialEndpoint: "http://127.0.0.1:" + []string{"4311", "4312", "4313"}[index],
			DKGEndpoint:     "http://127.0.0.1:" + []string{"4411", "4412", "4413"}[index],
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey),
			KEXKey:          base64.StdEncoding.EncodeToString(kexKey.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        []uint16{uint16((index + 1) % 3)},
		}
	}
	return document, authority, identities
}
