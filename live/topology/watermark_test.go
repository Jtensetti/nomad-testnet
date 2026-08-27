package topology

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

func watermarkFixture(t *testing.T, epoch uint64, networkID string) Verified {
	t.Helper()
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document, identities := unattestedDocument(t, networkID, 3)
	document.Epoch = epoch
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
	verified, err := Verify(encoded, authorityPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

// unattestedDocument builds a valid multi-operator document with fresh keys
// and returns the operator identities, so a test can attest it, mutate it, or
// deliberately leave an attestation off.
func unattestedDocument(t *testing.T, networkID string, operators int) (Document, map[string]ed25519.PrivateKey) {
	t.Helper()
	identities := make(map[string]ed25519.PrivateKey)
	dkgSession := [32]byte{1}
	now := time.Now().UTC().Truncate(time.Second)
	document := Document{
		Version: Version, NetworkID: networkID, Epoch: 1,
		NotBefore: now.Add(-time.Hour).Format(time.RFC3339),
		NotAfter:  now.Add(time.Hour).Format(time.RFC3339),
		Traffic:   TrafficClass{CellSize: CellSize, CellIntervalMillis: 10, MaxLatenessMillis: 40, QueueCapacity: 64},
		DKG:       DKGProfile{Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(dkgSession[:]), StartAt: now.Format(time.RFC3339), PhaseDurationMillis: 1_000},
		Operators: make([]Operator, operators),
	}
	for index := range document.Operators {
		id := "operator-" + string(rune('a'+index))
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
		document.Operators[index] = Operator{
			ID: id, Index: uint16(index), Endpoint: "127.0.0.1:" + string(rune('1'+index)) + "200",
			PartialEndpoint: "http://127.0.0.1:" + string(rune('1'+index)) + "300",
			DKGEndpoint:     "http://127.0.0.1:" + string(rune('1'+index)) + "400",
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey),
			KEXKey:          base64.StdEncoding.EncodeToString(kexKey.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        []uint16{uint16((index + 1) % operators)},
		}
	}
	return document, identities
}

// A signature and a validity window do not stop a rollback: an older topology
// inside its own window verifies perfectly. Replaying one is how an operator
// removed from the set is put back without forging anything, so the node must
// refuse to move backwards.
func TestTopologyWatermarkRefusesRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "topology-watermark.json")
	older := watermarkFixture(t, 4, "watermark-net")
	newer := watermarkFixture(t, 7, "watermark-net")

	if err := AcceptMonotonic(path, older); err != nil {
		t.Fatalf("first topology refused: %v", err)
	}
	if err := AcceptMonotonic(path, newer); err != nil {
		t.Fatalf("advancing to a newer epoch refused: %v", err)
	}
	if err := AcceptMonotonic(path, older); !errors.Is(err, ErrTopologyRollback) {
		t.Fatalf("rollback accepted: %v", err)
	}
	// The refusal must persist across restarts, which is the case that
	// matters: a stale directory restored from backup looks like a fresh
	// start to everything except this file.
	if err := AcceptMonotonic(path, older); !errors.Is(err, ErrTopologyRollback) {
		t.Fatalf("rollback accepted on a second attempt: %v", err)
	}
}

// Two different topologies signed for the same network and epoch is
// equivocation by the authority. The node must fail closed rather than pick
// whichever it saw last.
func TestTopologyWatermarkFailsClosedOnEquivocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "topology-watermark.json")
	first := watermarkFixture(t, 5, "watermark-net")
	second := watermarkFixture(t, 5, "watermark-net")
	if first.Digest == second.Digest {
		t.Fatal("fixture produced identical digests; the test would prove nothing")
	}
	if err := AcceptMonotonic(path, first); err != nil {
		t.Fatal(err)
	}
	if err := AcceptMonotonic(path, second); !errors.Is(err, ErrTopologyEquivocation) {
		t.Fatalf("equivocating topology accepted: %v", err)
	}
	// Re-offering the one already accepted is not equivocation.
	if err := AcceptMonotonic(path, first); err != nil {
		t.Fatalf("re-offering the accepted topology refused: %v", err)
	}
}

// A different network has its own history; sharing a state directory between
// networks must not make one network's epoch bound the other's.
func TestTopologyWatermarkIsScopedToItsNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "topology-watermark.json")
	if err := AcceptMonotonic(path, watermarkFixture(t, 9, "watermark-net")); err != nil {
		t.Fatal(err)
	}
	if err := AcceptMonotonic(path, watermarkFixture(t, 2, "other-net")); err != nil {
		t.Fatalf("a different network was bound by another network's epoch: %v", err)
	}
}

// A watermark the node cannot interpret is not permission to proceed.
func TestTopologyWatermarkFailsClosedOnUnreadableState(t *testing.T) {
	directory := t.TempDir()
	verified := watermarkFixture(t, 3, "watermark-net")
	for name, contents := range map[string]string{
		"truncated":     `{"version":"nomad-topology-watermark-v1","network_id":"watermark-net"`,
		"wrong-version": `{"version":"nomad-topology-watermark-v0","network_id":"watermark-net","epoch":9,"digest":"` + hex.EncodeToString(make([]byte, 32)) + `"}`,
		"zero-epoch":    `{"version":"nomad-topology-watermark-v1","network_id":"watermark-net","epoch":0,"digest":"` + hex.EncodeToString(make([]byte, 32)) + `"}`,
		"short-digest":  `{"version":"nomad-topology-watermark-v1","network_id":"watermark-net","epoch":9,"digest":"abcd"}`,
		"unknown-field": `{"version":"nomad-topology-watermark-v1","network_id":"watermark-net","epoch":9,"digest":"` + hex.EncodeToString(make([]byte, 32)) + `","extra":1}`,
	} {
		path := filepath.Join(directory, name+".json")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := AcceptMonotonic(path, verified); err == nil {
			t.Fatalf("%s watermark was treated as permission to proceed", name)
		}
	}
}
