package entry

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/airlock"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// entryFixture is one entry operator with everything it needs to open a cell,
// and everything a publisher needs to seal one for it.
//
// It builds the service through New and drives handle directly rather than
// through a socket. That is deliberate: what these tests are about is which
// session a cell is opened under, and a socket adds nothing to that question
// while making the address the test wants to control an artifact of the
// operating system.
type entryFixture struct {
	service   *Service
	committee mix.ThresholdCommittee
	context   uplink.Context
	kexPublic []byte
}

func newEntryFixture(t *testing.T, sessionLimit int) *entryFixture {
	t.Helper()
	committee, _, err := mix.GenerateDealerCommittee(mix.CommitteeID{4}, 1, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	network, kex := entryTestTopology(t)
	operator, err := network.OperatorByID("operator-a")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	schedule := airlock.Schedule{
		Genesis:               time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		Period:                time.Hour,
		DepositCutoff:         time.Minute,
		BatchSize:             8,
		MaxDepositsPerSession: 4,
	}
	service, err := New(Config{
		Topology: network, KEX: kex, Committee: committee,
		ListenAddress:  "127.0.0.1:0",
		BatchDirectory: filepath.Join(directory, "batches"),
		HealthPath:     filepath.Join(directory, "health.json"),
		Schedule:       schedule, SessionLimit: sessionLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Run is not started: these tests drive handle, and the release epoch the
	// mailbox belongs to is the one open now, exactly as Run would choose it.
	epoch, err := schedule.EpochAt(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.rollTo(epoch); err != nil {
		t.Fatal(err)
	}
	kexPublic, err := base64.StdEncoding.DecodeString(operator.KEXKey)
	if err != nil {
		t.Fatal(err)
	}
	return &entryFixture{
		service: service, committee: committee, kexPublic: kexPublic,
		context: uplink.Context{
			NetworkID: network.Document.NetworkID, Epoch: network.Document.Epoch,
			TopologyDigest: network.Digest, EntryOperator: operator.Index,
		},
	}
}

// publisher establishes a session the way a real one does: from the operator's
// published key-agreement key and nothing else.
func (fixture *entryFixture) publisher(t *testing.T) *uplink.Initiator {
	t.Helper()
	initiator, err := uplink.Establish(fixture.kexPublic, fixture.committee.PublicKey,
		fixture.context, 1)
	if err != nil {
		t.Fatal(err)
	}
	return initiator
}

func address(t *testing.T, text string) *net.UDPAddr {
	t.Helper()
	resolved, err := net.ResolveUDPAddr("udp", text)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func entryTestTopology(t *testing.T) (topology.Verified, *ecdh.PrivateKey) {
	t.Helper()
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	var session [32]byte
	document := topology.Document{
		Version: topology.Version, NetworkID: "entry-test", Epoch: 3,
		NotBefore: now.Add(-time.Hour).Format(time.RFC3339),
		NotAfter:  now.Add(time.Hour).Format(time.RFC3339),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: 50,
			MaxLatenessMillis: 200, QueueCapacity: 32,
		},
		DKG: topology.DKGProfile{
			Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(session[:]),
			StartAt: now.Format(time.RFC3339), PhaseDurationMillis: 1_000,
		},
		Operators: make([]topology.Operator, 3),
	}
	identities := map[string]ed25519.PrivateKey{}
	var own *ecdh.PrivateKey
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
		if index == 0 {
			own = kexKey
		}
		dkgPublic, _, err := mix.GenerateDKGIdentity()
		if err != nil {
			t.Fatal(err)
		}
		identities[id] = privateKey
		port := []string{"45501", "45502", "45503"}[index]
		document.Operators[index] = topology.Operator{
			ID: id, Index: uint16(index), Endpoint: "127.0.0.1:" + port,
			PartialEndpoint: "http://127.0.0.1:456" + port[3:],
			DKGEndpoint:     "http://127.0.0.1:457" + port[3:],
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey),
			KEXKey:          base64.StdEncoding.EncodeToString(kexKey.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        []uint16{uint16((index + 1) % 3)},
		}
	}
	signed, err := topology.Sign(document, authorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := topology.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	network, err := topology.Verify(encoded, authorityPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	return network, own
}
