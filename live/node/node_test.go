package node

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func TestReceiveRejectsInvalidSourcesAuthenticationAndReplay(t *testing.T) {
	network, identities, endpoints := nodeTestTopology(t)
	keyAB := [32]byte{1}
	keyBC := [32]byte{2}
	cache, err := rawcache.Open(filepath.Join(t.TempDir(), "raw"), 8)
	if err != nil {
		t.Fatal(err)
	}
	self := network.Document.Operators[1]
	worker, err := New(Config{
		Topology: network,
		Secrets: topology.VerifiedSecrets{
			Operator: self, Identity: identities[self.ID],
			OutboundKeys: map[uint16][32]byte{2: keyBC},
			InboundKeys:  map[uint16][32]byte{0: keyAB},
		},
		ListenAddress: endpoints[1], Cache: cache,
		SequencePath:    filepath.Join(t.TempDir(), "sequence"),
		HealthPath:      filepath.Join(t.TempDir(), "health.json"),
		CacheSweep:      time.Hour,
		ServingDeadline: func() time.Time { return time.Now().UTC().Add(time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.receive(ctx) }()
	defer func() {
		cancel()
		_ = worker.conn.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("receiver shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("receiver did not stop")
		}
	}()

	peerAddress, err := net.ResolveUDPAddr("udp", endpoints[0])
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUDP("udp", peerAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	destination := worker.conn.LocalAddr().(*net.UDPAddr)
	if _, err := peer.WriteToUDP([]byte{1, 2, 3}, destination); err != nil {
		t.Fatal(err)
	}

	stream := hop.StreamID{1}
	metadata, err := hop.WorkMetadata(stream, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext [hop.CiphertextSize]byte
	if _, err := rand.Read(ciphertext[:]); err != nil {
		t.Fatal(err)
	}
	cell, err := hop.FromCiphertext(ciphertext, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := hop.Seal(&cell, metadata, 0, 1, keyAB, hop.Context{
		TopologyDigest: network.Digest, NetworkID: network.Document.NetworkID,
		Epoch: network.Document.Epoch, Receiver: self.Index,
	}); err != nil {
		t.Fatal(err)
	}
	tampered := cell
	tampered[0] ^= 0xff
	if _, err := peer.WriteToUDP(tampered[:], destination); err != nil {
		t.Fatal(err)
	}
	unknown, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unknown.WriteToUDP(cell[:], destination); err != nil {
		t.Fatal(err)
	}
	_ = unknown.Close()

	waitForNodeStats(t, worker, func(stats Stats) bool {
		return stats.WrongSize == 1 && stats.AuthRejected == 1 && stats.UnknownPeer == 1
	})
	if _, err := peer.WriteToUDP(cell[:], destination); err != nil {
		t.Fatal(err)
	}
	waitForNodeStats(t, worker, func(stats Stats) bool { return stats.Stored == 1 })
	if _, err := peer.WriteToUDP(cell[:], destination); err != nil {
		t.Fatal(err)
	}
	waitForNodeStats(t, worker, func(stats Stats) bool { return stats.ReplayRejected == 1 })

	stats := worker.Snapshot()
	if stats.Received != 5 || stats.Stored != 1 || stats.WrongSize != 1 || stats.UnknownPeer != 1 ||
		stats.AuthRejected != 1 || stats.ReplayRejected != 1 {
		t.Fatalf("unexpected receiver counters: %+v", stats)
	}
}

func TestSendRefusesAtPublicEpochDeadlineBeforeNetworkWrite(t *testing.T) {
	network, identities, endpoints := nodeTestTopology(t)
	destinationAddress, err := net.ResolveUDPAddr("udp", endpoints[2])
	if err != nil {
		t.Fatal(err)
	}
	destination, err := net.ListenUDP("udp", destinationAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	cache, err := rawcache.Open(filepath.Join(t.TempDir(), "raw"), 8)
	if err != nil {
		t.Fatal(err)
	}
	self := network.Document.Operators[1]
	publicNow := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	deadline := publicNow.Add(time.Second)
	worker, err := New(Config{
		Topology: network,
		Secrets: topology.VerifiedSecrets{
			Operator: self, Identity: identities[self.ID],
			OutboundKeys: map[uint16][32]byte{2: {2}},
			InboundKeys:  map[uint16][32]byte{0: {1}},
		},
		ListenAddress: endpoints[1], Cache: cache,
		SequencePath: filepath.Join(t.TempDir(), "sequence"),
		HealthPath:   filepath.Join(t.TempDir(), "health.json"),
		CacheSweep:   time.Hour,
		Now:          func() time.Time { return publicNow },
		ServingDeadline: func() time.Time {
			return deadline
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.conn.Close()
	cell, err := (coverSource{}).NextCell(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	publicNow = deadline
	if err := worker.sink.Send(context.Background(), cell); !errors.Is(err, ErrEpochInactive) {
		t.Fatalf("deadline send = %v, want ErrEpochInactive", err)
	}
	if worker.Snapshot().Sent != 0 {
		t.Fatal("retired epoch incremented its sent counter")
	}
	if err := destination.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, fabric.CellSize)
	if _, _, err := destination.ReadFromUDP(buffer); err == nil {
		t.Fatal("retired epoch emitted a datagram")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("read after retired send: %v", err)
	}
}

func nodeTestTopology(t *testing.T) (topology.Verified, map[string]ed25519.PrivateKey, []string) {
	t.Helper()
	return nodeTestTopologyWithCadence(t, 10, 40, singlePeerPlan)
}

func singlePeerPlan(index int) []uint16 { return []uint16{uint16((index + 1) % 3)} }

// rotatingPeerPlan gives each operator a two-peer plan, so a test can check
// that the destination a cell goes to is a function of the signed plan and
// the emission ordinal alone. A plan must stay shorter than the operator
// count, so two entries is the longest available with three operators.
func rotatingPeerPlan(index int) []uint16 {
	return []uint16{uint16((index + 1) % 3), uint16((index + 2) % 3)}
}

func nodeTestTopologyWithCadence(t *testing.T, intervalMillis, maxLatenessMillis uint32, peerPlan func(int) []uint16) (topology.Verified, map[string]ed25519.PrivateKey, []string) {
	t.Helper()
	endpoints := make([]string, 3)
	listeners := make([]*net.UDPConn, 3)
	for index := range endpoints {
		listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		listeners[index] = listener
		endpoints[index] = listener.LocalAddr().String()
	}
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities := make(map[string]ed25519.PrivateKey)
	dkgSession := [32]byte{1}
	now := time.Now().UTC().Truncate(time.Second)
	document := topology.Document{
		Version: topology.Version, NetworkID: "node-test", Epoch: 7,
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: intervalMillis,
			MaxLatenessMillis: maxLatenessMillis, QueueCapacity: 32,
		},
		DKG:       topology.DKGProfile{Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(dkgSession[:]), StartAt: now.Format(time.RFC3339), PhaseDurationMillis: 1_000},
		Operators: make([]topology.Operator, 3),
	}
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
		document.Operators[index] = topology.Operator{
			ID: id, Index: uint16(index), Endpoint: endpoints[index],
			PartialEndpoint: "http://127.0.0.1:" + []string{"4311", "4312", "4313"}[index],
			DKGEndpoint:     "http://127.0.0.1:" + []string{"4411", "4412", "4413"}[index],
			IdentityKey:     base64.StdEncoding.EncodeToString(publicKey),
			KEXKey:          base64.StdEncoding.EncodeToString(kexKey.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        peerPlan(index),
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
	network, err := topology.Verify(encoded, authorityPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return network, identities, endpoints
}

func waitForNodeStats(t *testing.T, worker *Node, ready func(Stats) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ready(worker.Snapshot()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for node stats: %+v", worker.Snapshot())
}
