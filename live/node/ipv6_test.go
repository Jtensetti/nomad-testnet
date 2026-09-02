package node

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// PROD-21 asks for dual-stack behaviour and there was no IPv6 run anywhere:
// live/topology has thorough IPv6 tests, but they are all about the document,
// and a document that admits [::1]:4200 says nothing about a datagram
// arriving. Everything on the wire ran on 127.0.0.1.
//
// This is loopback, not a WAN, and it is stated that way in the readiness
// registry: it establishes that the transport, the peer table and the hop
// authentication work over IPv6 at all, which is what "untested" meant. NAT,
// path MTU, dual-stack address selection and IPv6 across a real network remain
// external (EB-2).

// requireIPv6Loopback returns the address to run on, or ends the test.
//
// The development container has no IPv6 stack at all -- not "no route", the
// address family is unsupported -- so a skip is the honest answer there. A
// skip is green, though, so where the environment declares it can do this, its
// absence is a failure instead. Otherwise this test would stop running the day
// a runner image changed and PROD-21 would go on citing it.
func requireIPv6Loopback(t *testing.T) string {
	t.Helper()
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err == nil {
		_ = probe.Close()
		return "::1"
	}
	if os.Getenv("NOMAD_REQUIRE_CAPABILITY_GATES") == "1" {
		t.Fatalf("IPv6 loopback is unavailable (%v), and "+
			"NOMAD_REQUIRE_CAPABILITY_GATES=1 says this environment is supposed to "+
			"have it. Skipping here would report what passing reports.", err)
	}
	t.Skipf("this host has no IPv6 loopback (%v), so the wire cannot be exercised "+
		"over it; an environment limit and not a pass", err)
	return ""
}

func TestCellsCrossTheWireOverIPv6(t *testing.T) {
	host := requireIPv6Loopback(t)
	network, identities, endpoints := nodeTestTopologyOn(t, host, 10, 40, singlePeerPlan)

	// The endpoints the fixture produced must actually be IPv6, or this test
	// would pass on IPv4 having proved nothing.
	for index, endpoint := range endpoints {
		address, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if address.IP.To4() != nil {
			t.Fatalf("operator %d listens on %s, which is IPv4", index, endpoint)
		}
	}

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
		SequencePath: filepath.Join(t.TempDir(), "sequence"),
		HealthPath:   filepath.Join(t.TempDir(), "health.json"),
		CacheSweep:   time.Hour,
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

	destination := worker.conn.LocalAddr().(*net.UDPAddr)
	if destination.IP.To4() != nil {
		t.Fatalf("the node bound %s, which is IPv4", destination)
	}
	peerAddress, err := net.ResolveUDPAddr("udp", endpoints[0])
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUDP("udp", peerAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

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
	if _, err := peer.WriteToUDP(cell[:], destination); err != nil {
		t.Fatal(err)
	}
	waitForNodeStats(t, worker, func(stats Stats) bool { return stats.Stored == 1 })

	// The peer table is keyed on the source address, so an IPv6 source that
	// the topology does not name must be refused over IPv6 as well -- the
	// admission rule is not allowed to weaken with the address family.
	unknown, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unknown.WriteToUDP(cell[:], destination); err != nil {
		t.Fatal(err)
	}
	_ = unknown.Close()
	waitForNodeStats(t, worker, func(stats Stats) bool { return stats.UnknownPeer == 1 })

	if _, err := peer.WriteToUDP(cell[:], destination); err != nil {
		t.Fatal(err)
	}
	waitForNodeStats(t, worker, func(stats Stats) bool { return stats.ReplayRejected == 1 })
}
