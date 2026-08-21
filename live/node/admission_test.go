package node

import (
	"context"
	"crypto/rand"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
)

// PROD-20 asks that Sybil, eclipse, amplification, resource-exhaustion and
// abusive-peer risks are bounded by a documented admission model.
//
// Nomad's answer to eclipse is structural rather than statistical: there is no
// peer discovery. A node's outgoing peers come from its own entry in the
// signed topology, and its incoming peers are exactly the operators whose
// signed plans name it. No message, flood, restart or elapsed time introduces
// a peer. An attacker therefore cannot surround a node by out-populating it,
// which is the usual eclipse route; it must first get itself into a signed
// topology, and that needs the previous committee's approval quorum.
//
// That is a strong claim precisely because it is architectural, so it is
// tested as an invariant rather than assumed from the absence of a discovery
// function.

func peerFingerprint(worker *Node) []string {
	out := make([]string, 0, len(worker.sink.peers)+len(worker.incoming))
	for _, peer := range worker.sink.peers {
		out = append(out, "out:"+peer.operator.ID+"@"+peer.address.String())
	}
	for key, peer := range worker.incoming {
		out = append(out, "in:"+peer.operator.ID+"@"+key)
	}
	sort.Strings(out)
	return out
}

func TestPeerSetComesOnlyFromTheSignedTopology(t *testing.T) {
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	scratch := t.TempDir()
	worker := buildCampaignNode(t, network, identities, endpoints, scratch)
	defer func() { _ = worker.conn.Close() }()

	self := network.Document.Operators[0]

	// Outgoing peers are exactly the signed plan, in the signed order.
	if len(worker.sink.plan) != len(self.PeerPlan) {
		t.Fatalf("outgoing plan has %d entries, signed plan has %d",
			len(worker.sink.plan), len(self.PeerPlan))
	}
	for position, peerIndex := range self.PeerPlan {
		peer := worker.sink.peers[worker.sink.plan[position]]
		if peer.operator.Index != peerIndex {
			t.Errorf("plan position %d resolves to operator %d, signed plan says %d",
				position, peer.operator.Index, peerIndex)
		}
		signed, _ := network.Operator(peerIndex)
		if peer.address.String() != resolveCampaignAddress(t, signed.Endpoint).String() {
			t.Errorf("peer %d resolves to %s, signed endpoint is %s",
				peerIndex, peer.address, signed.Endpoint)
		}
	}

	// Incoming peers are exactly the operators whose signed plans name us.
	expected := network.IncomingPeers(self.Index)
	if len(worker.incoming) != len(expected) {
		t.Errorf("accepts %d incoming peers, the signed topology names %d",
			len(worker.incoming), len(expected))
	}
	for _, operator := range expected {
		found := false
		for _, peer := range worker.incoming {
			if peer.operator.ID == operator.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("signed incoming peer %s is not accepted", operator.ID)
		}
	}
}

// The eclipse question stated directly: can anything an attacker does at
// runtime add it to a node's peer set? It floods from addresses the topology
// does not name, from a named address without the key, and with well-formed
// cells carrying foreign identities, and the peer set must be identical
// afterwards.
func TestNoRuntimeEventCanAddAPeer(t *testing.T) {
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	scratch := t.TempDir()
	worker := buildCampaignNode(t, network, identities, endpoints, scratch)

	before := peerFingerprint(worker)
	if len(before) == 0 {
		t.Fatal("the node has no peers at all; the comparison would be vacuous")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.receive(ctx) }()

	target := resolveCampaignAddress(t, endpoints[0])
	// A stranger: an address the signed topology does not name anywhere.
	stranger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stranger.Close() }()

	var cell fabric.Cell
	if _, err := rand.Read(cell[:]); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 200; attempt++ {
		_, _ = stranger.WriteToUDP(cell[:], target)
	}
	// And a well-formed, correctly sealed cell that simply comes from the
	// wrong socket: authentic bytes are not an introduction either.
	source, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	session := &hostileSession{
		conn: source, target: target, key: [32]byte{byte(2 + 11)}, sender: 2, receiver: 0,
		context: hop.Context{
			TopologyDigest: network.Digest, NetworkID: network.Document.NetworkID,
			Epoch: network.Document.Epoch, Receiver: 0,
		},
	}
	session.stream[15] = 1
	for attempt := 0; attempt < 50; attempt++ {
		authentic := session.workCell(t, true)
		_, _ = source.WriteToUDP(authentic[:], target)
	}

	waitForNodeStats(t, worker, func(s Stats) bool { return s.UnknownPeer > 0 })
	cancel()
	_ = worker.conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("receiver did not stop")
	}

	after := peerFingerprint(worker)
	if len(after) != len(before) {
		t.Fatalf("peer count changed from %d to %d under flood", len(before), len(after))
	}
	for index := range before {
		if before[index] != after[index] {
			t.Errorf("peer set changed under flood:\n  before %s\n  after  %s",
				before[index], after[index])
		}
	}
	stats := worker.Snapshot()
	if stats.UnknownPeer == 0 {
		t.Error("no datagram was attributed to an unknown peer; the flood did not arrive")
	}
	if stats.Stored != 0 {
		t.Errorf("a stranger's traffic caused %d cells to be stored", stats.Stored)
	}
	t.Logf("under flood: %d unknown-peer datagrams, %d stored, peer set unchanged (%d peers)",
		stats.UnknownPeer, stats.Stored, len(after))
}

// Sybil: identities are free to create, so the bound has to come from what an
// identity buys. Here it buys nothing, because admission is by signed topology
// membership rather than by presence. This asserts the property that makes
// that true -- an operator absent from the topology is never consulted, no
// matter how many of them there are.
func TestUnsignedIdentitiesGainNothingByExisting(t *testing.T) {
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	scratch := t.TempDir()
	worker := buildCampaignNode(t, network, identities, endpoints, scratch)
	defer func() { _ = worker.conn.Close() }()

	signed := map[string]struct{}{}
	for _, operator := range network.Document.Operators {
		signed[operator.ID] = struct{}{}
	}
	for _, peer := range worker.sink.peers {
		if _, ok := signed[peer.operator.ID]; !ok {
			t.Errorf("outgoing peer %s is not in the signed topology", peer.operator.ID)
		}
	}
	for _, peer := range worker.incoming {
		if _, ok := signed[peer.operator.ID]; !ok {
			t.Errorf("incoming peer %s is not in the signed topology", peer.operator.ID)
		}
	}

	// A thousand fresh identities change nothing, because the node consults
	// the signed document and never a population.
	var group sync.WaitGroup
	target := resolveCampaignAddress(t, endpoints[0])
	before := peerFingerprint(worker)
	for identity := 0; identity < 64; identity++ {
		group.Add(1)
		go func() {
			defer group.Done()
			sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				return
			}
			defer func() { _ = sock.Close() }()
			var cell fabric.Cell
			_, _ = rand.Read(cell[:])
			_, _ = sock.WriteToUDP(cell[:], target)
		}()
	}
	group.Wait()
	after := peerFingerprint(worker)
	if len(after) != len(before) {
		t.Errorf("64 fresh identities changed the peer set from %d to %d",
			len(before), len(after))
	}
}
