package node

import (
	"context"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/wire"
)

// An operator disappearing is the one failure a fixed-cadence network is most
// tempted to react to, and reacting is exactly what it must not do.
//
// Two reactions would each be a channel. Rerouting a vanished peer's share to a
// surviving one tells that peer, who may be the adversary, that a specific
// operator has stopped -- and it tells them by giving them more traffic, so the
// signal is unmissable. Retrying tells them the same thing at a different rate.
// Both are worse when they coincide with private activity, because then the
// volume the survivor sees is a function of what a user is doing during an
// outage.
//
// The surviving peer is therefore the right observer for this experiment: it is
// precisely the party who would learn something. These worlds ask what it sees.
//
// This is workstream B-08, at the loopback boundary. It is not WAN evidence and
// it is not a regional outage: one host, userspace timestamps, and the same
// party that wrote the sender. E-01 and B-09 stay open.

// TestAVanishedPeerChangesNothingTheSurvivorSees runs three worlds against a
// two-peer rotation and compares what the one peer that stays up receives.
func TestAVanishedPeerChangesNothingTheSurvivorSees(t *testing.T) {
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, rotatingPeerPlan)

	const emissions = 24
	// The plan is [1, 2] and the sink walks it by emission ordinal, so peer 1
	// is entitled to exactly half the emissions and no more.
	const survivorShare = emissions / 2

	worlds := map[string][]wire.Packet{}
	for _, world := range []struct {
		name string
		// bound names which peers have a socket. Peer 2 missing is an
		// operator that has disappeared: nothing is listening on its port.
		bound []int
		// active fills the work queue past the emission count, so every slot
		// in the run carries work rather than cover.
		active bool
	}{
		{name: "both-up-idle", bound: []int{1, 2}},
		{name: "peer-gone-idle", bound: []int{1}},
		{name: "peer-gone-active", bound: []int{1}, active: true},
	} {
		observers := bindObservers(t, endpoints, world.bound)
		worker := buildCampaignNode(t, network, identities, endpoints, t.TempDir())
		if world.active {
			fillWorkQueue(t, worker, emissions*2)
		}

		captured := make(chan []wire.Packet, 1)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { captured <- observeAll(observers, ctx) }()

		for emitted := 0; emitted < emissions; emitted++ {
			cell, err := worker.cover.NextCell(ctx)
			if err != nil {
				t.Fatalf("%s: source: %v", world.name, err)
			}
			if err := worker.sink.Send(ctx, cell); err != nil {
				// A write to a port nobody is listening on must still
				// succeed. If it does not, the sender has learned that its
				// peer is gone, and everything downstream of that knowledge
				// is a potential signal.
				t.Fatalf("%s: emission %d failed because a peer was absent: %v",
					world.name, emitted, err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
		cancel()
		worlds[world.name] = <-captured
		// The sender must believe it sent every scheduled cell, including the
		// ones addressed to an operator that is not there. Counting fewer
		// would mean emissions were suppressed rather than delivered into the
		// void, and a suppressed emission is a gap an observer can see.
		if sent := worker.Snapshot().Sent; sent != emissions {
			t.Fatalf("%s: the node counted %d emissions, want %d: a cell addressed to "+
				"an absent peer was not sent", world.name, sent, emissions)
		}
		closeObservers(observers)
		_ = worker.conn.Close()
	}

	// With both peers up, the survivor takes its half.
	if got := len(worlds["both-up-idle"]); got != emissions {
		t.Fatalf("both peers up received %d cells in total, want %d", got, emissions)
	}
	survivorWhenBothUp := onlyPeer(worlds["both-up-idle"], endpoints[1])
	if len(survivorWhenBothUp) != survivorShare {
		t.Fatalf("with both peers up the survivor received %d cells, want %d: "+
			"the rotation is not splitting emissions as the signed plan says",
			len(survivorWhenBothUp), survivorShare)
	}

	// The claim that matters. If the sender rerouted the vanished peer's
	// share, the survivor would see every emission instead of half.
	gone := worlds["peer-gone-idle"]
	if len(gone) != survivorShare {
		t.Fatalf("with a peer gone the survivor received %d cells, want %d. "+
			"Receiving more would mean the vanished peer's share was rerouted, "+
			"which announces the disappearance to whoever is still up",
			len(gone), survivorShare)
	}

	// And private activity during the outage must not change it.
	active := worlds["peer-gone-active"]
	if len(active) != len(gone) {
		t.Fatalf("during an outage the survivor received %d cells while the node was "+
			"idle and %d while it was busy: private activity changed what a peer sees",
			len(gone), len(active))
	}
	for index := range gone {
		if gone[index].Destination != active[index].Destination {
			t.Errorf("cell %d went to %s when idle and %s when active, during an outage",
				index, gone[index].Destination, active[index].Destination)
		}
		if gone[index].Size != fabric.CellSize || active[index].Size != fabric.CellSize {
			t.Errorf("cell %d size idle=%d active=%d, want %d",
				index, gone[index].Size, active[index].Size, fabric.CellSize)
		}
	}

	// The disappearance must not shift the rotation either: the survivor's
	// cells are the same ones it would have received with both peers up.
	if len(survivorWhenBothUp) != len(gone) {
		t.Fatalf("the survivor received %d cells with both peers up and %d with one "+
			"gone: the plan was re-walked rather than followed",
			len(survivorWhenBothUp), len(gone))
	}
}

// onlyPeer keeps the packets that arrived at one endpoint. Observers label a
// packet's destination with their own local address, which is the same string
// the signed topology carries as that operator's endpoint.
func onlyPeer(packets []wire.Packet, endpoint string) []wire.Packet {
	kept := make([]wire.Packet, 0, len(packets))
	for _, packet := range packets {
		if packet.Destination == endpoint {
			kept = append(kept, packet)
		}
	}
	return kept
}
