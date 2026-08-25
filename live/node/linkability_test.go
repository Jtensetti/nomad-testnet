package node

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
)

// observeCells reads whole cells rather than packet metadata, because what
// this file is about is the bytes a passive observer can read off the wire.
func observeCells(t *testing.T, observer *net.UDPConn, ctx context.Context) []fabric.Cell {
	t.Helper()
	var seen []fabric.Cell
	buffer := make([]byte, fabric.CellSize+64)
	for {
		if err := observer.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
			return seen
		}
		count, _, err := observer.ReadFromUDP(buffer)
		if err == nil {
			if count == fabric.CellSize {
				var cell fabric.Cell
				copy(cell[:], buffer[:count])
				seen = append(seen, cell)
			}
			continue
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			if ctx.Err() != nil {
				return seen
			}
			continue
		}
		return seen
	}
}

// The operator-to-operator hop header is authenticated but not encrypted: the
// 48 bytes after the mix ciphertext go on the wire in the clear. The work flag
// being visible there is known and documented (docs/PUBLICATION_INGRESS.md is
// the response, and live/uplink/distinguisher_test.go measures the separation
// as perfect). The stream ID in the same header has been carried as a noted
// risk since the uplink profile was built, without ever being measured.
//
// It is measured here. The stream ID is a hash of the batch payloads, so it is
// the same value at every hop a batch takes, and Send re-seals a relayed cell
// with a new sender and sequence while leaving the rest of the header as it
// arrived. A passive observer therefore does not need a correlation attack to
// follow a batch across the relay fabric: the identifier is written on it.
//
// This does not contradict a claim the project makes -- the threat model
// commits to size, destination and count for a global passive observer, and
// relay work is driven by public replication policy rather than by any
// reader's activity. It is recorded as a measured property rather than left as
// a note, because "we think this is fine" and "we measured what it is" are
// different statements, and only one of them belongs in a threat model.
func TestARelayedCellCarriesItsStreamIDOnwardInTheClear(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)

	conn, err := net.ListenUDP("udp", resolveCampaignAddress(t, endpoints[2]))
	if err != nil {
		t.Fatalf("bind source: %v", err)
	}
	defer func() { _ = conn.Close() }()
	source := &hostileSession{
		conn: conn, target: resolveCampaignAddress(t, endpoints[0]),
		key: [32]byte{byte(2 + 11)}, sender: 2, receiver: 0,
		context: hop.Context{
			TopologyDigest: network.Digest, NetworkID: network.Document.NetworkID,
			Epoch: network.Document.Epoch, Receiver: 0,
		},
	}

	// A stream nothing else could produce, so finding it on the far side is
	// not a coincidence.
	source.stream = hop.StreamID{
		0xA5, 0x17, 0x9C, 0x42, 0xD0, 0x6B, 0x33, 0xEE,
		0x81, 0x2F, 0x74, 0xBB, 0x08, 0x59, 0xC6, 0x1D,
	}
	marked := source.stream

	observers := bindObservers(t, endpoints, []int{1})
	defer closeObservers(observers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(700*time.Millisecond, cancel)
	defer stop.Stop()

	var group sync.WaitGroup
	group.Add(1)
	go func() { defer group.Done(); _ = worker.Run(ctx) }()

	// Both cells of the batch, so the node has a complete stream to relay.
	for ordinal := 0; ordinal < 2; ordinal++ {
		metadata, err := hop.WorkMetadata(marked, uint16(ordinal), 2)
		if err != nil {
			t.Fatal(err)
		}
		var cell fabric.Cell
		for index := range cell[:hop.CiphertextSize] {
			cell[index] = byte(index) ^ byte(ordinal)
		}
		source.sequence++
		if err := hop.Seal(&cell, metadata, source.sender, source.sequence,
			source.key, source.context); err != nil {
			t.Fatal(err)
		}
		if _, err := source.conn.WriteToUDP(cell[:], source.target); err != nil {
			t.Fatal(err)
		}
	}

	seen := observeCells(t, observers[0], ctx)
	cancel()
	group.Wait()

	if len(seen) == 0 {
		t.Fatal("the node emitted nothing; the measurement is vacuous")
	}
	carried := 0
	for _, cell := range seen {
		metadata, err := hop.MetadataFromCell(cell)
		if err != nil {
			continue
		}
		if metadata.Stream == marked {
			carried++
			if metadata.Sender == source.sender {
				t.Errorf("the relayed cell kept the original sender slot %d; only the "+
					"stream ID was expected to survive the hop", metadata.Sender)
			}
		}
	}

	stats := worker.Snapshot()
	if stats.Relayed == 0 {
		t.Skipf("the node relayed nothing in this window (%+v); the measurement needs "+
			"a relayed cell to inspect", stats)
	}
	if carried == 0 {
		t.Fatalf("no emitted cell carried the marked stream ID although %d were relayed: "+
			"either the header changed or the batch did not go out", stats.Relayed)
	}
	t.Logf("MEASURED: %d of %d emitted cells carry the ingress stream ID %x unchanged in "+
		"the cleartext hop header. A passive observer links this batch's ingress hop to "+
		"its egress hop by reading bytes 1164..1180, with no correlation attack.",
		carried, len(seen), marked[:8])
}
