package node

import (
	"bytes"
	"context"
	"encoding/binary"
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

// The operator-to-operator hop header used to go on the wire in the clear. The
// stream ID in it is a hash of the batch payloads, so it was the same value at
// every hop a batch took, and Send re-sealed a relayed cell with a new sender
// and sequence while leaving the rest of the header as it arrived. A passive
// observer did not need a correlation attack to follow a batch across the
// relay fabric: the identifier was written on it. That was measured here, and
// the measurement is what motivated hop header version 2.
//
// Version 2 encrypts the whole cell under the pairwise link key. This test now
// runs the same experiment against the same node and requires the opposite
// result: the marked stream must not be findable in anything the node emits.
//
// The experiment is only worth anything if it would still find the identifier
// when it is there. TestTheMarkedStreamIsFoundWhenItIsPresent below seals the
// same stream under version 1's cleartext layout and requires the search to
// find it, so a search that finds nothing cannot be a search that looks
// nowhere.
func TestARelayedCellDoesNotCarryItsStreamIDOnward(t *testing.T) {
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

	// A stream nothing else could produce, so finding it on the far side
	// would not be a coincidence.
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
	stats := worker.Snapshot()
	if stats.Relayed == 0 {
		t.Skipf("the node relayed nothing in this window (%+v); the measurement needs "+
			"a relayed cell to inspect", stats)
	}

	// Search the whole cell, not the header offsets version 1 used. If the
	// identifier survived anywhere -- moved, re-encoded, or copied into the
	// payload -- this finds it.
	carried := 0
	for _, cell := range seen {
		if bytes.Contains(cell[:], marked[:]) {
			carried++
		}
		if _, err := hop.LocalMetadata(cell); err == nil {
			t.Error("an emitted cell carries an unsealed header, so its routing " +
				"metadata is readable off the wire")
		}
	}
	if carried != 0 {
		t.Fatalf("%d of %d emitted cells still carry the ingress stream ID %x, so a "+
			"passive observer links this batch's ingress hop to its egress hop with no "+
			"correlation attack", carried, len(seen), marked[:8])
	}
	t.Logf("MEASURED: 0 of %d emitted cells carry the ingress stream ID %x, across %d "+
		"relayed cells.", len(seen), marked[:8], stats.Relayed)
}

// The positive control for the search above. It rebuilds version 1's cleartext
// header layout by hand -- magic, sender, ordinal, batch size, flags, then the
// stream ID at byte 12 -- and requires bytes.Contains to find the identifier.
//
// Without this, "no emitted cell carries the stream ID" would be satisfied by
// a search that cannot find a stream ID at all.
func TestTheMarkedStreamIsFoundWhenItIsPresent(t *testing.T) {
	marked := hop.StreamID{
		0xA5, 0x17, 0x9C, 0x42, 0xD0, 0x6B, 0x33, 0xEE,
		0x81, 0x2F, 0x74, 0xBB, 0x08, 0x59, 0xC6, 0x1D,
	}
	var cell fabric.Cell
	for index := range cell[:hop.CiphertextSize] {
		cell[index] = byte(index)
	}
	header := cell[hop.CiphertextSize:]
	copy(header[0:4], []byte{'N', 'H', 'C', 1})
	binary.BigEndian.PutUint16(header[4:6], 2)
	binary.BigEndian.PutUint16(header[6:8], 0)
	binary.BigEndian.PutUint16(header[8:10], 2)
	binary.BigEndian.PutUint16(header[10:12], hop.FlagWork)
	copy(header[12:28], marked[:])

	if !bytes.Contains(cell[:], marked[:]) {
		t.Fatal("the search cannot find a stream ID that is present, so finding none " +
			"in the test above would mean nothing")
	}
}
