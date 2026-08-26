package node

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func markedCell(source uint16, ordinal int) fabric.Cell {
	var cell fabric.Cell
	cell[0] = byte(source)
	cell[1] = byte(ordinal >> 8)
	cell[2] = byte(ordinal)
	return cell
}

func sourceOf(cell fabric.Cell) uint16 { return uint16(cell[0]) }

// The claim PROD-20 asks for, measured rather than argued: one operator
// sending far faster than the rest takes its own share and nothing more.
//
// Before this queue, the relay line was a single bounded FIFO that every peer
// filled. A flooding operator filled it and every other operator's work was
// dropped at the door until the flood stopped -- bounded memory, unbounded
// unfairness.
func TestAFloodingSourceCannotTakeAnotherSourcesShare(t *testing.T) {
	const (
		capacity = 64
		sources  = 4
		flooder  = uint16(1)
	)
	queue, err := NewFairQueue(capacity, []uint16{0, 1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}

	// The flood arrives first and at a hundred times the rate, which is the
	// order that would have starved everyone else.
	for ordinal := 0; ordinal < capacity*100; ordinal++ {
		queue.Enqueue(flooder, markedCell(flooder, ordinal))
	}
	accepted := map[uint16]int{}
	for _, quiet := range []uint16{0, 2, 3} {
		for ordinal := 0; ordinal < 8; ordinal++ {
			if queue.Enqueue(quiet, markedCell(quiet, ordinal)) {
				accepted[quiet]++
			}
		}
	}

	for _, quiet := range []uint16{0, 2, 3} {
		if accepted[quiet] != 8 {
			t.Errorf("source %d had %d of 8 cells accepted after the flood; a flood took "+
				"its share", quiet, accepted[quiet])
		}
	}

	// And on the way out, the flooder gets one turn in four rather than the
	// whole line.
	served := map[uint16]int{}
	for taken := 0; taken < 16; taken++ {
		cell, err := queue.NextCell(context.Background())
		if err != nil {
			t.Fatalf("queue ran dry after %d cells: %v", taken, err)
		}
		served[sourceOf(cell)]++
	}
	for source := uint16(0); source < sources; source++ {
		if served[source] != 4 {
			t.Errorf("over 16 emissions source %d was served %d times, not the fair 4: %v",
				source, served[source], served)
		}
	}

	dropped := queue.Dropped()
	if dropped[flooder] == 0 {
		t.Fatal("the flood was not dropped anywhere, so nothing was bounded")
	}
	for _, quiet := range []uint16{0, 2, 3} {
		if dropped[quiet] != 0 {
			t.Errorf("source %d lost %d cells to a flood it did not send", quiet, dropped[quiet])
		}
	}
	t.Logf("MEASURED: the flooder sent %d cells, kept %d, and lost %d to its own share; "+
		"every other source kept all 8 and lost none",
		capacity*100, queue.PerSource(), dropped[flooder])
}

// The total bound is the one the configuration asks for. A per-source share
// that multiplies out to more than the capacity would be a memory bound
// removed in the name of fairness.
func TestTheFairQueueKeepsTheConfiguredTotalBound(t *testing.T) {
	for _, shape := range []struct{ capacity, sources int }{
		{64, 4}, {64, 3}, {12, 5}, {1, 1}, {1000, 7},
	} {
		slots := make([]uint16, shape.sources)
		for index := range slots {
			slots[index] = uint16(index)
		}
		queue, err := NewFairQueue(shape.capacity, slots)
		if err != nil {
			t.Fatalf("capacity %d over %d sources: %v", shape.capacity, shape.sources, err)
		}
		for _, source := range slots {
			for ordinal := 0; ordinal < shape.capacity*2; ordinal++ {
				queue.Enqueue(source, markedCell(source, ordinal))
			}
		}
		if queue.Len() > shape.capacity {
			t.Errorf("capacity %d over %d sources held %d cells",
				shape.capacity, shape.sources, queue.Len())
		}
		if queue.PerSource()*shape.sources > shape.capacity {
			t.Errorf("capacity %d over %d sources gives a share of %d, which multiplies "+
				"out past the bound", shape.capacity, shape.sources, queue.PerSource())
		}
	}
}

// More signed operators than queue slots has no fair answer that respects the
// bound, so it is a configuration error rather than something to round away.
func TestAShareSmallerThanOneCellIsRefused(t *testing.T) {
	if _, err := NewFairQueue(3, []uint16{0, 1, 2, 3}); err == nil {
		t.Fatal("a capacity smaller than the operator set was accepted")
	}
	if _, err := NewFairQueue(0, []uint16{0}); err == nil {
		t.Fatal("a zero capacity was accepted")
	}
	if _, err := NewFairQueue(8, nil); err == nil {
		t.Fatal("a queue with no sources was accepted")
	}
}

// A slot that is not in the signed set has no line and cannot make one. This
// is the same rule the peer set follows, and it is why a Sybil cannot buy a
// share by sending.
func TestAnUnknownSourceGetsNoShare(t *testing.T) {
	queue, err := NewFairQueue(16, []uint16{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if queue.Enqueue(7, markedCell(7, 0)) {
		t.Fatal("a slot outside the signed set was given queue space")
	}
	if queue.Len() != 0 {
		t.Fatalf("the queue holds %d cells from an unknown source", queue.Len())
	}
	if queue.Dropped()[7] != 0 {
		t.Fatal("an unknown source was counted as a drop, which would let a stranger " +
			"write to this node's diagnostics")
	}
}

// The rotation must not depend on who has work: a source's turn is a function
// of the tick. Otherwise the order in which sources are served would carry
// information about which sources are busy.
func TestTheRotationDoesNotDependOnWhoHasWork(t *testing.T) {
	queue, err := NewFairQueue(64, []uint16{0, 1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	// Only source 2 has work. It must be served every time, and the cursor
	// must still be advancing underneath.
	for ordinal := 0; ordinal < 8; ordinal++ {
		queue.Enqueue(2, markedCell(2, ordinal))
	}
	for taken := 0; taken < 8; taken++ {
		cell, err := queue.NextCell(context.Background())
		if err != nil {
			t.Fatalf("a queue with work reported none after %d: %v", taken, err)
		}
		if sourceOf(cell) != 2 {
			t.Fatalf("served source %d when only 2 had work", sourceOf(cell))
		}
	}

	// An empty queue reports no work rather than blocking or inventing one.
	if _, err := queue.NextCell(context.Background()); err != fabric.ErrNoWork {
		t.Fatalf("an empty queue returned %v", err)
	}
}

// Order within one source is preserved. Fairness is between sources; a queue
// that also reordered a single source's cells would break batch reassembly for
// no gain.
func TestOrderIsPreservedWithinASource(t *testing.T) {
	queue, err := NewFairQueue(32, []uint16{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	for ordinal := 0; ordinal < 8; ordinal++ {
		queue.Enqueue(0, markedCell(0, ordinal))
		queue.Enqueue(1, markedCell(1, ordinal))
	}
	next := map[uint16]int{}
	for taken := 0; taken < 16; taken++ {
		cell, err := queue.NextCell(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		source := sourceOf(cell)
		ordinal := int(cell[1])<<8 | int(cell[2])
		if ordinal != next[source] {
			t.Fatalf("source %d produced ordinal %d, expected %d", source, ordinal, next[source])
		}
		next[source]++
	}
}

// A full line drops the incoming cell and touches nothing else. An eviction
// policy that reached into another line would be the unfairness this type
// exists to remove.
func TestAFullLineDropsItsOwnNewestAndNobodyElses(t *testing.T) {
	queue, err := NewFairQueue(8, []uint16{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	share := queue.PerSource()
	for ordinal := 0; ordinal < share; ordinal++ {
		if !queue.Enqueue(0, markedCell(0, ordinal)) {
			t.Fatalf("source 0 was refused within its own share at %d", ordinal)
		}
	}
	if !queue.Enqueue(1, markedCell(1, 0)) {
		t.Fatal("source 1 was refused while source 0 was full")
	}
	if queue.Enqueue(0, markedCell(0, share)) {
		t.Fatal("source 0 exceeded its share")
	}

	// Source 0's earlier cells all survived: the overflow cost the newcomer,
	// not the work already accepted.
	seen := 0
	for {
		cell, err := queue.NextCell(context.Background())
		if err != nil {
			break
		}
		if sourceOf(cell) == 0 {
			if int(cell[1])<<8|int(cell[2]) != seen {
				t.Fatalf("source 0's order changed at %d", seen)
			}
			seen++
		}
	}
	if seen != share {
		t.Fatalf("source 0 kept %d of its %d accepted cells", seen, share)
	}
}

// The end-to-end form of the claim, against a running node rather than a data
// structure: one signed operator flooding at full speed must not stop another
// signed operator's work from being admitted and relayed.
//
// Both halves have to hold for this to pass. The cache decides what is
// admitted, and before the share it refused every new stream once full, so the
// quiet peer's batch never reached the queue. The queue decides what is
// emitted, and before the rotation the flood filled it, so the quiet peer's
// batch sat behind thousands of cells that arrived first.
func TestAFloodFromOnePeerDoesNotStarveAnother(t *testing.T) {
	if testing.Short() {
		t.Skip("floods a live node")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, rotatingPeerPlan)

	self := network.Document.Operators[0]
	incoming := network.IncomingPeers(self.Index)
	if len(incoming) < 2 {
		t.Skipf("this topology gives node 0 only %d incoming peers; the comparison "+
			"needs two", len(incoming))
	}
	flooder, quiet := incoming[0], incoming[1]

	// A cache big enough that neither peer is bounded by the total, so what
	// is measured is the share rather than the ceiling.
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)

	dial := func(peer topology.Operator) *hostileSession {
		conn, err := net.ListenUDP("udp", resolveCampaignAddress(t, peer.Endpoint))
		if err != nil {
			t.Fatalf("bind %s: %v", peer.ID, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return &hostileSession{
			conn: conn, target: resolveCampaignAddress(t, endpoints[0]),
			key: [32]byte{byte(peer.Index + 11)}, sender: peer.Index, receiver: self.Index,
			context: hop.Context{
				TopologyDigest: network.Digest, NetworkID: network.Document.NetworkID,
				Epoch: network.Document.Epoch, Receiver: self.Index,
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(1200*time.Millisecond, cancel)
	defer stop.Stop()

	var group sync.WaitGroup
	group.Add(1)
	go func() { defer group.Done(); _ = worker.Run(ctx) }()

	floodSession := dial(flooder)
	group.Add(1)
	go func() {
		defer group.Done()
		for ctx.Err() == nil {
			cell := floodSession.workCell(t, true)
			_, _ = floodSession.conn.WriteToUDP(cell[:], floodSession.target)
		}
	}()

	// Let the flood get ahead, so the quiet peer arrives at a node that is
	// already saturated. That is the situation the share exists for.
	time.Sleep(400 * time.Millisecond)

	quietSession := dial(quiet)

	// Fixed payloads, so every resend of an ordinal is the same cell and the
	// cache treats a repeat as a duplicate rather than as equivocation. The
	// stream ID is derived from them rather than invented: it is a hash of
	// the batch, and a cache that completed a stream whose ID did not match
	// its own contents would be accepting a forgery. Randomness makes the
	// batch unique, so finding it later is not a coincidence.
	var payloads [2][hop.CiphertextSize]byte
	for ordinal := range payloads {
		if _, err := rand.Read(payloads[ordinal][:]); err != nil {
			t.Fatal(err)
		}
	}
	marked, err := hop.StreamFor([][hop.CiphertextSize]byte{payloads[0], payloads[1]})
	if err != nil {
		t.Fatal(err)
	}
	quietSession.stream = marked
	// The flood saturates the loopback receive buffer, so a single datagram
	// from the quiet peer is likely to be dropped by the kernel before the
	// node sees it. That is the harness, not the property under test: a peer
	// on a real link retries. Resending the batch for the rest of the window
	// separates "the node refused this work" from "this datagram was lost",
	// which is the difference the test is about.
	send := func() {
		for ordinal := 0; ordinal < 2; ordinal++ {
			metadata, err := hop.WorkMetadata(marked, uint16(ordinal), 2)
			if err != nil {
				t.Error(err)
				return
			}
			var cell fabric.Cell
			copy(cell[:hop.CiphertextSize], payloads[ordinal][:])
			quietSession.sequence++
			if err := hop.Seal(&cell, metadata, quietSession.sender, quietSession.sequence,
				quietSession.key, quietSession.context); err != nil {
				t.Error(err)
				return
			}
			_, _ = quietSession.conn.WriteToUDP(cell[:], quietSession.target)
		}
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	attempts := 0
	for time.Now().Before(deadline) && ctx.Err() == nil {
		send()
		attempts++
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	group.Wait()

	stats := worker.Snapshot()
	if stats.CacheRejected == 0 {
		t.Fatalf("nothing was ever rejected (%+v); the flood never reached a limit and "+
			"the comparison is vacuous", stats)
	}

	streams, err := worker.config.Cache.CompleteStreams()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, stream := range streams {
		if stream == marked {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("the quiet peer's batch was not admitted while another peer flooded: "+
			"%d complete streams cached, %+v", len(streams), stats)
	}
	t.Logf("MEASURED: under a continuous flood from operator %d that drove %d rejections, "+
		"operator %d's two-cell batch was admitted and completed after %d sends",
		flooder.Index, stats.CacheRejected, quiet.Index, attempts)
}
