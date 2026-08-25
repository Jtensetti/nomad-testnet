package node

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// The other half of PROD-14's resource question is memory. A node reads from
// a socket an adversary can saturate, and every buffer, map and cache entry it
// allocates in response is allocated at that adversary's request. If any of
// them grows with the volume received rather than with public policy, a flood
// ends in an OOM kill -- which, like the node stopping, is an externally
// observable event caused by an adversary rather than by the schedule.
//
// The claim is that every allocation on the receive path is bounded by the
// signed topology or by a configured limit: the read buffer is one cell, the
// peer and replay maps come from the topology, the relay queue is capped by
// the traffic class, and the cache is capped by its stream limit. This tests
// the claim two ways -- the exact structural bounds, which are deterministic,
// and the heap itself, which is not but is the thing that actually kills a
// process.

// floodSteadily saturates the node with authentic, distinct work from a peer
// it accepts, and reports how many datagrams it managed to send.
func floodSteadily(t *testing.T, network topology.Verified, endpoints []string,
	ctx context.Context, sent *atomic.Int64) {
	t.Helper()
	source, err := net.ListenUDP("udp", resolveCampaignAddress(t, endpoints[2]))
	if err != nil {
		t.Errorf("bind flood source: %v", err)
		return
	}
	defer func() { _ = source.Close() }()
	session := &hostileSession{
		conn: source, target: resolveCampaignAddress(t, endpoints[0]),
		key: [32]byte{byte(2 + 11)}, sender: 2, receiver: 0,
		context: hop.Context{
			TopologyDigest: network.Digest, NetworkID: network.Document.NetworkID,
			Epoch: network.Document.Epoch, Receiver: 0,
		},
	}
	session.stream[15] = 1
	for ctx.Err() == nil {
		cell := session.workCell(t, true)
		if _, err := session.conn.WriteToUDP(cell[:], session.target); err == nil {
			sent.Add(1)
		}
	}
}

// heapInUse settles the collector and reports the live heap. Two collections
// rather than one: the first runs finalizers that the second then reclaims,
// so a single call reads high by whatever was pending.
func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

func TestASustainedFloodCannotGrowTheHeapWithoutBound(t *testing.T) {
	if testing.Short() {
		t.Skip("floods a node for several seconds")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	const cacheStreams = 32
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), cacheStreams)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var group sync.WaitGroup
	var runError error
	group.Add(1)
	go func() {
		defer group.Done()
		runError = worker.Run(ctx)
	}()
	var sent atomic.Int64
	group.Add(1)
	go func() {
		defer group.Done()
		floodSteadily(t, network, endpoints, ctx, &sent)
	}()

	// A bounded system reaches a steady state. Compare two marks under the
	// same continuous load rather than start against end, so the reading is
	// about growth rather than about the working set a node needs at all.
	settle := time.NewTimer(1500 * time.Millisecond)
	select {
	case <-settle.C:
	case <-ctx.Done():
	}
	early := heapInUse()
	earlySent := sent.Load()

	sustain := time.NewTimer(3 * time.Second)
	select {
	case <-sustain.C:
	case <-ctx.Done():
	}
	late := heapInUse()
	lateSent := sent.Load()

	cancel()
	group.Wait()
	if runError != nil && !errors.Is(runError, context.Canceled) &&
		!errors.Is(runError, net.ErrClosed) {
		if errors.Is(runError, fabric.ErrDeadlineMissed) {
			t.Skipf("host stalled past the cadence budget: %v", runError)
		}
		t.Fatalf("node stopped under flood: %v", runError)
	}

	delivered := lateSent - earlySent
	if delivered < 1000 {
		t.Fatalf("only %d datagrams were delivered between the two marks; the "+
			"measurement is vacuous", delivered)
	}
	stats := worker.Snapshot()
	t.Logf("%d datagrams delivered between marks; heap %d KiB -> %d KiB; "+
		"stored %d, cache-rejected %d, queue-dropped %d",
		delivered, early/1024, late/1024,
		stats.Stored, stats.CacheRejected, stats.QueueDropped)

	// The structural bounds, which are exact. These are the reason the heap
	// is expected to hold; asserting them separately means a heap reading
	// that happens to look fine cannot hide a bound that has been removed.
	streams, err := worker.config.Cache.CompleteStreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) > cacheStreams {
		t.Errorf("cache holds %d complete streams against a %d limit", len(streams), cacheStreams)
	}
	capacity := int(network.Document.Traffic.QueueCapacity)
	if queued := worker.queue.Len(); queued > capacity {
		t.Errorf("relay queue holds %d cells against a %d capacity", queued, capacity)
	}
	if len(worker.replay) != len(network.IncomingPeers(0)) {
		t.Errorf("replay windows: %d, against %d signed incoming peers",
			len(worker.replay), len(network.IncomingPeers(0)))
	}
	if len(worker.incoming) != len(network.IncomingPeers(0)) {
		t.Errorf("peer table: %d entries, against %d signed incoming peers",
			len(worker.incoming), len(network.IncomingPeers(0)))
	}

	// And the heap. Thousands of datagrams arrived between the marks; a
	// receive path that retained anything per datagram would show it here.
	// The ceiling is generous because a Go heap under load is not quiet, and
	// generous is enough: unbounded growth under this load is megabytes per
	// second, not kilobytes.
	const ceiling = 8 << 20
	if late > early && late-early > ceiling {
		t.Errorf("heap grew by %d KiB across %d delivered datagrams, above the %d KiB "+
			"ceiling: something on the receive path retains per-datagram state",
			(late-early)/1024, delivered, ceiling/1024)
	}
}

// The bounds above are only meaningful if the flood actually reached them.
// This drives the same node until its cache and queue are both refusing and
// checks that refusal is what happens, rather than growth.
func TestTheCacheAndQueueBoundsAreReachedRatherThanGrown(t *testing.T) {
	if testing.Short() {
		t.Skip("floods a node")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	const cacheStreams = 4
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), cacheStreams)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(1500*time.Millisecond, cancel)
	defer stop.Stop()
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); _ = worker.Run(ctx) }()
	var sent atomic.Int64
	go func() { defer group.Done(); floodSteadily(t, network, endpoints, ctx, &sent) }()
	group.Wait()

	stats := worker.Snapshot()
	if stats.CacheRejected == 0 {
		t.Errorf("a %d-stream cache under a flood of %d datagrams rejected nothing: "+
			"either the limit is not enforced or the flood never landed (%+v)",
			cacheStreams, sent.Load(), stats)
	}
	if stats.Stored > uint64(cacheStreams)*uint64(hop.MaximumBatch) {
		t.Errorf("cache stored %d cells, beyond what %d streams of at most %d can hold",
			stats.Stored, cacheStreams, hop.MaximumBatch)
	}
	t.Logf("%d datagrams offered: %d stored, %d cache-rejected, %d queue-dropped",
		sent.Load(), stats.Stored, stats.CacheRejected, stats.QueueDropped)
}
