package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"github.com/Jtensetti/nomad-testnet/live/wire"
)

// PROD-14 asks what a node emits when it hits a resource limit. The honest
// answer used to be "nothing, ever again": every local failure in the
// emission path -- a full disk under the hop sequence reservation, a socket
// buffer the host had run out of, a health file that could not be written --
// returned from the scheduler, which closed the socket and ended the node.
//
// That is the worst possible answer to the question. A node going permanently
// silent is the most visible event a passive observer can see, and it was
// reachable from conditions that are local, ordinary, and in an adversary's
// partial reach. These tests fix what the boundary is: a resource limit costs
// work, never the schedule.

// buildLimitedNode is buildCampaignNode with the cache limit under the test's
// control, so a world can be driven into its limit while its control is not.
func buildLimitedNode(t *testing.T, network topology.Verified,
	identities map[string]ed25519.PrivateKey, endpoints []string,
	scratch string, cacheStreams int) *Node {
	t.Helper()
	self := network.Document.Operators[0]
	cache, err := rawcache.Open(filepath.Join(scratch, "raw"), cacheStreams)
	if err != nil {
		t.Fatal(err)
	}
	outbound := map[uint16][32]byte{}
	for _, peer := range self.PeerPlan {
		outbound[peer] = [32]byte{byte(peer + 1)}
	}
	inbound := map[uint16][32]byte{}
	for _, peer := range network.IncomingPeers(self.Index) {
		inbound[peer.Index] = [32]byte{byte(peer.Index + 11)}
	}
	worker, err := New(Config{
		Topology: network,
		Secrets: topology.VerifiedSecrets{
			Operator: self, Identity: identities[self.ID],
			OutboundKeys: outbound, InboundKeys: inbound,
		},
		ListenAddress: endpoints[0], Cache: cache,
		SequencePath: filepath.Join(scratch, "sequence"),
		HealthPath:   filepath.Join(scratch, "health.json"),
		CacheSweep:   time.Hour,
	})
	if err != nil {
		t.Fatalf("build node: %v", err)
	}
	return worker
}

// runNodeFor runs a node until the deadline and returns its final counters.
// Errors are reported rather than failed on, because the point of most of
// these tests is which errors end the run.
func runNodeFor(t *testing.T, worker *Node, duration time.Duration, during func(context.Context)) (Stats, error) {
	t.Helper()
	// Cancellation rather than a deadline: Node.Run reports a clean stop for
	// context.Canceled, and a test that could not tell a clean stop from a
	// crash would pass for the wrong reason.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(duration, cancel)
	defer stop.Stop()
	var group sync.WaitGroup
	if during != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			during(ctx)
		}()
	}
	started := time.Now()
	err := worker.Run(ctx)
	ran := time.Since(started)
	group.Wait()
	// A node that returns well before its deadline stopped on its own.
	if err == nil && ran < duration*3/4 {
		t.Errorf("node returned after %s of a %s run without an error", ran, duration)
	}
	return worker.Snapshot(), err
}

// A destination the kernel refuses is a real send failure, not a simulated
// one: writing to port 0 returns EINVAL from sendto, in the same shape as the
// ENOBUFS, EPERM and ENETUNREACH a deployed node meets on a busy or
// rate-limited host.
func TestASendFailureCostsOneCellAndNotTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	for index := range worker.sink.peers {
		worker.sink.peers[index].address = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	}

	const duration = 600 * time.Millisecond
	stats, err := runNodeFor(t, worker, duration, nil)
	if errors.Is(err, fabric.ErrDeadlineMissed) {
		t.Skipf("host stalled past the cadence budget: %v", err)
	}
	if err != nil {
		t.Fatalf("a refused destination ended the node: %v", err)
	}

	if stats.Sent != 0 {
		t.Errorf("node counted %d sends to a destination the kernel refuses", stats.Sent)
	}
	// The node must have kept trying for the whole run, not stopped at the
	// first refusal. Two thirds of the nominal tick count is well clear of
	// scheduling noise and far above the 1 the old behaviour produced.
	ticks := uint64(duration / (campaignIntervalMillis * time.Millisecond))
	if stats.SendDropped < ticks*2/3 {
		t.Errorf("node dropped %d cells over roughly %d ticks; it stopped emitting early",
			stats.SendDropped, ticks)
	}
	// And it must not have made up for them: a scheduler that spun on failure
	// would run far past the cadence.
	if stats.SendDropped > ticks+4 {
		t.Errorf("node attempted %d emissions over roughly %d ticks: failure accelerated the loop",
			stats.SendDropped, ticks)
	}
	t.Logf("%d emissions dropped over a %s run at a %dms cadence, cadence held",
		stats.SendDropped, duration, campaignIntervalMillis)
}

// Dropping is deliberately narrow, and the narrowness is the safety property:
// a sink that treated every write error as a lost cell would treat its own
// closed socket as one too, and a node whose socket had gone would sit on the
// cadence forever, emitting nothing and reporting nothing wrong.
//
// The rule is tested where it is decided rather than through the node, and
// that is not a shortcut. A first version of this test closed the node's
// socket and called Send; it passed, and it passed for the wrong reason --
// SetWriteDeadline fails on a closed socket before WriteToUDP is ever
// reached, so the branch under test never ran. Mutating the write branch away
// left the test green. Every failure site in Send now routes through
// sendFailureIsFatal, and this is a table over the error values the operating
// system actually produces there.
func TestOnlyAClosedSocketEndsTheSchedule(t *testing.T) {
	fatal := []struct {
		name  string
		cause error
	}{
		{"closed socket", net.ErrClosed},
		// This is the shape the socket layer really returns: the sentinel
		// arrives wrapped in an OpError, not bare.
		{"closed socket inside an OpError", &net.OpError{
			Op: "write", Net: "udp", Err: net.ErrClosed,
		}},
	}
	local := []struct {
		name  string
		cause error
	}{
		{"socket buffers exhausted", syscall.ENOBUFS},
		{"local rate limiter", syscall.EPERM},
		{"route withdrawn", syscall.ENETUNREACH},
		{"destination refused", syscall.EINVAL},
		{"write deadline passed", os.ErrDeadlineExceeded},
		{"disk full under the sequence reservation", syscall.ENOSPC},
		{"a wrapped host error", &net.OpError{Op: "write", Net: "udp", Err: syscall.ENOBUFS}},
	}

	for _, tc := range fatal {
		if !sendFailureIsFatal(tc.cause) {
			t.Errorf("%s was classified as a lost cell; the node would hold the cadence "+
				"forever against a socket that is gone", tc.name)
		}
	}
	for _, tc := range local {
		if sendFailureIsFatal(tc.cause) {
			t.Errorf("%s was classified as fatal; an ordinary host condition would stop "+
				"the node, which is the loudest possible event from the quietest cause", tc.name)
		}
	}

	// And the wrapping the scheduler reads: a lost cell must carry
	// ErrCellDropped and be counted; a fatal one must carry neither.
	sink := &authenticatedSink{stats: &counters{}}
	dropped := sink.classify("write cell", syscall.ENOBUFS)
	if !errors.Is(dropped, fabric.ErrCellDropped) {
		t.Errorf("a host error returned %v, which the scheduler will treat as fatal", dropped)
	}
	if sink.stats.sendDropped.Load() != 1 {
		t.Errorf("a lost cell was not counted: %d", sink.stats.sendDropped.Load())
	}
	ended := sink.classify("write cell", net.ErrClosed)
	if errors.Is(ended, fabric.ErrCellDropped) {
		t.Errorf("a closed socket was swallowed as a dropped cell: %v", ended)
	}
	if !errors.Is(ended, net.ErrClosed) {
		t.Errorf("a closed socket lost its sentinel on the way out: %v", ended)
	}
	if sink.stats.sendDropped.Load() != 1 {
		t.Errorf("a fatal error was counted as a lost cell: %d", sink.stats.sendDropped.Load())
	}
}

// The hop sequence is reserved from disk before it is used, so a full disk
// reaches the emission path directly: Send cannot seal a cell without a
// sequence number. That path is the one an adversary gets closest to -- disk
// pressure on an operator is ordinary, and before this change it stopped the
// node outright.
//
// The failure is injected by replacing the sequence directory with a regular
// file, so the reservation's CreateTemp fails with ENOTDIR. That is
// uid-independent: unlike a mode bit it fails for root too, so the test
// measures the code rather than the user the suite happens to run as.
func TestAFullDiskUnderTheSequenceReservationCostsCellsNotTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	scratch := t.TempDir()
	worker := buildLimitedNode(t, network, identities, endpoints, scratch, 64)

	// Open a sequence on a good path, take away the directory under it, then
	// force the next reservation: that is what a disk which filled up
	// mid-run looks like from inside Send.
	broken, err := hop.OpenFileSequence(filepath.Join(scratch, "usable", "sequence"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(scratch, "usable")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratch, "usable"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken.ExhaustReservationForTest()
	worker.sink.sequence = broken

	observers := bindObservers(t, endpoints, []int{1})
	defer closeObservers(observers)
	var packets []wire.Packet

	const duration = 600 * time.Millisecond
	stats, err := runNodeFor(t, worker, duration, func(ctx context.Context) {
		packets = observeAll(observers, ctx)
	})
	if errors.Is(err, fabric.ErrDeadlineMissed) {
		t.Skipf("host stalled past the cadence budget: %v", err)
	}
	if err != nil {
		t.Fatalf("a full disk under the sequence reservation ended the node: %v", err)
	}
	if len(packets) != 0 {
		t.Errorf("observer saw %d cells while no sequence number could be reserved", len(packets))
	}
	ticks := uint64(duration / (campaignIntervalMillis * time.Millisecond))
	if stats.SendDropped < ticks*2/3 {
		t.Errorf("node dropped %d cells over roughly %d ticks; it stopped emitting early",
			stats.SendDropped, ticks)
	}
	if stats.SendDropped > ticks+4 {
		t.Errorf("node attempted %d emissions over roughly %d ticks: failure accelerated the loop",
			stats.SendDropped, ticks)
	}
	t.Logf("%d emissions dropped for want of a sequence number over %s, cadence held",
		stats.SendDropped, duration)
}

// Which peer a tick is addressed to must stay a function of the tick index and
// the signed plan. If a dropped cell held its place back, the next tick would
// re-address the same failing peer, and a single unreachable peer would take
// the whole node down with it -- silently, since every send would then fail.
//
// The plan rotates over two peers and one of them is given a destination the
// kernel refuses, so half the ticks drop and half must still go out.
func TestADroppedCellStillConsumesItsPlaceInThePeerPlan(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, rotatingPeerPlan)
	observers := bindObservers(t, endpoints, []int{1, 2})
	defer closeObservers(observers)

	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	if len(worker.sink.peers) != 2 {
		t.Fatalf("expected a two-peer plan, got %d peers", len(worker.sink.peers))
	}
	reachable := worker.sink.peers[1].address.String()
	worker.sink.peers[0].address = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

	const duration = 600 * time.Millisecond
	var packets []wire.Packet
	stats, err := runNodeFor(t, worker, duration, func(ctx context.Context) {
		packets = observeAll(observers, ctx)
	})
	if errors.Is(err, fabric.ErrDeadlineMissed) {
		t.Skipf("host stalled past the cadence budget: %v", err)
	}
	if err != nil {
		t.Fatalf("one refused peer ended the node: %v", err)
	}

	if stats.Sent == 0 {
		t.Fatalf("nothing reached the reachable peer: a dropped cell held its place in "+
			"the plan, so the refused peer was re-addressed every tick (%+v)", stats)
	}
	if stats.SendDropped == 0 {
		t.Fatalf("nothing was dropped; the refused peer was never addressed (%+v)", stats)
	}
	// Half each, give or take the tick the run ended on.
	if drift := int(stats.Sent) - int(stats.SendDropped); drift > 2 || drift < -2 {
		t.Errorf("%d cells sent against %d dropped over a rotating two-peer plan: "+
			"the rotation is not following the tick index", stats.Sent, stats.SendDropped)
	}
	for _, packet := range packets {
		if packet.Destination != reachable {
			t.Errorf("a cell reached %s, which is not the reachable peer %s",
				packet.Destination, reachable)
		}
	}
	t.Logf("%d cells to the reachable peer, %d dropped at the refused one, rotation held",
		stats.Sent, stats.SendDropped)
}

// The health file is local observability. It is written to disk on a schedule,
// which means a full disk fails it, which used to stop the node -- turning a
// local disk condition into a network-visible outage precisely when an
// operator most needed the node to still be running.
//
// The failure is injected by making the health path's parent a regular file,
// so MkdirAll fails with ENOTDIR. That is uid-independent: unlike a mode bit,
// it fails for root too, so the test measures the code rather than the user
// the suite happens to run as.
func TestAnUnwritableHealthPathDoesNotStopTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	scratch := t.TempDir()
	blocked := filepath.Join(scratch, "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	worker := buildLimitedNode(t, network, identities, endpoints, scratch, 64)
	worker.config.HealthPath = filepath.Join(blocked, "health.json")

	observers := bindObservers(t, endpoints, []int{1})
	defer closeObservers(observers)
	capture := &wire.Capture{Label: "unwritable-health"}

	// Two health ticks, so the failure is met more than once.
	const duration = 2200 * time.Millisecond
	stats, err := runNodeFor(t, worker, duration, func(ctx context.Context) {
		observeInto(observers[0], ctx, capture)
	})
	if errors.Is(err, fabric.ErrDeadlineMissed) {
		t.Skipf("host stalled past the cadence budget: %v", err)
	}
	if err != nil {
		t.Fatalf("an unwritable health path ended the node: %v", err)
	}
	if stats.HealthDeferred < 2 {
		t.Errorf("node recorded %d deferred health writes; the failure was not exercised twice",
			stats.HealthDeferred)
	}
	if len(capture.Packets) == 0 {
		t.Fatal("node emitted nothing while its health file was unwritable")
	}
	ticks := int(duration / (campaignIntervalMillis * time.Millisecond))
	if len(capture.Packets) < ticks*2/3 {
		t.Errorf("observer saw %d cells over roughly %d ticks: the node fell behind or stopped",
			len(capture.Packets), ticks)
	}
	t.Logf("%d health writes failed; %d cells still went out over %s",
		stats.HealthDeferred, len(capture.Packets), duration)
}

// The two-world question. One node's raw cache is at its stream limit and its
// relay queue is overflowing; the other has room for everything. Both are fed
// the same public replication traffic. What a passive observer sees must not
// separate them.
//
// The worlds differ in what the node does internally -- one stores and relays,
// the other rejects -- and that difference is exactly what the fixed cadence
// exists to hide. The observable compared here is what the threat model claims
// for a global passive observer: cell size, destination and count.
func TestAResourceLimitDoesNotChangeTheEmittedTrace(t *testing.T) {
	if testing.Short() {
		t.Skip("runs two nodes against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, rotatingPeerPlan)

	// One stream, so every later stream is refused: the cache is at its limit
	// from the second stream onwards.
	saturated := runLimitRound(t, network, identities, endpoints, 1)
	spacious := runLimitRound(t, network, identities, endpoints, 4096)

	if saturated.stats.CacheRejected == 0 {
		t.Fatalf("the saturated world never reached its cache limit (%+v): "+
			"the comparison would be vacuous", saturated.stats)
	}
	if spacious.stats.CacheRejected != 0 {
		t.Fatalf("the spacious world hit its cache limit too (%+v): "+
			"the two worlds are the same world", spacious.stats)
	}
	t.Logf("saturated: stored %d, cache-rejected %d, queue-dropped %d",
		saturated.stats.Stored, saturated.stats.CacheRejected, saturated.stats.QueueDropped)
	t.Logf("spacious:  stored %d, cache-rejected %d, queue-dropped %d",
		spacious.stats.Stored, spacious.stats.CacheRejected, spacious.stats.QueueDropped)

	// What this test does not claim. The two worlds emit the same number of
	// equally sized cells to the same destinations, and they emit different
	// *kinds* of cell: the spacious world relays work, the saturated one
	// falls back to cover. At the operator-to-operator layer that difference
	// is readable straight off the wire, because the hop header is
	// authenticated but not encrypted -- see
	// live/uplink/distinguisher_test.go, which measures the separation as
	// perfect, and docs/PUBLICATION_INGRESS.md for why the publisher uplink
	// uses a different cell profile.
	//
	// So the boundary this test establishes is precise: a resource limit does
	// not change the size, count, destination or cadence of what an operator
	// emits. It does change the work/cover mix, which is already public at
	// this layer. Asserting that the mix actually moved keeps the limitation
	// measured rather than merely mentioned.
	if saturated.stats.Relayed >= spacious.stats.Relayed {
		t.Errorf("the saturated world relayed %d cells and the spacious one %d: "+
			"the limit did not change the work/cover mix, so the note above is untested",
			saturated.stats.Relayed, spacious.stats.Relayed)
	}
	t.Logf("work/cover mix, public at this layer: saturated relayed %d and covered %d; "+
		"spacious relayed %d and covered %d",
		saturated.stats.Relayed, saturated.stats.CoverSent,
		spacious.stats.Relayed, spacious.stats.CoverSent)

	// Size: one size, and the right one, in both worlds.
	for _, world := range []limitWorld{saturated, spacious} {
		sizes := world.capture.Sizes()
		if len(sizes) != 1 || sizes[0] != fabric.CellSize {
			t.Errorf("%s emitted sizes %v", world.name, sizes)
		}
	}

	// Count: the cadence is public, so both worlds emit the same number of
	// cells over the same wall-clock window. Scheduling noise on a shared
	// host moves this by a cell or two; a resource limit that changed the
	// emission rate would move it by far more.
	difference := saturated.capture.Packets
	other := spacious.capture.Packets
	gap := len(difference) - len(other)
	if gap < 0 {
		gap = -gap
	}
	if allowed := 3; gap > allowed {
		t.Errorf("saturated emitted %d cells and spacious %d, a gap of %d above the %d "+
			"a shared host explains", len(difference), len(other), gap, allowed)
	}

	// Destination: the peer plan rotates, so a resource limit that changed
	// which peer a tick went to would show up as a different split. Both
	// worlds must have used both destinations in the same proportion.
	saturatedSplit := destinationSplit(saturated.capture)
	spaciousSplit := destinationSplit(spacious.capture)
	if len(saturatedSplit) < 2 {
		t.Fatalf("the rotating plan produced %d destinations; the split comparison "+
			"would be vacuous", len(saturatedSplit))
	}
	if len(saturatedSplit) != len(spaciousSplit) {
		t.Fatalf("saturated used %d destinations and spacious %d",
			len(saturatedSplit), len(spaciousSplit))
	}
	for destination, saturatedShare := range saturatedSplit {
		spaciousShare, seen := spaciousSplit[destination]
		if !seen {
			t.Errorf("only the saturated world sent to %s", destination)
			continue
		}
		if drift := saturatedShare - spaciousShare; drift > 0.1 || drift < -0.1 {
			t.Errorf("share of cells to %s was %.3f saturated and %.3f spacious",
				destination, saturatedShare, spaciousShare)
		}
	}

	// Burst: an absolute ceiling, so it holds whatever the host noise is. A
	// node that queued cells while rejecting and released them afterwards
	// would exceed it.
	ceiling := int(time.Second/time.Millisecond)/campaignIntervalMillis + 2
	for _, world := range []limitWorld{saturated, spacious} {
		if burst := world.capture.MaxBurst(time.Second); burst > ceiling {
			t.Errorf("%s produced %d cells in one second, above the cadence ceiling %d",
				world.name, burst, ceiling)
		}
	}
}

type limitWorld struct {
	name    string
	capture *wire.Capture
	stats   Stats
}

// runLimitRound feeds one node a stream of authentic public replication work
// from a peer it accepts, and records what it emits.
func runLimitRound(t *testing.T, network topology.Verified,
	identities map[string]ed25519.PrivateKey, endpoints []string, cacheStreams int) limitWorld {
	t.Helper()
	name := "saturated"
	if cacheStreams > 1 {
		name = "spacious"
	}

	// Peer 2 is both the source of the work and one of the two destinations
	// the rotating plan emits to, so one socket plays both roles. Binding a
	// separate observer there would collide with the source.
	source, err := net.ListenUDP("udp", resolveCampaignAddress(t, endpoints[2]))
	if err != nil {
		t.Fatalf("bind work source: %v", err)
	}
	defer func() { _ = source.Close() }()
	observers := bindObservers(t, endpoints, []int{1})
	defer closeObservers(observers)
	observers = append(observers, source)

	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), cacheStreams)

	capture := &wire.Capture{Label: name}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(900*time.Millisecond, cancel)
	defer stop.Stop()

	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		if err := worker.Run(ctx); err != nil && !errors.Is(err, fabric.ErrDeadlineMissed) {
			t.Logf("%s node stopped: %v", name, err)
		}
	}()

	// Distinct streams at a steady rate: enough to exceed a one-stream cache
	// many times over, slow enough that the flood itself is not the variable
	// under test. Both worlds receive the same offered load.
	group.Add(1)
	go func() {
		defer group.Done()
		session := &hostileSession{
			conn: source, target: resolveCampaignAddress(t, endpoints[0]),
			key: [32]byte{byte(2 + 11)}, sender: 2, receiver: 0,
			context: hop.Context{
				TopologyDigest: network.Digest, NetworkID: network.Document.NetworkID,
				Epoch: network.Document.Epoch, Receiver: 0,
			},
		}
		session.stream[15] = 1
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cell := session.workCell(t, true)
				_, _ = session.conn.WriteToUDP(cell[:], session.target)
			}
		}
	}()

	packets := observeAll(observers, ctx)
	cancel()
	group.Wait()
	for _, packet := range packets {
		capture.Add(packet)
	}
	return limitWorld{name: name, capture: capture, stats: worker.Snapshot()}
}

// destinationSplit is the share of a capture's cells that went to each
// destination, which is what a passive observer of the peer plan sees.
func destinationSplit(capture *wire.Capture) map[string]float64 {
	counts := map[string]int{}
	for _, packet := range capture.Packets {
		counts[packet.Destination]++
	}
	shares := make(map[string]float64, len(counts))
	total := float64(len(capture.Packets))
	if total == 0 {
		return shares
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		shares[name] = float64(counts[name]) / total
	}
	return shares
}
