package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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
// emission path returned from the scheduler, which closed the socket and
// ended the node. A node going permanently silent is the most visible event a
// passive observer can see, and it was reachable from conditions that are
// local, ordinary, and in an adversary's partial reach.
//
// A resource limit now costs the cell it interrupted. Which failures qualify
// is an allowlist, not a denylist, because the first version of this change
// asked "is this error fatal?" and answered with a list of one -- so a hop
// sequence space that had run out became a counter rather than a stop.

// scriptedWriter stands in for the socket. The errors that decide whether a
// node loses a cell or stops cannot be produced on demand from a real socket:
// ENOBUFS needs a host that is out of buffers. A test restricted to the errors
// it can provoke would be testing those rather than the ones that matter.
//
// It also records the sequence number of every cell that reached the wire,
// which is what a passive observer reads out of the cleartext hop header.
type scriptedWriter struct {
	mu        sync.Mutex
	inner     cellWriter
	failWith  error
	deadline  error
	onWire    []uint32
	destinies []string
}

func (writer *scriptedWriter) SetWriteDeadline(at time.Time) error {
	writer.mu.Lock()
	failure := writer.deadline
	writer.mu.Unlock()
	if failure != nil {
		return failure
	}
	if writer.inner != nil {
		return writer.inner.SetWriteDeadline(at)
	}
	return nil
}

func (writer *scriptedWriter) WriteToUDP(payload []byte, address *net.UDPAddr) (int, error) {
	writer.mu.Lock()
	failure := writer.failWith
	writer.mu.Unlock()
	if failure != nil {
		return 0, failure
	}
	var cell fabric.Cell
	copy(cell[:], payload)
	// The sequence is the one field a sealed cell leaves readable, which is
	// exactly what a passive observer of this link would have, so the trace
	// is built from the same thing an observer sees.
	if sequence, err := hop.WireSequence(cell); err == nil {
		writer.mu.Lock()
		writer.onWire = append(writer.onWire, sequence)
		writer.destinies = append(writer.destinies, address.String())
		writer.mu.Unlock()
	}
	if writer.inner != nil {
		return writer.inner.WriteToUDP(payload, address)
	}
	return len(payload), nil
}

func (writer *scriptedWriter) fail(err error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.failWith = err
}

func (writer *scriptedWriter) sequences() []uint32 {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return append([]uint32(nil), writer.onWire...)
}

// brokenSequence is a hop sequence allocator that fails with a chosen error.
type brokenSequence struct {
	err       error
	returned  []uint32
	issued    uint32
	mu        sync.Mutex
	failAfter uint32
}

func (sequence *brokenSequence) Next() (uint32, error) {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	if sequence.issued >= sequence.failAfter {
		return 0, sequence.err
	}
	sequence.issued++
	return sequence.issued, nil
}

func (sequence *brokenSequence) Return(value uint32) {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	sequence.returned = append(sequence.returned, value)
	if sequence.issued == value {
		sequence.issued--
	}
}

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

// interceptWrites puts a scripted writer in front of the node's socket. Cells
// still go out for real unless the writer is told to fail.
func interceptWrites(worker *Node) *scriptedWriter {
	writer := &scriptedWriter{inner: worker.sink.conn}
	worker.sink.conn = writer
	return writer
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

func nominalTicks(duration time.Duration) uint64 {
	return uint64(duration / (campaignIntervalMillis * time.Millisecond))
}

// The allowlist, tested where it is decided. A first version of this test
// closed the node's socket and called Send, expecting the fatal branch; it
// passed for the wrong reason, because SetWriteDeadline fails on a closed
// socket before WriteToUDP is reached, and mutating the write branch away left
// it green. Mutation testing found that; reading the test did not.
func TestOnlyKnownTransientConditionsCostACell(t *testing.T) {
	transient := []struct {
		name  string
		cause error
	}{
		{"socket buffers exhausted", syscall.ENOBUFS},
		{"host out of memory for the write", syscall.ENOMEM},
		{"socket would block", syscall.EAGAIN},
		{"interrupted before sending", syscall.EINTR},
		{"route withdrawn", syscall.ENETUNREACH},
		{"peer unreachable", syscall.EHOSTUNREACH},
		{"interface down", syscall.ENETDOWN},
		{"write deadline passed", os.ErrDeadlineExceeded},
		{"reservation write failed", hop.ErrSequenceWriteFailed},
		{"wrapped in an OpError, which is how they really arrive",
			&net.OpError{Op: "write", Net: "udp", Err: syscall.ENOBUFS}},
	}
	// Everything else. The two that matter most are the ones the first
	// version of this classification swallowed.
	fatal := []struct {
		name  string
		cause error
	}{
		{"closed socket", net.ErrClosed},
		{"closed socket inside an OpError", &net.OpError{
			Op: "write", Net: "udp", Err: net.ErrClosed}},
		{"hop sequence exhausted", hop.ErrSequenceExhausted},
		{"hop sequence state unreadable", hop.ErrSequenceStateInvalid},
		{"firewall verdict", syscall.EPERM},
		{"destination the kernel will never accept", syscall.EINVAL},
		{"an error nobody thought of", errors.New("something new")},
	}

	for _, testCase := range transient {
		if !sendFailureIsTransient(testCase.cause) {
			t.Errorf("%s was classified as fatal; an ordinary host condition would stop "+
				"the node, which is the loudest event from the quietest cause", testCase.name)
		}
	}
	for _, testCase := range fatal {
		if sendFailureIsTransient(testCase.cause) {
			t.Errorf("%s was classified as a lost cell; it names a condition that does "+
				"not pass, so the node would tick past it forever", testCase.name)
		}
	}

	// And the wrapping the scheduler reads.
	sink := &authenticatedSink{stats: &counters{}}
	dropped := sink.classify("write cell", syscall.ENOBUFS)
	if !errors.Is(dropped, fabric.ErrCellDropped) {
		t.Errorf("a transient error returned %v, which the scheduler will treat as fatal", dropped)
	}
	if !errors.Is(dropped, syscall.ENOBUFS) {
		t.Errorf("the cause was flattened out of %v, so nothing downstream can inspect it", dropped)
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

// A transient condition costs cells and not the node.
func TestATransientSendFailureCostsOneCellAndNotTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	writer := interceptWrites(worker)
	writer.fail(&net.OpError{Op: "write", Net: "udp", Err: syscall.ENOBUFS})

	const duration = 600 * time.Millisecond
	stats, err := runNodeFor(t, worker, duration, nil)
	if errors.Is(err, fabric.ErrDeadlineMissed) {
		t.Skipf("host stalled past the cadence budget: %v", err)
	}
	if err != nil {
		t.Fatalf("an exhausted socket buffer ended the node: %v", err)
	}

	if stats.Sent != 0 {
		t.Errorf("node counted %d sends while every write failed", stats.Sent)
	}
	ticks := nominalTicks(duration)
	if stats.SendDropped < ticks*2/3 {
		t.Errorf("node dropped %d cells over roughly %d ticks; it stopped emitting early",
			stats.SendDropped, ticks)
	}
	if stats.SendDropped > ticks+4 {
		t.Errorf("node attempted %d emissions over roughly %d ticks: failure accelerated the loop",
			stats.SendDropped, ticks)
	}
	t.Logf("%d emissions dropped over a %s run at a %dms cadence, cadence held",
		stats.SendDropped, duration, campaignIntervalMillis)
}

// The corrected half of the same claim. A destination the kernel will never
// accept is a signed topology carrying an endpoint that cannot work, and the
// node must say so rather than tick past it. Writing to port 0 produces the
// real EINVAL, so this is the production path end to end.
func TestAPermanentlyRefusedDestinationStopsTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	for index := range worker.sink.peers {
		worker.sink.peers[index].address = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	}

	stats, err := runNodeFor(t, worker, 5*time.Second, nil)
	if err == nil {
		t.Fatalf("a destination the kernel refuses did not stop the node (%+v)", stats)
	}
	if errors.Is(err, fabric.ErrCellDropped) {
		t.Errorf("a permanent misconfiguration was reported as a lost cell: %v", err)
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("the node stopped with %v, which does not name the cause", err)
	}
	t.Logf("stopped after %d dropped and %d sent: %v", stats.SendDropped, stats.Sent, err)
}

// A transient condition that never clears is a misconfiguration wearing a
// counter. Continuing forever would be the original bug: a node that is up,
// on cadence, and has emitted nothing since it started.
func TestATransientConditionThatNeverClearsEventuallyStopsTheNode(t *testing.T) {
	sink := &authenticatedSink{stats: &counters{}}
	var last error
	for attempt := 1; attempt <= maximumConsecutiveDrops+1; attempt++ {
		last = sink.classify("write cell", syscall.ENOBUFS)
		if !errors.Is(last, fabric.ErrCellDropped) {
			if attempt <= maximumConsecutiveDrops {
				t.Fatalf("stopped after %d consecutive drops, before the %d threshold",
					attempt, maximumConsecutiveDrops)
			}
			break
		}
	}
	if errors.Is(last, fabric.ErrCellDropped) {
		t.Fatalf("%d consecutive drops did not stop the node", maximumConsecutiveDrops+1)
	}
	if !errors.Is(last, syscall.ENOBUFS) {
		t.Errorf("the stop did not name what had been failing: %v", last)
	}

	// And a single success resets it, so a node that is working is never
	// stopped by a long-ago run of bad luck.
	sink.consecutive = 0
	for attempt := 0; attempt < maximumConsecutiveDrops*2; attempt++ {
		if err := sink.classify("write cell", syscall.ENOBUFS); !errors.Is(err, fabric.ErrCellDropped) {
			t.Fatalf("the counter did not reset: stopped again at %d", attempt)
		}
		sink.consecutive = 0
	}
}

// A cell that never reached the socket must not spend a sequence number. The
// hop sequence is in the clear in every header, so a number that is issued and
// discarded leaves a gap: an exact, per-cell count of local send failures,
// readable by the receiving peer and by any observer of the link.
func TestADroppedCellDoesNotBurnASequenceNumberOnTheWire(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	writer := interceptWrites(worker)

	// Alternate: some ticks reach the wire, some fail transiently.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var group sync.WaitGroup
	group.Add(1)
	go func() { defer group.Done(); _ = worker.Run(ctx) }()
	group.Add(1)
	go func() {
		defer group.Done()
		ticker := time.NewTicker(campaignIntervalMillis * time.Millisecond / 2)
		defer ticker.Stop()
		failing := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				failing = !failing
				if failing {
					writer.fail(&net.OpError{Op: "write", Net: "udp", Err: syscall.ENOBUFS})
				} else {
					writer.fail(nil)
				}
			}
		}
	}()
	time.Sleep(900 * time.Millisecond)
	cancel()
	group.Wait()

	observed := writer.sequences()
	stats := worker.Snapshot()
	if stats.SendDropped == 0 {
		t.Fatalf("nothing was dropped; the comparison would be vacuous (%+v)", stats)
	}
	if len(observed) < 4 {
		t.Fatalf("only %d cells reached the wire; the comparison would be vacuous", len(observed))
	}
	// Consecutive on the wire, with no gaps: a passive observer counting hop
	// sequences sees an unbroken run and learns nothing about the drops.
	for index := 1; index < len(observed); index++ {
		if observed[index] != observed[index-1]+1 {
			t.Errorf("hop sequence jumped from %d to %d on the wire: %d locally dropped "+
				"cells are countable by anyone watching the link",
				observed[index-1], observed[index], stats.SendDropped)
			break
		}
	}
	t.Logf("%d cells on the wire carrying sequences %d..%d with no gap, against %d "+
		"locally dropped", len(observed), observed[0], observed[len(observed)-1],
		stats.SendDropped)
}

// The hop sequence space running out, and the durable state that keeps it
// unique being unreadable, are not resource limits. Both mean authenticated
// sequence numbers can no longer be guaranteed unique, and both say so in
// their own message: rotate the topology epoch. A node that ticked past
// either would be a failed cryptographic precondition downgraded to a counter.
func TestAnUnusableHopSequenceStopsTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	for _, testCase := range []struct {
		name  string
		cause error
	}{
		{"exhausted", hop.ErrSequenceExhausted},
		{"state unreadable", hop.ErrSequenceStateInvalid},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			network, identities, endpoints := nodeTestTopologyWithCadence(
				t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
			worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
			worker.sink.sequence = &brokenSequence{err: testCase.cause}

			stats, err := runNodeFor(t, worker, 5*time.Second, nil)
			if err == nil {
				t.Fatalf("an unusable hop sequence did not stop the node (%+v)", stats)
			}
			if errors.Is(err, fabric.ErrCellDropped) {
				t.Errorf("%s was reported as a lost cell: %v", testCase.name, err)
			}
			if !errors.Is(err, testCase.cause) {
				t.Errorf("the node stopped with %v, which does not name the cause", err)
			}
			if stats.SendDropped != 0 {
				t.Errorf("%d cells were counted as dropped before the node stopped",
					stats.SendDropped)
			}
		})
	}
}

// A reservation that could not be written is the disk-full case, and it is the
// one sequence failure that costs cells rather than the node.
func TestAFullDiskUnderTheSequenceReservationCostsCellsNotTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	worker.sink.sequence = &brokenSequence{
		err: fmt.Errorf("%w: %v", hop.ErrSequenceWriteFailed, syscall.ENOSPC),
	}
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
	ticks := nominalTicks(duration)
	if stats.SendDropped < ticks*2/3 {
		t.Errorf("node dropped %d cells over roughly %d ticks; it stopped emitting early",
			stats.SendDropped, ticks)
	}
	t.Logf("%d emissions dropped for want of a sequence number over %s, cadence held",
		stats.SendDropped, duration)
}

// Which peer a tick is addressed to must stay a function of the tick index and
// the signed plan. If a dropped cell held its place back, the next tick would
// re-address the same failing peer, and a single unreachable peer would take
// the whole node down with it -- silently, since every send would then fail.
func TestADroppedCellStillConsumesItsPlaceInThePeerPlan(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, rotatingPeerPlan)
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	if len(worker.sink.peers) != 2 {
		t.Fatalf("expected a two-peer plan, got %d peers", len(worker.sink.peers))
	}
	refused := worker.sink.peers[0].address.String()
	writer := &selectiveWriter{
		inner:  worker.sink.conn,
		broken: refused,
		fail:   &net.OpError{Op: "write", Net: "udp", Err: syscall.ENOBUFS},
	}
	worker.sink.conn = writer

	const duration = 600 * time.Millisecond
	stats, err := runNodeFor(t, worker, duration, nil)
	if errors.Is(err, fabric.ErrDeadlineMissed) {
		t.Skipf("host stalled past the cadence budget: %v", err)
	}
	if err != nil {
		t.Fatalf("one failing peer ended the node: %v", err)
	}
	if stats.Sent == 0 {
		t.Fatalf("nothing reached the working peer: a dropped cell held its place in "+
			"the plan, so the failing peer was re-addressed every tick (%+v)", stats)
	}
	if stats.SendDropped == 0 {
		t.Fatalf("nothing was dropped; the failing peer was never addressed (%+v)", stats)
	}
	if drift := int(stats.Sent) - int(stats.SendDropped); drift > 2 || drift < -2 {
		t.Errorf("%d cells sent against %d dropped over a rotating two-peer plan: "+
			"the rotation is not following the tick index", stats.Sent, stats.SendDropped)
	}
	t.Logf("%d cells to the working peer, %d dropped at the failing one, rotation held",
		stats.Sent, stats.SendDropped)
}

// selectiveWriter fails writes to one destination and passes the rest through.
type selectiveWriter struct {
	inner  cellWriter
	broken string
	fail   error
}

func (writer *selectiveWriter) SetWriteDeadline(at time.Time) error {
	return writer.inner.SetWriteDeadline(at)
}

func (writer *selectiveWriter) WriteToUDP(payload []byte, address *net.UDPAddr) (int, error) {
	if address.String() == writer.broken {
		return 0, writer.fail
	}
	return writer.inner.WriteToUDP(payload, address)
}

// The change removed an alarm: a node that no longer stops can be up, on
// cadence, and silently dropping every cell, which a supervisor asking only
// "is the process up" cannot see. last_sent_at is what replaced it, so the
// replacement has to be tested on the production path and not only against
// hand-built Stats structs. Two mutations survived a first attempt at this --
// never storing the timestamp, and storing it before the write rather than
// after -- and the second is precisely the bug that would defeat the
// supervision story while looking fine.
func TestTheLivenessTimestampFollowsWhatActuallyWentOut(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a node against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)

	// A working node advances it.
	worker := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	started := time.Now().UTC()
	healthy, err := runNodeFor(t, worker, 400*time.Millisecond, nil)
	if err != nil && !errors.Is(err, fabric.ErrDeadlineMissed) {
		t.Fatalf("healthy node stopped: %v", err)
	}
	if healthy.LastSentAt.IsZero() {
		t.Fatal("a node that emitted normally never recorded an emission")
	}
	if healthy.LastSentAt.Before(started) {
		t.Errorf("last_sent_at is %s, before the run began at %s", healthy.LastSentAt, started)
	}

	// A node dropping every cell does not. This is the mutation that survived:
	// storing the timestamp before the write makes a totally failing node
	// report a fresh last_sent_at forever, and --check-health call it healthy.
	silent := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	writer := interceptWrites(silent)
	writer.fail(&net.OpError{Op: "write", Net: "udp", Err: syscall.ENOBUFS})
	stats, err := runNodeFor(t, silent, 600*time.Millisecond, nil)
	if err != nil && !errors.Is(err, fabric.ErrDeadlineMissed) {
		t.Fatalf("silent node stopped: %v", err)
	}
	if stats.SendDropped == 0 {
		t.Fatalf("nothing was dropped; the comparison would be vacuous (%+v)", stats)
	}
	if !stats.LastSentAt.IsZero() {
		t.Errorf("a node that emitted nothing reports last_sent_at %s, so a supervisor "+
			"would call it healthy while it drops every cell", stats.LastSentAt)
	}

	// And it stops advancing once emission stops, rather than tracking the
	// attempt: a node that worked and then broke must go stale.
	broke := buildLimitedNode(t, network, identities, endpoints, t.TempDir(), 64)
	brokeWriter := interceptWrites(broke)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var group sync.WaitGroup
	group.Add(1)
	go func() { defer group.Done(); _ = broke.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)
	brokeWriter.fail(&net.OpError{Op: "write", Net: "udp", Err: syscall.ENOBUFS})
	frozen := broke.Snapshot().LastSentAt
	time.Sleep(400 * time.Millisecond)
	after := broke.Snapshot()
	cancel()
	group.Wait()
	if frozen.IsZero() {
		t.Fatal("the node never emitted before it was broken")
	}
	if after.LastSentAt.After(frozen) {
		t.Errorf("last_sent_at advanced from %s to %s while every write was failing",
			frozen, after.LastSentAt)
	}
	t.Logf("healthy %s; silent zero; broken frozen at %s with %d dropped",
		healthy.LastSentAt.Format(time.RFC3339Nano), frozen.Format(time.RFC3339Nano),
		after.SendDropped)
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
	ticks := int(nominalTicks(duration))
	if len(capture.Packets) < ticks*2/3 {
		t.Errorf("observer saw %d cells over roughly %d ticks: the node fell behind or stopped",
			len(capture.Packets), ticks)
	}
	t.Logf("%d health writes failed; %d cells still went out over %s",
		stats.HealthDeferred, len(capture.Packets), duration)
}

// The structural half of the two-world question, which is decidable on any
// host: whatever else differs, a node at its cache limit emits cells of one
// size, never bursts, and uses the destinations its signed plan gives it.
//
// Scope, because a first version of this test overstated it: this varies a
// receive-side limit only. It is not evidence about the send path -- the
// dropped-cell tests above are -- and it makes no claim about emission rate,
// which is a statistical comparison and lives in the campaign below.
func TestAReceiveSideLimitChangesNothingStructuralAboutWhatIsEmitted(t *testing.T) {
	if testing.Short() {
		t.Skip("runs two nodes against a cadence")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, rotatingPeerPlan)

	saturated := runLimitRound(t, network, identities, endpoints, 1, "saturated")
	spacious := runLimitRound(t, network, identities, endpoints, 4096, "spacious")

	if saturated.stats.CacheRejected == 0 {
		t.Fatalf("the saturated world never reached its cache limit (%+v): "+
			"the comparison would be vacuous", saturated.stats)
	}
	if spacious.stats.CacheRejected != 0 {
		t.Fatalf("the spacious world hit its cache limit too (%+v): "+
			"the two worlds are the same world", spacious.stats)
	}
	// The worlds must differ internally, or nothing is being compared. The
	// work/cover mix is the difference, and at this layer it is readable off
	// the wire -- the hop header is authenticated but not encrypted; see
	// live/uplink/distinguisher_test.go and docs/PUBLICATION_INGRESS.md.
	// Asserting the mix moved keeps that limitation measured, not mentioned.
	if saturated.stats.Relayed >= spacious.stats.Relayed {
		t.Errorf("the saturated world relayed %d cells and the spacious one %d: "+
			"the limit did not change the work/cover mix", saturated.stats.Relayed,
			spacious.stats.Relayed)
	}

	ceiling := int(time.Second/time.Millisecond)/campaignIntervalMillis + 2
	for _, world := range []limitWorld{saturated, spacious} {
		if world.runError != nil {
			t.Logf("%s could not hold cadence on this host (%v); the size and burst "+
				"assertions below still apply to what it did emit",
				world.name, world.runError)
		}
		if len(world.capture.Packets) == 0 {
			t.Fatalf("the %s world emitted nothing", world.name)
		}
		if sizes := world.capture.Sizes(); len(sizes) != 1 || sizes[0] != fabric.CellSize {
			t.Errorf("%s emitted sizes %v", world.name, sizes)
		}
		if burst := world.capture.MaxBurst(time.Second); burst > ceiling {
			t.Errorf("%s produced %d cells in one second, above the cadence ceiling %d",
				world.name, burst, ceiling)
		}
		if split := destinationSplit(world.capture); len(split) < 2 {
			t.Errorf("%s used %d destinations against a two-peer rotating plan",
				world.name, len(split))
		}
	}
	t.Logf("saturated: stored %d, cache-rejected %d, relayed %d, covered %d",
		saturated.stats.Stored, saturated.stats.CacheRejected,
		saturated.stats.Relayed, saturated.stats.CoverSent)
	t.Logf("spacious:  stored %d, cache-rejected %d, relayed %d, covered %d",
		spacious.stats.Stored, spacious.stats.CacheRejected,
		spacious.stats.Relayed, spacious.stats.CoverSent)
}

// The statistical half. Whether a resource limit moves the emission *rate* is
// a two-world comparison whose control spread is a property of the host, so it
// belongs with the other wall-clock campaigns rather than in a per-push suite.
//
// That is not a way of avoiding a failing test. An earlier version of this
// comparison ran per-push and failed CI intermittently in both directions --
// with a message that read like a privacy finding when what had actually
// happened was that one world's node missed its lateness budget on a loaded
// runner. Measuring a rate difference of a fraction of a percent against a
// control floor measured from three runs is not something a shared container
// can do; on a quiet machine it is.
func TestAResourceLimitDoesNotChangeTheEmissionRate(t *testing.T) {
	campaignEnabled(t)
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, rotatingPeerPlan)

	// The noise floor first, from worlds that differ by nothing. The
	// tolerance has to be measured rather than chosen, and it has to be
	// measured over more than one pair: two sequential runs with independent
	// start times differ by a cell purely from where a 900 ms window falls
	// against a 20 ms cadence, and a single pair reports that as 0 about half
	// the time. A floor of 0 then fails every honest run.
	controls := []limitWorld{
		runLimitRound(t, network, identities, endpoints, 4096, "control-a"),
		runLimitRound(t, network, identities, endpoints, 4096, "control-b"),
		runLimitRound(t, network, identities, endpoints, 4096, "control-c"),
	}
	// A control that could not hold cadence is this host, not this code, and
	// nothing can be decided on it. A *treatment* world that cannot hold
	// cadence while every control could is the opposite: it is the limit
	// under test changing whether the node keeps its schedule, which is the
	// finding this test exists to make. Skipping on that -- which an earlier
	// version did, for both -- would have hidden it.
	for _, control := range controls {
		if control.runError != nil {
			t.Skipf("the %s world could not hold cadence on this host (%v); nothing "+
				"can be decided here", control.name, control.runError)
		}
	}
	spread, controlDrift := 0.0, 0.0
	for i := range controls {
		for j := i + 1; j < len(controls); j++ {
			if gap := rateGap(controls[i].capture, controls[j].capture); gap > spread {
				spread = gap
			}
			drift := splitDrift(destinationSplit(controls[i].capture),
				destinationSplit(controls[j].capture))
			if drift > controlDrift {
				controlDrift = drift
			}
		}
	}
	// A host whose own noise is a fifth of the signal cannot decide this.
	// Reporting that is a result; passing quietly is not.
	if len(controls[0].capture.Packets) < 8 {
		t.Fatalf("the control worlds emitted %d cells; nothing can be measured",
			len(controls[0].capture.Packets))
	}
	if spread > 0.2 {
		t.Skipf("control emission rates differ by %.3f between worlds that differ by "+
			"nothing: this host cannot decide the comparison", spread)
	}

	saturated := runLimitRound(t, network, identities, endpoints, 1, "saturated")
	spacious := runLimitRound(t, network, identities, endpoints, 4096, "spacious")

	for _, world := range []limitWorld{saturated, spacious} {
		if world.runError != nil {
			t.Fatalf("the %s world's node stopped (%v) while all three controls held "+
				"cadence: the limit under test changed whether the node keeps its "+
				"schedule", world.name, world.runError)
		}
	}
	if saturated.stats.CacheRejected == 0 {
		t.Fatalf("the saturated world never reached its cache limit (%+v): "+
			"the comparison would be vacuous", saturated.stats)
	}
	if spacious.stats.CacheRejected != 0 {
		t.Fatalf("the spacious world hit its cache limit too (%+v): "+
			"the two worlds are the same world", spacious.stats)
	}
	// The floor cannot go below the comparison's own repeatability. Three
	// control pairs can agree to four decimal places by luck, and a floor of
	// zero then reports ordinary jitter as a finding.
	if spread < minimumRateFloor {
		spread = minimumRateFloor
	}
	if controlDrift < minimumSplitFloor {
		controlDrift = minimumSplitFloor
	}
	t.Logf("measured control floor over three worlds that differ by nothing: %.4f "+
		"emission rate, %.4f destination share", spread, controlDrift)
	t.Logf("saturated: stored %d, cache-rejected %d, queue-dropped %d",
		saturated.stats.Stored, saturated.stats.CacheRejected, saturated.stats.QueueDropped)
	t.Logf("spacious:  stored %d, cache-rejected %d, queue-dropped %d",
		spacious.stats.Stored, spacious.stats.CacheRejected, spacious.stats.QueueDropped)

	// Rate rather than raw count. A 900 ms observation window is not phase
	// aligned to a 20 ms cadence, so two identical worlds differ by a whole
	// cell depending on where the window edges fall -- and three controls can
	// all land on the same count by luck, leaving a floor of zero that then
	// fails an honest run. Emission rate over each world's own observed span
	// has no such cliff, and it is the quantity the claim is actually about.
	if gap := rateGap(saturated.capture, spacious.capture); gap > spread {
		t.Errorf("emission rate differs by %.4f between the worlds (%.2f/s saturated "+
			"over %d cells, %.2f/s spacious over %d cells), against a measured control "+
			"floor of %.4f", gap,
			emissionRate(saturated.capture), len(saturated.capture.Packets),
			emissionRate(spacious.capture), len(spacious.capture.Packets), spread)
	}

	saturatedSplit := destinationSplit(saturated.capture)
	spaciousSplit := destinationSplit(spacious.capture)
	if len(saturatedSplit) < 2 {
		t.Fatalf("the rotating plan produced %d destinations; the split comparison "+
			"would be vacuous", len(saturatedSplit))
	}
	if drift := splitDrift(saturatedSplit, spaciousSplit); drift > controlDrift {
		t.Errorf("destination share moved by %.3f between the worlds, against %.3f "+
			"between two runs that differ by nothing", drift, controlDrift)
	}

}

// The floors below which this comparison cannot resolve anything: two percent
// of the emission rate, and one percent of a destination share.
const (
	minimumRateFloor  = 0.02
	minimumSplitFloor = 0.01
)

type limitWorld struct {
	name     string
	capture  *wire.Capture
	stats    Stats
	runError error
}

// runLimitRound feeds one node a stream of authentic public replication work
// from a peer it accepts, and records what it emits.
func runLimitRound(t *testing.T, network topology.Verified,
	identities map[string]ed25519.PrivateKey, endpoints []string,
	cacheStreams int, name string) limitWorld {
	t.Helper()

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
	var runError error
	group.Add(1)
	go func() {
		defer group.Done()
		runError = worker.Run(ctx)
	}()

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

	if errors.Is(runError, context.Canceled) || errors.Is(runError, net.ErrClosed) {
		runError = nil
	}
	for _, packet := range packets {
		capture.Add(packet)
	}
	return limitWorld{name: name, capture: capture, stats: worker.Snapshot(), runError: runError}
}

// emissionRate is cells per second over the span a capture actually covers,
// which is insensitive to where the observation window's edges fell.
func emissionRate(capture *wire.Capture) float64 {
	packets := append([]wire.Packet(nil), capture.Packets...)
	if len(packets) < 2 {
		return 0
	}
	sort.Slice(packets, func(i, j int) bool { return packets[i].At.Before(packets[j].At) })
	span := packets[len(packets)-1].At.Sub(packets[0].At)
	if span <= 0 {
		return 0
	}
	return float64(len(packets)-1) / span.Seconds()
}

// rateGap is the relative difference between two captures' emission rates.
func rateGap(left, right *wire.Capture) float64 {
	a, b := emissionRate(left), emissionRate(right)
	if a == 0 || b == 0 {
		return 1
	}
	gap := (a - b) / ((a + b) / 2)
	if gap < 0 {
		gap = -gap
	}
	return gap
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

// splitDrift is the largest share difference between two destination splits.
func splitDrift(left, right map[string]float64) float64 {
	worst := 0.0
	seen := map[string]struct{}{}
	for name := range left {
		seen[name] = struct{}{}
	}
	for name := range right {
		seen[name] = struct{}{}
	}
	for name := range seen {
		drift := left[name] - right[name]
		if drift < 0 {
			drift = -drift
		}
		if drift > worst {
			worst = drift
		}
	}
	return worst
}
