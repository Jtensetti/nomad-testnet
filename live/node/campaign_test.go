package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"github.com/Jtensetti/nomad-testnet/live/wire"
)

// These are the wire-level form of the core privacy invariant: two worlds
// differing only in private user activity must look the same to an observer
// of the sender's socket. They run the production Node -- real scheduler,
// real sealing, real UDP writes -- and observe arrivals on a separate socket.
//
// The claim is split in two because the two halves are evidenced very
// differently.
//
// What a cell contains and where it goes is decided by the signed plan and
// the emission ordinal, so it can be asserted exactly and cheaply, and it is:
// see TestWireContentIsIndependentOfPrivateActivity.
//
// When a cell leaves is a timing property of a shared host, and a single
// container gives ambient stalls far larger than any effect worth measuring.
// TestWireTimingIsIndependentOfPrivateActivityUnderStress therefore runs a
// positive control first -- idle against idle -- and refuses to report a
// result when the host cannot resolve the effect. It skips loudly rather
// than passing quietly, because a test that could not run has not passed.
//
// Neither test is WAN evidence. Both are loopback, single host, userspace
// receive timestamps, seconds rather than days, and analysed by the same
// party that wrote the system. E-01, E-02, E-06 and E-09 stay open.

const (
	campaignIntervalMillis = 20
	campaignLateness       = 200
	campaignDuration       = 1000 * time.Millisecond
	campaignRounds         = 3

	// Decision tolerances, mirroring PREREGISTRATION.md. A difference must
	// also exceed the run's own idle-versus-idle control to be a finding.
	cadenceTolerance = 0.02
)

type campaignWorld struct {
	name string
	// private drives private-side activity. A nil function is the idle
	// world: the difference between the two worlds is exactly this.
	private func(ctx context.Context, node *Node, scratch string)
}

type campaignStressor struct {
	name string
	run  func(ctx context.Context, scratch string)
}

// TestWireContentIsIndependentOfPrivateActivity asserts the exactly-checkable
// half: for the same number of scheduled emissions, the sizes and the ordered
// destinations on the wire are identical whether or not the work queue has
// anything in it. This is what makes cover and work interchangeable at a
// slot; if it fails, no amount of timing regularity would help.
func TestWireContentIsIndependentOfPrivateActivity(t *testing.T) {
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, rotatingPeerPlan)

	const emissions = 24
	traces := map[string][]wire.Packet{}
	for _, world := range []string{"idle", "active"} {
		observers := bindObservers(t, endpoints, []int{1, 2})
		scratch := t.TempDir()
		worker := buildCampaignNode(t, network, identities, endpoints, scratch)

		if world == "active" {
			// Fill the queue past the number of emissions so that every
			// single slot in this run carries work rather than cover.
			fillWorkQueue(t, worker, emissions*2)
		}

		captured := make(chan []wire.Packet, 1)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { captured <- observeAll(observers, ctx) }()

		for emitted := 0; emitted < emissions; emitted++ {
			cell, err := worker.cover.NextCell(ctx)
			if err != nil {
				t.Fatalf("%s: source: %v", world, err)
			}
			if err := worker.sink.Send(ctx, cell); err != nil {
				t.Fatalf("%s: send: %v", world, err)
			}
			// Two observer sockets are merged by arrival time, so emissions
			// are spaced far enough apart that the merge order is the send
			// order. Back-to-back sends can be delivered out of order across
			// two sockets, which would be a property of the harness rather
			// than of the sender.
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
		cancel()
		traces[world] = <-captured
		closeObservers(observers)
		_ = worker.conn.Close()
	}

	idle, active := traces["idle"], traces["active"]
	if len(idle) != emissions || len(active) != emissions {
		t.Fatalf("emission counts differ from the schedule: idle=%d active=%d want %d",
			len(idle), len(active), emissions)
	}
	for index := range idle {
		if idle[index].Size != fabric.CellSize || active[index].Size != fabric.CellSize {
			t.Fatalf("cell %d size idle=%d active=%d, want %d",
				index, idle[index].Size, active[index].Size, fabric.CellSize)
		}
		if idle[index].Destination != active[index].Destination {
			t.Errorf("cell %d went to %s when idle and %s when active",
				index, idle[index].Destination, active[index].Destination)
		}
	}
	// The plan rotates, so a constant destination would mean the assertion
	// above compared nothing.
	distinct := map[string]struct{}{}
	for _, packet := range idle {
		distinct[packet.Destination] = struct{}{}
	}
	if len(distinct) < 2 {
		t.Fatalf("peer plan did not rotate; the destination comparison is vacuous")
	}
}

func TestWireTimingIsIndependentOfPrivateActivityUnderStress(t *testing.T) {
	if testing.Short() {
		t.Skip("wire campaign needs wall-clock time")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)

	idle := campaignWorld{name: "idle"}
	active := campaignWorld{name: "active", private: drivePrivateActivity}

	stressors := []campaignStressor{
		{name: "baseline", run: func(context.Context, string) {}},
		{name: "cpu-starvation", run: burnCPU},
		{name: "disk-pressure", run: pressureDisk},
	}

	// Captures are evidence, not fixtures: they are regenerated every run and
	// belong with the other CI evidence artifacts rather than in the tree.
	artifacts := filepath.Join("..", "..", "runtime", "evidence", "wire-campaign")
	if err := os.MkdirAll(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, stressor := range stressors {
		t.Run(stressor.name, func(t *testing.T) {
			if stressor.name == "cpu-starvation" && runtime.GOMAXPROCS(0) < 2 {
				t.Skip("cannot starve the scheduler without starving the test")
			}

			// Series are interleaved round by round so that drift in the
			// host's own load falls on all of them equally. Three of the
			// four series are idle: they differ by nothing, so the spread
			// among them measures this host's noise directly rather than
			// assuming it. A single control pair is one sample of a bursty,
			// heavy-tailed distribution, and one unlucky stall in it reads
			// as a finding.
			controls := []*wire.Capture{
				{Label: stressor.name + "-control-a"},
				{Label: stressor.name + "-control-b"},
				{Label: stressor.name + "-control-c"},
			}
			treatment := &wire.Capture{Label: stressor.name + "-active"}
			idleStops, activeStops := 0, 0
			for round := 0; round < campaignRounds; round++ {
				for _, control := range controls {
					if runCampaignRound(t, network, identities, endpoints, idle, stressor, control) {
						idleStops++
					}
				}
				if runCampaignRound(t, network, identities, endpoints, active, stressor, treatment) {
					activeStops++
				}
			}

			// The noise floor is the widest gap between two worlds that are
			// identical. The signal is the narrowest gap between the active
			// world and any idle world; taking the narrowest is the
			// conservative choice, because it makes a finding harder to claim.
			noise := worldGap{}
			for left := 0; left < len(controls); left++ {
				for right := left + 1; right < len(controls); right++ {
					noise = noise.widen(worldDistance(controls[left], controls[right]))
				}
			}
			signal := worldDistance(controls[0], treatment)
			for _, control := range controls[1:] {
				signal = signal.narrow(worldDistance(control, treatment))
			}
			t.Logf("control spread: cadence %.4f (packet count %.3f)", noise.cadence, noise.count)
			t.Logf("idle vs active: cadence %.4f (packet count %.3f)", signal.cadence, signal.count)
			// Early termination is reported, never gated. It is a rare,
			// coarse event: campaignRounds rounds give that many Bernoulli
			// samples per world, which cannot separate a private-dependent
			// effect from an unlucky host. Deciding it needs the sustained
			// campaign of E-03 and E-09, not a CI run.
			t.Logf("rounds ending early: idle %d/%d, active %d/%d "+
				"(reported only; too few samples to decide here)",
				idleStops, len(controls)*campaignRounds, activeStops, campaignRounds)

			ceiling := (int(time.Second/time.Millisecond) / campaignIntervalMillis) + 2
			for _, capture := range append(append([]*wire.Capture{}, controls...), treatment) {
				writeCampaignCapture(t, artifacts, capture)
				sizes := capture.Sizes()
				if len(sizes) != 1 || sizes[0] != fabric.CellSize {
					t.Errorf("%s emitted sizes %v, want only %d",
						capture.Label, sizes, fabric.CellSize)
				}
				// A catch-up burst is the specific failure the scheduler
				// exists to avoid. It is bounded by the public cadence rather
				// than by a comparison, so it is checked outright, whatever
				// the noise floor turns out to be.
				if burst := capture.MaxBurst(time.Second); burst > ceiling {
					t.Errorf("%s emitted %d cells in one second, above the cadence ceiling %d",
						capture.Label, burst, ceiling)
				}
			}

			// Decision rule, fixed before the run: a difference between the
			// worlds is a finding only when it exceeds both the tolerance and
			// the spread among worlds that differ by nothing. Where the
			// control spread alone already reaches the tolerance, that
			// statistic is undecidable on this host and is reported as such
			// rather than counted as a pass -- but statistics that do have a
			// usable noise floor are still decided, because a host being
			// noisy about one measure says nothing about another.
			// Only median cadence is gated. Total packet count over a fixed
			// window is dominated by whether a round ended early, so its
			// control spread on a shared host swings between 0.01 and 0.7
			// between runs; gating on it would mean a test that fails at
			// random, which is a test that gets switched off. It is measured
			// and written into the evidence, and the preregistered rule is
			// run against the captures separately.
			if decide(t, "median cadence", signal.cadence, noise.cadence, cadenceTolerance) == 0 {
				t.Skipf("cadence was not decidable on this host (control spread %.4f). "+
					"Captures were still written to %s.", noise.cadence, artifacts)
			}
		})
	}
}

// decide applies the preregistered rule to one statistic and reports whether
// it could be decided at all.
func decide(t *testing.T, name string, signal, noise, tolerance float64) int {
	t.Helper()
	if noise >= tolerance {
		t.Logf("%s: UNDECIDABLE on this host -- control spread %.4f already reaches the "+
			"%.4f tolerance (measured idle-vs-active difference was %.4f)",
			name, noise, tolerance, signal)
		return 0
	}
	if signal > tolerance && signal > noise {
		t.Errorf("%s: idle and active differ by %.4f, above the %.4f tolerance and above "+
			"the %.4f control spread", name, signal, tolerance, noise)
		return 1
	}
	t.Logf("%s: no finding -- difference %.4f within tolerance %.4f (control spread %.4f)",
		name, signal, tolerance, noise)
	return 1
}

type worldGap struct {
	count   float64
	cadence float64
}

func (gap worldGap) widen(other worldGap) worldGap {
	if other.count > gap.count {
		gap.count = other.count
	}
	if other.cadence > gap.cadence {
		gap.cadence = other.cadence
	}
	return gap
}

func (gap worldGap) narrow(other worldGap) worldGap {
	if other.count < gap.count {
		gap.count = other.count
	}
	if other.cadence < gap.cadence {
		gap.cadence = other.cadence
	}
	return gap
}

func worldDistance(left, right *wire.Capture) worldGap {
	interval := float64(campaignIntervalMillis) * float64(time.Millisecond)
	return worldGap{
		count:   relativeDifference(float64(len(left.Packets)), float64(len(right.Packets))),
		cadence: absolute(medianGap(left)-medianGap(right)) / interval,
	}
}

func buildCampaignNode(t *testing.T, network topology.Verified,
	identities map[string]ed25519.PrivateKey, endpoints []string, scratch string) *Node {
	t.Helper()
	self := network.Document.Operators[0]
	cache, err := rawcache.Open(filepath.Join(scratch, "raw"), 64)
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

func fillWorkQueue(t *testing.T, worker *Node, count int) {
	t.Helper()
	var payload [hop.CiphertextSize]byte
	if _, err := rand.Read(payload[:]); err != nil {
		t.Fatal(err)
	}
	var stream hop.StreamID
	stream[15] = 1
	for index := 0; index < count; index++ {
		stream[0] = byte(index)
		stream[1] = byte(index >> 8)
		metadata, err := hop.WorkMetadata(stream, 0, 2)
		if err != nil {
			t.Fatal(err)
		}
		cell, err := hop.FromCiphertext(payload, metadata)
		if err != nil {
			t.Fatal(err)
		}
		worker.queue.Enqueue(cell)
	}
}

func bindObservers(t *testing.T, endpoints []string, indexes []int) []*net.UDPConn {
	t.Helper()
	observers := make([]*net.UDPConn, 0, len(indexes))
	for _, index := range indexes {
		address, err := net.ResolveUDPAddr("udp", endpoints[index])
		if err != nil {
			t.Fatal(err)
		}
		observer, err := net.ListenUDP("udp", address)
		if err != nil {
			t.Fatalf("bind observer on %s: %v", endpoints[index], err)
		}
		observers = append(observers, observer)
	}
	return observers
}

func closeObservers(observers []*net.UDPConn) {
	for _, observer := range observers {
		_ = observer.Close()
	}
}

// observeAll reads from every observer socket until the context ends and
// returns the merged, time-ordered trace, which is what a single passive
// observer of the sender would have seen.
func observeAll(observers []*net.UDPConn, ctx context.Context) []wire.Packet {
	var mutex sync.Mutex
	var packets []wire.Packet
	var group sync.WaitGroup
	for _, observer := range observers {
		group.Add(1)
		go func(observer *net.UDPConn) {
			defer group.Done()
			capture := &wire.Capture{}
			observeInto(observer, ctx, capture)
			mutex.Lock()
			packets = append(packets, capture.Packets...)
			mutex.Unlock()
		}(observer)
	}
	group.Wait()
	sort.Slice(packets, func(i, j int) bool { return packets[i].At.Before(packets[j].At) })
	return packets
}

// runCampaignRound runs one round and reports whether the sender stopped
// before the round's wall clock ran out. Stopping is correct behaviour -- the
// scheduler refuses to emit a catch-up burst -- but it is also externally
// observable, so which world it happened in is recorded rather than averaged
// away.
func runCampaignRound(t *testing.T, network topology.Verified, identities map[string]ed25519.PrivateKey,
	endpoints []string, world campaignWorld, stressor campaignStressor, capture *wire.Capture) bool {
	t.Helper()

	observers := bindObservers(t, endpoints, []int{1})
	defer closeObservers(observers)

	scratch := t.TempDir()
	worker := buildCampaignNode(t, network, identities, endpoints, scratch)

	// A cancellable context, not a deadline context: authenticatedSink copies
	// any context deadline onto the socket write deadline, so a deadline here
	// would fail writes near the end of the round with i/o timeout, an
	// artifact of the harness that production never sees.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(campaignDuration, cancel)
	defer stop.Stop()

	stopped := make(chan bool, 1)
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		err := worker.Run(ctx)
		early := err != nil && ctx.Err() == nil
		if err != nil {
			t.Logf("%s/%s node stopped: %v", stressor.name, world.name, err)
		}
		stopped <- early
	}()
	group.Add(1)
	go func() {
		defer group.Done()
		stressor.run(ctx, scratch)
	}()
	if world.private != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			world.private(ctx, worker, scratch)
		}()
	}

	observeInto(observers[0], ctx, capture)
	cancel()
	group.Wait()
	return <-stopped
}

func observeInto(observer *net.UDPConn, ctx context.Context, capture *wire.Capture) {
	buffer := make([]byte, fabric.CellSize+64)
	local := observer.LocalAddr().String()
	for {
		if err := observer.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
			return
		}
		count, from, err := observer.ReadFromUDP(buffer)
		at := time.Now()
		if err == nil {
			capture.Add(wire.Packet{At: at, Size: count, Source: from.String(), Destination: local})
			continue
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		return
	}
}

// drivePrivateActivity is everything a reader or publisher does that must not
// reach the wire: queuing work for relay, persisting private material, and
// the CPU cost of local selection and reconstruction.
func drivePrivateActivity(ctx context.Context, node *Node, scratch string) {
	var payload [hop.CiphertextSize]byte
	if _, err := rand.Read(payload[:]); err != nil {
		return
	}
	private := filepath.Join(scratch, "private")
	_ = os.MkdirAll(private, 0o700)
	var stream hop.StreamID
	stream[15] = 1
	counter := 0
	for ctx.Err() == nil {
		counter++
		stream[0] = byte(counter)
		stream[1] = byte(counter >> 8)
		metadata, err := hop.WorkMetadata(stream, 0, 2)
		if err != nil {
			return
		}
		cell, err := hop.FromCiphertext(payload, metadata)
		if err != nil {
			return
		}
		// Enqueueing work is the private-dependent input to the emission
		// path. It turns the next cell from cover into work; it must not
		// turn it into a differently timed or differently sized cell.
		node.queue.Enqueue(cell)

		digest := sha256.Sum256(payload[:])
		for round := 0; round < 64; round++ {
			digest = sha256.Sum256(digest[:])
		}
		_ = os.WriteFile(filepath.Join(private, fmt.Sprintf("object-%d", counter%16)), digest[:], 0o600)
		time.Sleep(2 * time.Millisecond)
	}
}

func burnCPU(ctx context.Context, _ string) {
	var group sync.WaitGroup
	for worker := 0; worker < runtime.GOMAXPROCS(0); worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			digest := [32]byte{}
			for ctx.Err() == nil {
				for round := 0; round < 4096; round++ {
					digest = sha256.Sum256(digest[:])
				}
			}
		}()
	}
	group.Wait()
}

func pressureDisk(ctx context.Context, scratch string) {
	block := make([]byte, 1<<20)
	path := filepath.Join(scratch, "pressure")
	for ctx.Err() == nil {
		file, err := os.Create(path)
		if err != nil {
			return
		}
		for round := 0; round < 8 && ctx.Err() == nil; round++ {
			if _, err := file.Write(block); err != nil {
				break
			}
			_ = file.Sync()
		}
		_ = file.Close()
		_ = os.Remove(path)
	}
}

// medianGap is the middle inter-arrival, in nanoseconds. The median rather
// than the mean because ambient stalls on a shared host produce a few very
// large gaps, and a mean lets one of them stand in for a systematic shift.
// Gaps at round boundaries come from restarting the sender rather than from
// either world, and are excluded outright.
func medianGap(capture *wire.Capture) float64 {
	ceiling := float64(campaignIntervalMillis*10) * float64(time.Millisecond)
	gaps := make([]float64, 0, len(capture.Packets))
	for _, gap := range capture.Interarrivals() {
		if float64(gap) <= ceiling {
			gaps = append(gaps, float64(gap))
		}
	}
	if len(gaps) == 0 {
		return 0
	}
	sort.Float64s(gaps)
	middle := len(gaps) / 2
	if len(gaps)%2 == 1 {
		return gaps[middle]
	}
	return (gaps[middle-1] + gaps[middle]) / 2
}

func relativeDifference(left, right float64) float64 {
	larger := left
	if right > larger {
		larger = right
	}
	if larger == 0 {
		return 0
	}
	return absolute(left-right) / larger
}

func absolute(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}

func writeCampaignCapture(t *testing.T, directory string, capture *wire.Capture) {
	t.Helper()
	path := filepath.Join(directory, capture.Label+".txt")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("write capture: %v", err)
	}
	defer func() { _ = file.Close() }()
	if err := capture.WriteTcpdump(file); err != nil {
		t.Fatalf("render capture: %v", err)
	}
}
