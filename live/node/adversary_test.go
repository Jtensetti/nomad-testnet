package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"github.com/Jtensetti/nomad-testnet/live/wire"
)

// A fixed-cadence sender should be structurally immune to both amplification
// and induced catch-up traffic: it emits one cell per public interval no
// matter what arrives. "Should be" is the operative phrase -- the receive
// path does real work per datagram (authentication, replay checking, cache
// writes, queue insertion) on the same process as the scheduler, so a flood
// could in principle starve the emitter or, worse, make it emit differently.
//
// These tests flood the node from a peer it is configured to accept and
// measure what comes out. G-09 asks for amplification measured and bounded;
// G-10 asks that a malicious peer cannot trigger catch-up traffic.

type adversary struct {
	name string
	// send emits one hostile datagram and reports its size.
	send func(t *testing.T, session *hostileSession) int
}

// hostileSession is peer 2 of the campaign topology, which the node under
// test is configured to accept cells from. Holding its real inbound key is
// the strongest case: the flood is authentic, not merely well-formed.
type hostileSession struct {
	conn     *net.UDPConn
	target   *net.UDPAddr
	key      [32]byte
	sender   uint16
	receiver uint16
	context  hop.Context
	sequence uint32
	stream   hop.StreamID
}

func (session *hostileSession) workCell(t *testing.T, fresh bool) fabric.Cell {
	t.Helper()
	if fresh {
		session.stream[0]++
		if session.stream[0] == 0 {
			session.stream[1]++
		}
	}
	metadata, err := hop.WorkMetadata(session.stream, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	var cell fabric.Cell
	if _, err := rand.Read(cell[:hop.CiphertextSize]); err != nil {
		t.Fatal(err)
	}
	session.sequence++
	if err := hop.Seal(&cell, metadata, session.sender, session.sequence, session.key, session.context); err != nil {
		t.Fatal(err)
	}
	return cell
}

func TestFloodFromAnAcceptedPeerNeitherAmplifiesNorInducesCatchUp(t *testing.T) {
	campaignEnabled(t)
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)

	adversaries := []adversary{
		{name: "authentic-work", send: func(t *testing.T, session *hostileSession) int {
			cell := session.workCell(t, true)
			written, _ := session.conn.WriteToUDP(cell[:], session.target)
			return written
		}},
		{name: "replayed-work", send: func(t *testing.T, session *hostileSession) int {
			// The same sealed cell over and over: it passes authentication
			// and dies at the replay window, which is the cheapest rejection
			// an attacker can force repeatedly.
			cell := session.workCell(t, false)
			written, _ := session.conn.WriteToUDP(cell[:], session.target)
			return written
		}},
		{name: "unauthenticated", send: func(t *testing.T, session *hostileSession) int {
			var cell fabric.Cell
			if _, err := rand.Read(cell[:]); err != nil {
				t.Fatal(err)
			}
			written, _ := session.conn.WriteToUDP(cell[:], session.target)
			return written
		}},
		{name: "wrong-size", send: func(t *testing.T, session *hostileSession) int {
			payload := make([]byte, fabric.CellSize/2)
			written, _ := session.conn.WriteToUDP(payload, session.target)
			return written
		}},
	}

	// The control is the same node with no adversary at all. Everything is
	// compared against it rather than against an absolute expectation, so
	// ordinary host noise does not read as an attack succeeding.
	control := &wire.Capture{Label: "flood-control"}
	var controlSpread worldGap
	{
		first := &wire.Capture{Label: "flood-control-a"}
		second := &wire.Capture{Label: "flood-control-b"}
		for round := 0; round < 2; round++ {
			runFloodRound(t, network, identities, endpoints, nil, first)
			runFloodRound(t, network, identities, endpoints, nil, second)
		}
		controlSpread = worldDistance(first, second)
		control.Packets = append(append([]wire.Packet{}, first.Packets...), second.Packets...)
		t.Logf("control spread with no adversary: cadence %.4f", controlSpread.cadence)
	}

	for _, hostile := range adversaries {
		t.Run(hostile.name, func(t *testing.T) {
			flooded := &wire.Capture{Label: "flood-" + hostile.name}
			var inbound int64
			for round := 0; round < 2; round++ {
				inbound += runFloodRound(t, network, identities, endpoints, &hostile, flooded)
			}
			outbound := int64(len(flooded.Packets)) * int64(fabric.CellSize)

			// G-09. A fixed-cadence sender emits on a public schedule, so the
			// more an attacker sends the lower this ratio goes. Anything at
			// or above 1 would mean the flood paid for itself.
			if inbound == 0 {
				t.Fatalf("no hostile traffic was sent; the measurement is vacuous")
			}
			amplification := float64(outbound) / float64(inbound)
			if amplification >= 1.0 {
				t.Errorf("amplification factor %.4f: %d bytes out for %d bytes in",
					amplification, outbound, inbound)
			}
			t.Logf("amplification %.5f (%d bytes out, %d bytes in over %d hostile datagrams)",
				amplification, outbound, inbound, inbound/int64(fabric.CellSize)+1)

			// G-10. The flood must not change the emission cadence, in either
			// direction: neither a catch-up burst nor a slowdown.
			signal := worldDistance(control, flooded)
			if decide(t, "median cadence under "+hostile.name,
				signal.cadence, controlSpread.cadence, cadenceTolerance) == 0 {
				t.Logf("cadence was not decidable on this host under %s", hostile.name)
			}
			// The shift is reported in absolute terms as well, because it is
			// consistently non-zero and above the control spread: a busy
			// receive loop does slow the emitter slightly. That effect is
			// caused by the attacker's own traffic and is identical whatever
			// the victim is doing, so it carries no private information --
			// TestFloodIsNotAPrivateStateOracle checks that claim rather than
			// assuming it -- but burying a real measured effect under "within
			// tolerance" would be the wrong record to leave.
			t.Logf("%s shifted median cadence by %.4f of the interval (%.3f ms), "+
				"attacker-caused and therefore public",
				hostile.name, signal.cadence,
				signal.cadence*float64(campaignIntervalMillis))

			// The burst ceiling is absolute rather than comparative, so it
			// holds whatever the host noise is.
			ceiling := (int(time.Second/time.Millisecond) / campaignIntervalMillis) + 2
			if burst := flooded.MaxBurst(time.Second); burst > ceiling {
				t.Errorf("%s produced %d cells in one second, above the cadence ceiling %d",
					hostile.name, burst, ceiling)
			}
			if sizes := flooded.Sizes(); len(sizes) != 1 || sizes[0] != fabric.CellSize {
				t.Errorf("%s changed the emitted sizes to %v", hostile.name, sizes)
			}
		})
	}
}

// runFloodRound runs one round with an optional adversary and returns the
// number of hostile bytes sent.
func runFloodRound(t *testing.T, network topology.Verified, identities map[string]ed25519.PrivateKey,
	endpoints []string, hostile *adversary, capture *wire.Capture) int64 {
	t.Helper()
	return runFloodRoundInternal(t, network, identities, endpoints, hostile, capture,
		campaignWorld{name: "idle"})
}

func runFloodRoundInternal(t *testing.T, network topology.Verified,
	identities map[string]ed25519.PrivateKey, endpoints []string, hostile *adversary,
	capture *wire.Capture, world campaignWorld) int64 {
	t.Helper()

	observers := bindObservers(t, endpoints, []int{1})
	defer closeObservers(observers)

	scratch := t.TempDir()
	worker := buildCampaignNode(t, network, identities, endpoints, scratch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(campaignDuration, cancel)
	defer stop.Stop()

	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		if err := worker.Run(ctx); err != nil {
			t.Logf("flood/%s node stopped: %v", floodName(hostile), err)
		}
	}()

	var sent atomic.Int64
	if hostile != nil {
		// The hostile source binds peer 2's endpoint, which the node accepts
		// cells from, and sends as fast as it can.
		source, err := net.ListenUDP("udp", resolveCampaignAddress(t, endpoints[2]))
		if err != nil {
			t.Fatalf("bind hostile source: %v", err)
		}
		defer func() { _ = source.Close() }()
		session := &hostileSession{
			conn: source, target: resolveCampaignAddress(t, endpoints[0]),
			key: [32]byte{byte(2 + 11)}, sender: 2, receiver: 0,
			context: hop.Context{
				TopologyDigest: network.Digest,
				NetworkID:      network.Document.NetworkID,
				Epoch:          network.Document.Epoch,
				Receiver:       0,
			},
		}
		session.stream[15] = 1
		group.Add(1)
		go func() {
			defer group.Done()
			for ctx.Err() == nil {
				sent.Add(int64(hostile.send(t, session)))
			}
		}()
	}

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
	return sent.Load()
}

func floodName(hostile *adversary) string {
	if hostile == nil {
		return "control"
	}
	return hostile.name
}

// A hostile peer must not be able to make the node treat a datagram as
// something it is not. This is the unit-level companion to the flood: it
// checks the rejection reasons rather than the rate.
func TestHostileDatagramsAreRejectedForTheRightReason(t *testing.T) {
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	scratch := t.TempDir()
	worker := buildCampaignNode(t, network, identities, endpoints, scratch)
	defer func() { _ = worker.conn.Close() }()

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

	source, err := net.ListenUDP("udp", resolveCampaignAddress(t, endpoints[2]))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	target := resolveCampaignAddress(t, endpoints[0])
	session := &hostileSession{
		conn: source, target: target, key: [32]byte{byte(2 + 11)}, sender: 2, receiver: 0,
		context: hop.Context{
			TopologyDigest: network.Digest, NetworkID: network.Document.NetworkID,
			Epoch: network.Document.Epoch, Receiver: 0,
		},
	}
	session.stream[15] = 1

	cases := []struct {
		name    string
		send    func()
		counter func(Stats) uint64
		// stored is how many of the sent datagrams should legitimately reach
		// the cache. It is not always zero: a replay test has to send a valid
		// cell first, and accepting that one is correct.
		stored uint64
	}{
		{"undersized datagram", func() {
			_, _ = source.WriteToUDP(make([]byte, 16), target)
		}, func(s Stats) uint64 { return s.WrongSize }, 0},
		{"oversized datagram", func() {
			_, _ = source.WriteToUDP(make([]byte, fabric.CellSize+8), target)
		}, func(s Stats) uint64 { return s.WrongSize }, 0},
		{"unauthenticated cell", func() {
			var cell fabric.Cell
			_, _ = rand.Read(cell[:])
			_, _ = source.WriteToUDP(cell[:], target)
		}, func(s Stats) uint64 { return s.AuthRejected }, 0},
		{"cell sealed for another receiver", func() {
			// Same key and sender, but the context names a different
			// receiver, so the tag does not authenticate here.
			elsewhere := *session
			elsewhere.context.Receiver = 1
			cell := elsewhere.workCell(t, true)
			_, _ = source.WriteToUDP(cell[:], target)
		}, func(s Stats) uint64 { return s.AuthRejected }, 0},
		{"cell sealed for another epoch", func() {
			elsewhere := *session
			elsewhere.context.Epoch = session.context.Epoch + 1
			cell := elsewhere.workCell(t, true)
			_, _ = source.WriteToUDP(cell[:], target)
		}, func(s Stats) uint64 { return s.AuthRejected }, 0},
		{"replayed cell", func() {
			cell := session.workCell(t, false)
			_, _ = source.WriteToUDP(cell[:], target)
			_, _ = source.WriteToUDP(cell[:], target)
		}, func(s Stats) uint64 { return s.ReplayRejected }, 1},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			before := testCase.counter(worker.Snapshot())
			storedBefore := worker.Snapshot().Stored
			testCase.send()
			waitForNodeStats(t, worker, func(s Stats) bool {
				return testCase.counter(s) > before
			})
			if after := testCase.counter(worker.Snapshot()); after <= before {
				t.Errorf("%s did not increment its rejection counter (%d -> %d)",
					testCase.name, before, after)
			}
			if stored := worker.Snapshot().Stored - storedBefore; stored != testCase.stored {
				t.Errorf("%s caused %d cells to be stored, want %d",
					testCase.name, stored, testCase.stored)
			}
		})
	}
}

// A flood measurably slows the emitter, by a small amount. That is fine only
// if the slowdown is the same whatever the victim is doing privately. If it
// were larger when the node had work to relay, an attacker could flood a
// node and read private activity off the cadence -- turning a denial-of-
// service lever into a privacy oracle, which is far worse.
func TestFloodIsNotAPrivateStateOracle(t *testing.T) {
	campaignEnabled(t)
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)

	hostile := adversary{name: "authentic-work", send: func(t *testing.T, session *hostileSession) int {
		cell := session.workCell(t, true)
		written, _ := session.conn.WriteToUDP(cell[:], session.target)
		return written
	}}

	// Three series, all flooded: two idle and one with private activity. The
	// two idle series bound this host's noise while under attack, which is
	// the only fair comparison for the third.
	idleA := &wire.Capture{Label: "flood-oracle-idle-a"}
	idleB := &wire.Capture{Label: "flood-oracle-idle-b"}
	active := &wire.Capture{Label: "flood-oracle-active"}
	for round := 0; round < 2; round++ {
		runFloodRoundWithWork(t, network, identities, endpoints, &hostile, idleA, false)
		runFloodRoundWithWork(t, network, identities, endpoints, &hostile, idleB, false)
		runFloodRoundWithWork(t, network, identities, endpoints, &hostile, active, true)
	}

	noise := worldDistance(idleA, idleB)
	signal := worldDistance(idleA, active)
	if other := worldDistance(idleB, active); other.cadence < signal.cadence {
		signal = other
	}
	t.Logf("under flood: control spread %.4f, idle vs active %.4f", noise.cadence, signal.cadence)
	if decide(t, "median cadence under flood, idle vs active",
		signal.cadence, noise.cadence, cadenceTolerance) == 0 {
		t.Skipf("this host cannot decide whether the flood is an oracle "+
			"(control spread %.4f)", noise.cadence)
	}
}

func runFloodRoundWithWork(t *testing.T, network topology.Verified,
	identities map[string]ed25519.PrivateKey, endpoints []string,
	hostile *adversary, capture *wire.Capture, private bool) {
	t.Helper()
	world := campaignWorld{name: "idle"}
	if private {
		world = campaignWorld{name: "active", private: drivePrivateActivity}
	}
	runFloodRoundInternal(t, network, identities, endpoints, hostile, capture, world)
}
