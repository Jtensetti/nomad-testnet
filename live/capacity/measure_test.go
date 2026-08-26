package capacity_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/capacity"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// The deployed configuration, from deploy/compose.yaml and cmd/nomad-node's
// defaults. These are duplicated here deliberately: a capacity report derived
// from whatever the test happened to construct would drift from the deployment
// without anybody noticing, and the consistency test below is what catches it.
const (
	deployedIntervalMillis = 50
	deployedOperators      = 3
	deployedCacheStreams   = 64
	// An epoch is a deployment parameter with no committed default yet. A day
	// is used as the unit the arithmetic is quoted in, and the report says so.
	quotedEpochSeconds = 86_400
)

func deployedEnvelope() capacity.Envelope {
	return capacity.Envelope{
		CellIntervalMillis: deployedIntervalMillis,
		Links:              deployedOperators - 1,
		EpochSeconds:       quotedEpochSeconds,
		CacheStreams:       deployedCacheStreams,
	}
}

// measure times an operation over enough repetitions to be a mean rather than a
// sample, and reports the mean. It deliberately does not report a minimum: the
// question is whether a node keeps its cadence on a machine that is doing other
// things, and a best-case figure answers a question nobody asked.
func measure(tb testing.TB, name string, onPath bool, budget time.Duration,
	operation func() error) capacity.Cost {
	tb.Helper()
	// Warm up, so the first allocation and the first branch prediction are not
	// part of the number.
	for warm := 0; warm < 8; warm++ {
		if err := operation(); err != nil {
			tb.Fatalf("%s: %v", name, err)
		}
	}
	samples := 0
	start := time.Now()
	for time.Since(start) < budget {
		if err := operation(); err != nil {
			tb.Fatalf("%s: %v", name, err)
		}
		samples++
	}
	elapsed := time.Since(start)
	if samples == 0 {
		tb.Fatalf("%s completed no operations in %s", name, budget)
	}
	return capacity.Cost{
		Name: name, Each: elapsed / time.Duration(samples),
		Samples: samples, OnThePath: onPath,
	}
}

func hopContext() hop.Context {
	var digest [32]byte
	copy(digest[:], []byte("capacity-report-topology-digest1"))
	return hop.Context{NetworkID: "capacity", Epoch: 1, Receiver: 1, TopologyDigest: digest}
}

func publisherSession(tb testing.TB) *uplink.Session {
	tb.Helper()
	committee, _, err := mix.GenerateDealerCommittee(mix.CommitteeID{7}, 1, 3, 2)
	if err != nil {
		tb.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		tb.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], []byte("capacity-report-topology-digest1"))
	session, err := uplink.NewSession(secret, committee.PublicKey, uplink.Context{
		NetworkID: "capacity", Epoch: 1, TopologyDigest: digest, EntryOperator: 0,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return session
}

// TestCapacityReport measures every per-cell and per-session cost on the
// operator's path, derives the three figures PROD-28 names, and writes the
// report deploy/SLO.md cites.
//
// It is a test rather than a benchmark because the numbers have to be published
// with their environment and their limits attached, and `go test -bench` prints
// a number with neither.
func TestCapacityReport(t *testing.T) {
	envelope := deployedEnvelope()
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	const budget = 250 * time.Millisecond

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	context := hopContext()
	stream := hop.StreamID{1, 2, 3}
	metadata, err := hop.WorkMetadata(stream, 0, 4)
	if err != nil {
		t.Fatal(err)
	}

	var costs []capacity.Cost

	// What an operator pays to put one cell on a link.
	var sealCell fabric.Cell
	sequence := uint32(0)
	costs = append(costs, measure(t, "hop seal (operator, per emitted cell)", true, budget,
		func() error {
			sequence++
			if err := hop.SetMetadata(&sealCell, metadata); err != nil {
				return err
			}
			return hop.Seal(&sealCell, metadata, 0, sequence, key, context)
		}))

	// What it pays to take one cell off a link. This is the cost an attacker
	// controls the rate of, so it is the one that decides whether a flood can
	// push a node past its deadline.
	var openTemplate fabric.Cell
	if err := hop.SetMetadata(&openTemplate, metadata); err != nil {
		t.Fatal(err)
	}
	if err := hop.Seal(&openTemplate, metadata, 0, 1, key, context); err != nil {
		t.Fatal(err)
	}
	costs = append(costs, measure(t, "hop open (operator, per received cell)", true, budget,
		func() error {
			cell := openTemplate
			_, err := hop.Open(&cell, 0, key, context)
			return err
		}))

	// The relay path: one open and one seal, which is what an operator does
	// per cell it forwards.
	costs = append(costs, measure(t, "hop relay (open then seal)", true, budget,
		func() error {
			cell := openTemplate
			opened, err := hop.Open(&cell, 0, key, context)
			if err != nil {
				return err
			}
			sequence++
			if err := hop.SetMetadata(&cell, opened); err != nil {
				return err
			}
			return hop.Seal(&cell, opened, 0, sequence, key, context)
		}))

	// Writing a received cell to the immutable raw cache.
	store, err := rawcache.Open(t.TempDir(), deployedCacheStreams)
	if err != nil {
		t.Fatal(err)
	}
	var payload [hop.CiphertextSize]byte
	if _, err := rand.Read(payload[:]); err != nil {
		t.Fatal(err)
	}
	ordinal := uint16(0)
	cacheMetadata := metadata
	cacheMetadata.BatchSize = hop.MaximumBatch
	costs = append(costs, measure(t, "raw cache put (operator, per received cell)", true, budget,
		func() error {
			// A fresh stream every batch, so the measurement is not dominated
			// by one directory growing without bound.
			if ordinal >= cacheMetadata.BatchSize {
				ordinal = 0
				cacheMetadata.Stream[0]++
			}
			local := cacheMetadata
			local.Ordinal = ordinal
			ordinal++
			_, err := store.Put(local, payload)
			return err
		}))

	// What a publisher pays per emitted cell. This is the expensive one, and
	// it is on the publisher rather than the operator.
	session := publisherSession(t)
	publisherSequence := uint64(0)
	costs = append(costs, measure(t, "uplink seal (publisher, per emitted cell)", true,
		2*time.Second, func() error {
			publisherSequence++
			_, err := session.SealCover(publisherSequence)
			return err
		}))

	// Session establishment. The responder is a library capability that no
	// deployed command runs yet, so its cost is reported as off the path.
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	committee, _, err := mix.GenerateDealerCommittee(mix.CommitteeID{7}, 1, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], []byte("capacity-report-topology-digest1"))
	uplinkContext := uplink.Context{
		NetworkID: "capacity", Epoch: 1, TopologyDigest: digest, EntryOperator: 0,
	}
	handshakeSequence := uint64(0)
	costs = append(costs, measure(t, "uplink handshake (publisher side)", false, budget,
		func() error {
			handshakeSequence++
			_, err := uplink.Establish(static.PublicKey().Bytes(), committee.PublicKey,
				uplinkContext, handshakeSequence)
			return err
		}))

	report := capacity.Report{
		Environment: fmt.Sprintf(
			"%s/%s, %d logical CPUs, shared development container running other work concurrently; "+
				"Go %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version()),
		Envelope: envelope,
		Costs:    costs,
		Derived:  map[string]float64{},
		NotEstablished: []string{
			"nothing here runs for longer than a few seconds, so none of it speaks to drift, " +
				"leaks or degradation over a soak",
			"every figure comes from a shared container doing other work, so the costs are " +
				"upper bounds on a quiet machine and say nothing about a small operator's hardware",
			"the per-cell costs are measured in isolation, not with the scheduler, the socket " +
				"and the cache contending for the same core",
			"objects per epoch is a ceiling that assumes every cell carries work; cover traffic " +
				"is the mechanism rather than waste, so no deployment reaches it",
			"the coding rate is not applied: RLNC emits more coded fragments than an object has " +
				"source fragments, so the real object figure is lower",
			"concurrent publishers is a configuration bound, not a measured one: no deployed " +
				"command constructs an uplink responder, so there is no deployed limit to measure",
		},
	}

	objects, err := envelope.ObjectsPerEpoch(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	report.Derived["cells_per_second_per_link"] = envelope.CellsPerSecondPerLink()
	report.Derived["cells_per_second_per_operator"] = envelope.CellsPerSecondPerOperator()
	report.Derived["cells_per_epoch_per_operator"] = float64(envelope.CellsPerEpochPerOperator())
	report.Derived["payload_bytes_per_epoch"] = float64(envelope.PayloadBytesPerEpoch())
	report.Derived["objects_per_epoch_at_1MiB"] = float64(objects)
	for _, cost := range costs {
		report.Derived[cost.Name+" /s"] = cost.PerSecond()
		report.Derived[cost.Name+" headroom vs interval"] = cost.Headroom(envelope.Interval())
	}

	if err := report.Validate(); err != nil {
		t.Fatalf("the report this test produced would be quoted as more than it is: %v", err)
	}

	// The artifact is only rewritten on request. These numbers move by tens of
	// percent between runs on a shared container -- which is the point the
	// report makes about itself -- so writing on every run would leave the
	// committed artifact and the table in SLO.md disagreeing after any test
	// invocation, and a dirty tree that everyone learns to ignore.
	if os.Getenv("NOMAD_WRITE_CAPACITY") == "1" {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, '\n')
		destination := filepath.Join("..", "..", "deploy", "capacity-report.json")
		if err := os.WriteFile(destination, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("rewrote deploy/capacity-report.json; regenerate the SLO.md table to match")
	}
	for _, cost := range costs {
		t.Logf("%-44s %10s each, %8.0f/s, headroom %8.1f x  (on path: %v)",
			cost.Name, cost.Each.Round(time.Nanosecond), cost.PerSecond(),
			cost.Headroom(envelope.Interval()), cost.OnThePath)
	}
	t.Logf("envelope: %.0f cells/s/operator, %d cells/epoch, %d objects/epoch at 1 MiB",
		envelope.CellsPerSecondPerOperator(), envelope.CellsPerEpochPerOperator(), objects)
}

// The relay path has to fit inside the cadence with room to spare, or the node
// starts missing deadlines under nothing worse than its own traffic.
//
// The margin asserted is deliberately wide. A tight one would fail on a busy
// shared runner and teach everyone to ignore it; a wide one still catches the
// change this is really guarding against, which is somebody putting a
// signature, a disk write or a network round trip on the per-cell path.
func TestTheRelayPathFitsInsideTheCadence(t *testing.T) {
	envelope := deployedEnvelope()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	context := hopContext()
	metadata, err := hop.WorkMetadata(hop.StreamID{4}, 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	var template fabric.Cell
	if err := hop.SetMetadata(&template, metadata); err != nil {
		t.Fatal(err)
	}
	if err := hop.Seal(&template, metadata, 0, 1, key, context); err != nil {
		t.Fatal(err)
	}

	sequence := uint32(0)
	cost := measure(t, "relay", true, 250*time.Millisecond, func() error {
		cell := template
		opened, err := hop.Open(&cell, 0, key, context)
		if err != nil {
			return err
		}
		sequence++
		if err := hop.SetMetadata(&cell, opened); err != nil {
			return err
		}
		return hop.Seal(&cell, opened, 0, sequence, key, context)
	})

	// Every link, not one: an operator relays for all of them inside the same
	// interval.
	perInterval := cost.Each * time.Duration(envelope.Links)
	const requiredMargin = 20
	if margin := float64(envelope.Interval()) / float64(perInterval); margin < requiredMargin {
		t.Errorf("relaying %d links costs %s of a %s interval, a margin of %.1fx; below %dx "+
			"a node is one busy neighbour away from missing its cadence, and a node whose "+
			"emissions drift with load is a node whose timing carries load",
			envelope.Links, perInterval, envelope.Interval(), margin, requiredMargin)
	}
	t.Logf("relay costs %s per cell, %s for %d links, %.0fx inside a %s interval",
		cost.Each, perInterval, envelope.Links,
		float64(envelope.Interval())/float64(perInterval), envelope.Interval())
}

// The report describes a deployment, so it must not be able to drift from one.
//
// The constants above are duplicated from deploy/compose.yaml and
// cmd/nomad-node's defaults, which is how a published capacity figure quietly
// stops describing anything: somebody halves the cadence, the report keeps
// saying 50 ms, and every derived number in SLO.md is wrong with nothing red.
func TestTheReportedDeploymentIsTheDeployedOne(t *testing.T) {
	compose, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(compose)

	wantInterval := fmt.Sprintf("--cell-interval-ms=%d", deployedIntervalMillis)
	if !strings.Contains(text, wantInterval) {
		t.Errorf("the capacity report assumes %q and deploy/compose.yaml does not set it; "+
			"every derived figure in SLO.md is describing a deployment that no longer exists",
			wantInterval)
	}

	operators := 0
	for _, name := range []string{"operator-a:", "operator-b:", "operator-c:", "operator-d:",
		"operator-e:"} {
		if strings.Contains(text, "\n  "+name) {
			operators++
		}
	}
	if operators != deployedOperators {
		t.Errorf("the capacity report assumes %d operators; deploy/compose.yaml defines %d",
			deployedOperators, operators)
	}

	// The cache-stream bound is a command default rather than a compose flag,
	// so it is checked where it lives.
	node, err := os.ReadFile(filepath.Join("..", "..", "cmd", "nomad-node", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	wantStreams := fmt.Sprintf(`"cache-streams", %d,`, deployedCacheStreams)
	if !strings.Contains(string(node), wantStreams) {
		t.Errorf("the capacity report assumes a default of %d cache streams and "+
			"cmd/nomad-node no longer defaults to it", deployedCacheStreams)
	}
}

// The arithmetic, checked against hand-computed values rather than against
// itself. A derivation that only agrees with its own re-derivation is a
// tautology, and these are the numbers a deployment plans with.
func TestTheEnvelopeArithmeticIsRight(t *testing.T) {
	envelope := capacity.Envelope{
		CellIntervalMillis: 50, Links: 2, EpochSeconds: 86_400, CacheStreams: 64,
	}
	if got := envelope.CellsPerSecondPerLink(); got != 20 {
		t.Errorf("cells per second per link is %v, want 20", got)
	}
	if got := envelope.CellsPerSecondPerOperator(); got != 40 {
		t.Errorf("cells per second per operator is %v, want 40", got)
	}
	if got := envelope.CellsPerEpochPerOperator(); got != 3_456_000 {
		t.Errorf("cells per epoch is %d, want 3456000", got)
	}
	if got := envelope.PayloadBytesPerEpoch(); got != 3_456_000*504 {
		t.Errorf("payload bytes per epoch is %d", got)
	}
	// 1 MiB needs ceil(1048576/504) = 2081 cells; 3456000/2081 = 1660.
	objects, err := envelope.ObjectsPerEpoch(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if objects != 1660 {
		t.Errorf("objects per epoch at 1 MiB is %d, want 1660", objects)
	}
	// An object smaller than one cell still costs a whole cell, because a cell
	// is the unit on the wire and a partial one would be a different size.
	small, err := envelope.ObjectsPerEpoch(1)
	if err != nil {
		t.Fatal(err)
	}
	if small != 3_456_000 {
		t.Errorf("a one-byte object gives %d per epoch, want one per cell", small)
	}
	if _, err := envelope.ObjectsPerEpoch(0); err == nil {
		t.Error("an object of zero bytes was costed")
	}

	// A shorter cadence multiplies everything, which is the point of quoting
	// the envelope rather than a single number.
	faster := envelope
	faster.CellIntervalMillis = 5
	if got := faster.CellsPerSecondPerOperator(); got != 400 {
		t.Errorf("at the shortest permitted cadence the operator carries %v cells/s, want 400", got)
	}
}

// A report is published, so it has to refuse to be publishable while it is
// missing the things that make a number interpretable.
func TestAReportWithoutItsLimitsIsRefused(t *testing.T) {
	sound := capacity.Report{
		Environment: "a container",
		Envelope:    deployedEnvelope(),
		Costs: []capacity.Cost{
			{Name: "something", Each: time.Microsecond, Samples: 10, OnThePath: true},
		},
		NotEstablished: []string{"almost everything"},
	}
	if err := sound.Validate(); err != nil {
		t.Fatalf("a complete report was refused: %v", err)
	}

	for name, broken := range map[string]func(*capacity.Report){
		"no environment": func(r *capacity.Report) { r.Environment = "" },
		"no costs":       func(r *capacity.Report) { r.Costs = nil },
		"no limits":      func(r *capacity.Report) { r.NotEstablished = nil },
		"an unmeasured cost": func(r *capacity.Report) {
			r.Costs = []capacity.Cost{{Name: "invented", Samples: 1}}
		},
		"a cost with no samples": func(r *capacity.Report) {
			r.Costs = []capacity.Cost{{Name: "invented", Each: time.Second}}
		},
		"an impossible envelope": func(r *capacity.Report) {
			r.Envelope.CellIntervalMillis = 1
		},
		"an operator with no links": func(r *capacity.Report) { r.Envelope.Links = 0 },
		"an epoch of no seconds":    func(r *capacity.Report) { r.Envelope.EpochSeconds = 0 },
		"a cache holding nothing":   func(r *capacity.Report) { r.Envelope.CacheStreams = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := sound
			candidate.Costs = append([]capacity.Cost(nil), sound.Costs...)
			candidate.NotEstablished = append([]string(nil), sound.NotEstablished...)
			broken(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("a report with %s was publishable", name)
			}
		})
	}
}

// Headroom below one is the condition that matters, so it has to be reported
// as such rather than as a small positive number nobody reads.
func TestHeadroomAndRateAreZeroForAnUnmeasuredCost(t *testing.T) {
	var unmeasured capacity.Cost
	if unmeasured.PerSecond() != 0 || unmeasured.Headroom(time.Second) != 0 {
		t.Fatal("an unmeasured cost reports a rate")
	}
	tight := capacity.Cost{Name: "tight", Each: 60 * time.Millisecond, Samples: 1}
	if got := tight.Headroom(50 * time.Millisecond); got >= 1 {
		t.Fatalf("an operation slower than its interval reports headroom %v", got)
	}
}
