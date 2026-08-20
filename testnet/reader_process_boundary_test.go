package testnet

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/fetchplan"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	readerProcessInterval  = 100 * time.Millisecond
	readerProcessWarmup    = 750 * time.Millisecond
	readerProcessWindow    = 4 * time.Second
	readerProcessTolerance = 0.02
)

type requestRecorder struct {
	mu    sync.Mutex
	times []time.Time
}

func (r *requestRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.times = append(r.times, time.Now())
	r.mu.Unlock()
	http.NotFound(w, req)
}

func (r *requestRecorder) reset() {
	r.mu.Lock()
	r.times = nil
	r.mu.Unlock()
}

func (r *requestRecorder) snapshot() []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.times...)
}

type readerRun struct {
	Label     string        `json:"label"`
	Stress    bool          `json:"stress"`
	Requests  int           `json:"requests"`
	MedianGap time.Duration `json:"median_gap_ns"`
	EarlyExit bool          `json:"early_exit"`
}

type readerBoundaryEvidence struct {
	IntervalMillis    int         `json:"interval_ms"`
	Tolerance         float64     `json:"tolerance"`
	IdleMedianNanos   int64       `json:"idle_median_ns"`
	StressMedianNanos int64       `json:"stress_median_ns"`
	ControlSpread     float64     `json:"idle_control_spread"`
	Signal            float64     `json:"idle_vs_stress_signal"`
	Decision          string      `json:"decision"`
	Runs              []readerRun `json:"runs"`
	ClaimBoundary     string      `json:"claim_boundary"`
}

// TestReaderFetchProcessTimingBoundary exercises the release-shaped reader
// network boundary. The real nomad-partial-fetch executable runs in its own OS
// process. CPU/disk pressure runs in a different OS process. The parent test is
// only the public 404 endpoint/observer and fixture coordinator.
//
// The test deliberately does not model private work as a goroutine in the
// network process. That same-runtime model is retained elsewhere as a positive
// control for the resource-coupling problem tracked by issue #7.
func TestReaderFetchProcessTimingBoundary(t *testing.T) {
	binary := os.Getenv("NOMAD_PARTIAL_FETCH_BIN")
	if binary == "" {
		t.Skip("NOMAD_PARTIAL_FETCH_BIN is required for the separate-process gate")
	}
	if info, err := os.Stat(binary); err != nil || info.IsDir() {
		t.Fatalf("partial-fetch executable is unavailable: %v", err)
	}

	recorders := []*requestRecorder{{}, {}, {}}
	servers := make([]*http.Server, 0, len(recorders))
	partialEndpoints := make([]string, len(recorders))
	for index, recorder := range recorders {
		address := fmt.Sprintf("127.0.0.1:%d", 49301+index)
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatalf("listen on %s: %v", address, err)
		}
		server := &http.Server{Handler: recorder, ReadHeaderTimeout: time.Second}
		servers = append(servers, server)
		partialEndpoints[index] = "http://" + address
		go func() { _ = server.Serve(listener) }()
	}
	defer func() {
		for _, server := range servers {
			_ = server.Close()
		}
	}()

	fixture := t.TempDir()
	topologyPath, authorityPath, planPath := writeReaderProcessFixture(t, fixture, partialEndpoints)

	// ABBA BAAB makes each world occupy early and late positions equally. This
	// prevents slow host drift from being silently relabelled as private-state
	// modulation, the exact harness defect found while reopening issue #6.
	order := []bool{false, true, true, false, true, false, false, true}
	runs := make([]readerRun, 0, len(order))
	idleMedians := make([]time.Duration, 0, 4)
	stressMedians := make([]time.Duration, 0, 4)
	for index, stress := range order {
		label := fmt.Sprintf("run-%02d-idle", index+1)
		if stress {
			label = fmt.Sprintf("run-%02d-stress", index+1)
		}
		run := runReaderWorld(t, binary, topologyPath, authorityPath, planPath, recorders[0], stress, label)
		runs = append(runs, run)
		if run.EarlyExit {
			writeReaderEvidence(t, readerBoundaryEvidence{
				IntervalMillis: int(readerProcessInterval / time.Millisecond), Tolerance: readerProcessTolerance,
				Decision: "FAIL", Runs: runs,
				ClaimBoundary: "A network-process early exit under separate private-process load is an availability/timing finding; this test is not an anonymity proof.",
			})
			t.Fatalf("%s: partial-fetch process exited before the public observation window ended", label)
		}
		if run.Requests < 30 {
			t.Fatalf("%s: only %d public fetches observed; need at least 30", label, run.Requests)
		}
		if stress {
			stressMedians = append(stressMedians, run.MedianGap)
		} else {
			idleMedians = append(idleMedians, run.MedianGap)
		}
	}

	idleMedian := medianDuration(idleMedians)
	stressMedian := medianDuration(stressMedians)
	signal := durationDistance(idleMedian, stressMedian, readerProcessInterval)
	control := maximumPairwiseDistance(idleMedians, readerProcessInterval)
	decision := "PASS"
	if control >= readerProcessTolerance {
		decision = "UNDECIDABLE"
	} else if signal > readerProcessTolerance && signal > control {
		decision = "FAIL"
	}
	evidence := readerBoundaryEvidence{
		IntervalMillis: int(readerProcessInterval / time.Millisecond), Tolerance: readerProcessTolerance,
		IdleMedianNanos: idleMedian.Nanoseconds(), StressMedianNanos: stressMedian.Nanoseconds(),
		ControlSpread: control, Signal: signal, Decision: decision, Runs: runs,
		ClaimBoundary: "This bounds cadence modulation for the real partial-fetch process versus a separate CPU/disk process on this macOS runner. It does not prove browser UI isolation, WAN anonymity, publication anonymity, or independent-operator security.",
	}
	writeReaderEvidence(t, evidence)

	switch decision {
	case "UNDECIDABLE":
		t.Skipf("reader process timing is undecidable on this host: idle control spread %.4f reaches %.4f; signal %.4f", control, readerProcessTolerance, signal)
	case "FAIL":
		t.Fatalf("separate private-process load changed reader fetch cadence by %.4f, above %.4f tolerance and %.4f idle control spread", signal, readerProcessTolerance, control)
	default:
		t.Logf("reader separate-process timing PASS: signal=%.4f control=%.4f tolerance=%.4f", signal, control, readerProcessTolerance)
	}
}

// TestReaderPrivateStressor is never a normal test. The parent gate launches
// this same signed test binary as a second OS process. It approximates local
// browser selection/render/cache pressure without giving that process any
// handle to the partial-fetch child or its public schedule.
func TestReaderPrivateStressor(t *testing.T) {
	if os.Getenv("NOMAD_READER_STRESS_HELPER") != "1" {
		t.Skip("helper process only")
	}
	directory := os.Getenv("NOMAD_READER_STRESS_DIR")
	if directory == "" {
		os.Exit(2)
	}
	workers := runtime.NumCPU() / 4
	if workers < 1 {
		workers = 1
	}
	if workers > 2 {
		workers = 2
	}
	for worker := 0; worker < workers; worker++ {
		go func(seed byte) {
			digest := sha256.Sum256([]byte{seed})
			for {
				for round := 0; round < 4096; round++ {
					digest = sha256.Sum256(digest[:])
				}
			}
		}(byte(worker + 1))
	}
	block := make([]byte, 256<<10)
	for index := range block {
		block[index] = byte(index)
	}
	for counter := 0; ; counter++ {
		path := filepath.Join(directory, fmt.Sprintf("private-%02d", counter%4))
		file, err := os.Create(path)
		if err != nil {
			os.Exit(3)
		}
		_, _ = file.Write(block)
		_ = file.Sync()
		_ = file.Close()
		time.Sleep(8 * time.Millisecond)
	}
}

func runReaderWorld(t *testing.T, binary, topologyPath, authorityPath, planPath string, recorder *requestRecorder, stress bool, label string) readerRun {
	t.Helper()
	output := filepath.Join(t.TempDir(), "partials")
	fetch := exec.Command(binary,
		"--topology="+topologyPath,
		"--authority-key="+authorityPath,
		"--plan="+planPath,
		"--out="+output,
		"--interval="+readerProcessInterval.String(),
	)
	var fetchLog syncBuffer
	fetch.Stdout = &fetchLog
	fetch.Stderr = &fetchLog
	if err := fetch.Start(); err != nil {
		t.Fatalf("%s: start partial-fetch: %v", label, err)
	}
	fetchDone := make(chan error, 1)
	go func() { fetchDone <- fetch.Wait() }()

	var stressProcess *exec.Cmd
	if stress {
		stressDirectory := t.TempDir()
		stressProcess = exec.Command(os.Args[0], "-test.run=^TestReaderPrivateStressor$")
		stressProcess.Env = append(os.Environ(),
			"NOMAD_READER_STRESS_HELPER=1",
			"NOMAD_READER_STRESS_DIR="+stressDirectory,
		)
		if err := stressProcess.Start(); err != nil {
			_ = fetch.Process.Kill()
			<-fetchDone
			t.Fatalf("%s: start separate stress process: %v", label, err)
		}
	}
	cleanupStress := func() {
		if stressProcess != nil && stressProcess.Process != nil {
			_ = stressProcess.Process.Kill()
			_, _ = stressProcess.Process.Wait()
		}
	}
	defer cleanupStress()

	select {
	case err := <-fetchDone:
		cleanupStress()
		t.Fatalf("%s: partial-fetch exited during warmup: %v\n%s", label, err, fetchLog.String())
	case <-time.After(readerProcessWarmup):
	}
	recorder.reset()
	deadline := time.NewTimer(readerProcessWindow)
	defer deadline.Stop()
	earlyExit := false
	select {
	case err := <-fetchDone:
		earlyExit = true
		t.Logf("%s: partial-fetch exited during observation: %v\n%s", label, err, fetchLog.String())
	case <-deadline.C:
	}
	if !earlyExit {
		_ = fetch.Process.Signal(os.Interrupt)
		select {
		case err := <-fetchDone:
			if err != nil {
				t.Fatalf("%s: partial-fetch did not stop cleanly: %v\n%s", label, err, fetchLog.String())
			}
		case <-time.After(2 * time.Second):
			_ = fetch.Process.Kill()
			<-fetchDone
			t.Fatalf("%s: partial-fetch ignored SIGINT", label)
		}
	}
	cleanupStress()

	timestamps := recorder.snapshot()
	gaps := make([]time.Duration, 0, len(timestamps)-1)
	for index := 1; index < len(timestamps); index++ {
		gap := timestamps[index].Sub(timestamps[index-1])
		if gap > 0 && gap < 5*readerProcessInterval {
			gaps = append(gaps, gap)
		}
	}
	return readerRun{Label: label, Stress: stress, Requests: len(timestamps), MedianGap: medianDuration(gaps), EarlyExit: earlyExit}
}

type syncBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.b = append(b.b, p...)
	return len(p), nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(append([]byte(nil), b.b...))
}

func writeReaderProcessFixture(t *testing.T, root string, partialEndpoints []string) (string, string, string) {
	t.Helper()
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities := make(map[string]ed25519.PrivateKey, 3)
	now := time.Now().UTC().Truncate(time.Second)
	var dkgSession [32]byte
	if _, err := rand.Read(dkgSession[:]); err != nil {
		t.Fatal(err)
	}
	document := topology.Document{
		Version: topology.Version, NetworkID: "reader-process-test", Epoch: 1,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339),
		NotAfter:  now.Add(time.Hour).Format(time.RFC3339),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: 50,
			MaxLatenessMillis: 200, QueueCapacity: 64,
		},
		DKG: topology.DKGProfile{
			Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(dkgSession[:]),
			StartAt: now.Format(time.RFC3339), PhaseDurationMillis: 1_000,
		},
		Operators: make([]topology.Operator, 3),
	}
	for index := range document.Operators {
		id := fmt.Sprintf("operator-%c", 'a'+index)
		identityPublic, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		kex, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		dkgPublic, _, err := mix.GenerateDKGIdentity()
		if err != nil {
			t.Fatal(err)
		}
		identities[id] = identityPrivate
		document.Operators[index] = topology.Operator{
			ID: id, Index: uint16(index),
			Endpoint:        fmt.Sprintf("127.0.0.1:%d", 49501+index),
			PartialEndpoint: partialEndpoints[index],
			DKGEndpoint:     fmt.Sprintf("http://127.0.0.1:%d", 49401+index),
			IdentityKey:     base64.StdEncoding.EncodeToString(identityPublic),
			KEXKey:          base64.StdEncoding.EncodeToString(kex.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        []uint16{uint16((index + 1) % 3)},
		}
	}
	signedTopology, err := topology.Sign(document, authorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	topologyBytes, err := topology.Encode(signedTopology)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := topology.Verify(topologyBytes, authorityPublic, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var stream hop.StreamID
	stream[len(stream)-1] = 1
	plan, err := fetchplan.Sign(fetchplan.Plan{
		Version: fetchplan.Version, NetworkID: verified.Document.NetworkID,
		TopologyEpoch: verified.Document.Epoch,
		TopologyDigest: fmt.Sprintf("%x", verified.Digest),
		StreamID:       hex.EncodeToString(stream[:]),
	}, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	planBytes, err := fetchplan.Encode(plan)
	if err != nil {
		t.Fatal(err)
	}
	topologyPath := filepath.Join(root, "topology.json")
	authorityPath := filepath.Join(root, "authority.pub")
	planPath := filepath.Join(root, "fetch-plan.json")
	if err := os.WriteFile(topologyPath, topologyBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorityPath, []byte(base64.StdEncoding.EncodeToString(authorityPublic)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, planBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return topologyPath, authorityPath, planPath
}

func medianDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	copyValues := append([]time.Duration(nil), values...)
	sort.Slice(copyValues, func(i, j int) bool { return copyValues[i] < copyValues[j] })
	middle := len(copyValues) / 2
	if len(copyValues)%2 == 1 {
		return copyValues[middle]
	}
	return (copyValues[middle-1] + copyValues[middle]) / 2
}

func durationDistance(left, right, interval time.Duration) float64 {
	difference := left - right
	if difference < 0 {
		difference = -difference
	}
	return float64(difference) / float64(interval)
}

func maximumPairwiseDistance(values []time.Duration, interval time.Duration) float64 {
	maximum := 0.0
	for left := 0; left < len(values); left++ {
		for right := left + 1; right < len(values); right++ {
			gap := durationDistance(values[left], values[right], interval)
			if gap > maximum {
				maximum = gap
			}
		}
	}
	return maximum
}

func writeReaderEvidence(t *testing.T, evidence readerBoundaryEvidence) {
	t.Helper()
	root := filepath.Join("..", "runtime", "evidence", "reader-process-boundary")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(root, "reader-process-timing.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
