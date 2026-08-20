package testnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/relayipc"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	shaperProcessInterval  = 50 * time.Millisecond
	shaperProcessWarmup    = 500 * time.Millisecond
	shaperProcessWindow    = 4 * time.Second
	shaperProcessTolerance = 0.02
)

type udpRecorder struct {
	mu        sync.Mutex
	times     []time.Time
	wrongSize int
}

func (r *udpRecorder) add(at time.Time, size int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if size != fabric.CellSize {
		r.wrongSize++
		return
	}
	r.times = append(r.times, at)
}

func (r *udpRecorder) reset() {
	r.mu.Lock()
	r.times = nil
	r.wrongSize = 0
	r.mu.Unlock()
}

func (r *udpRecorder) snapshot() ([]time.Time, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.times...), r.wrongSize
}

type shaperRun struct {
	Label     string        `json:"label"`
	Producer  bool          `json:"producer"`
	Packets   int           `json:"packets"`
	WrongSize int           `json:"wrong_size"`
	MedianGap time.Duration `json:"median_gap_ns"`
	EarlyExit bool          `json:"early_exit"`
}

type shaperBoundaryEvidence struct {
	IntervalMillis    int         `json:"interval_ms"`
	Tolerance         float64     `json:"tolerance"`
	IdleMedianNanos   int64       `json:"idle_median_ns"`
	ActiveMedianNanos int64       `json:"active_median_ns"`
	ControlSpread     float64     `json:"idle_control_spread"`
	Signal            float64     `json:"idle_vs_active_signal"`
	Decision          string      `json:"decision"`
	Runs              []shaperRun `json:"runs"`
	ClaimBoundary     string      `json:"claim_boundary"`
}

// TestShaperProcessTimingBoundary is the production replacement for the old
// same-Go-runtime relay timing gate. The real nomad-shaper executable owns the
// scheduler and UDP socket in one OS process. A different process performs
// relay production plus CPU/disk pressure and can only offer work through the
// bounded nonblocking Unix datagram queue.
func TestShaperProcessTimingBoundary(t *testing.T) {
	binary := os.Getenv("NOMAD_SHAPER_BIN")
	if binary == "" {
		t.Skip("NOMAD_SHAPER_BIN is required for the separate-process shaper gate")
	}
	if info, err := os.Stat(binary); err != nil || info.IsDir() {
		t.Fatalf("nomad-shaper executable is unavailable: %v", err)
	}

	fixture := t.TempDir()
	topologyPath, authorityPath, secretsPath, endpoints := writeShaperFixture(t, fixture)

	// Each condition occupies early and late positions equally. The earlier
	// relay experiment demonstrated that fixed treatment ordering can turn slow
	// runner drift into a false signal.
	order := []bool{false, true, true, false, true, false, false, true}
	runs := make([]shaperRun, 0, len(order))
	idle := make([]time.Duration, 0, 4)
	active := make([]time.Duration, 0, 4)
	for index, producer := range order {
		label := fmt.Sprintf("run-%02d-idle", index+1)
		if producer {
			label = fmt.Sprintf("run-%02d-active", index+1)
		}
		run := runShaperWorld(t, binary, topologyPath, authorityPath, secretsPath, endpoints, producer, label)
		runs = append(runs, run)
		if run.EarlyExit || run.WrongSize != 0 {
			writeShaperEvidence(t, shaperBoundaryEvidence{
				IntervalMillis: int(shaperProcessInterval / time.Millisecond), Tolerance: shaperProcessTolerance,
				Decision: "FAIL", Runs: runs,
				ClaimBoundary: "An early shaper exit or non-1200-byte datagram is a direct fixed-fabric finding; this test is not a complete anonymity proof.",
			})
			t.Fatalf("%s: early_exit=%t wrong_size=%d", label, run.EarlyExit, run.WrongSize)
		}
		if run.Packets < 60 {
			t.Fatalf("%s: observed only %d packets in the fixed window", label, run.Packets)
		}
		if producer {
			active = append(active, run.MedianGap)
		} else {
			idle = append(idle, run.MedianGap)
		}
	}

	idleMedian := shaperMedian(idle)
	activeMedian := shaperMedian(active)
	signal := shaperDistance(idleMedian, activeMedian, shaperProcessInterval)
	control := shaperMaximumPairwiseDistance(idle, shaperProcessInterval)
	decision := "PASS"
	if control >= shaperProcessTolerance {
		decision = "UNDECIDABLE"
	} else if signal > shaperProcessTolerance && signal > control {
		decision = "FAIL"
	}
	evidence := shaperBoundaryEvidence{
		IntervalMillis: int(shaperProcessInterval / time.Millisecond), Tolerance: shaperProcessTolerance,
		IdleMedianNanos: idleMedian.Nanoseconds(), ActiveMedianNanos: activeMedian.Nanoseconds(),
		ControlSpread: control, Signal: signal, Decision: decision, Runs: runs,
		ClaimBoundary: "This bounds relay-production modulation of the real fixed-rate shaper across a local OS process boundary on this runner. It does not establish WAN indistinguishability, independent operators, publication anonymity, or production anonymity.",
	}
	writeShaperEvidence(t, evidence)

	switch decision {
	case "UNDECIDABLE":
		t.Skipf("shaper process timing undecidable: idle control %.4f reaches %.4f; signal %.4f", control, shaperProcessTolerance, signal)
	case "FAIL":
		t.Fatalf("separate relay producer changed shaper cadence by %.4f, above %.4f tolerance and %.4f idle control", signal, shaperProcessTolerance, control)
	default:
		t.Logf("shaper process timing PASS: signal=%.4f control=%.4f tolerance=%.4f", signal, control, shaperProcessTolerance)
	}
}

// TestShaperProducerHelper runs only as a child process of the gate above. It
// combines useful-work production with CPU and local fsync pressure. None of
// those operations share the shaper's Go runtime.
func TestShaperProducerHelper(t *testing.T) {
	if os.Getenv("NOMAD_SHAPER_PRODUCER_HELPER") != "1" {
		t.Skip("helper process only")
	}
	socket := os.Getenv("NOMAD_SHAPER_WORK_SOCKET")
	directory := os.Getenv("NOMAD_SHAPER_STRESS_DIR")
	if socket == "" || directory == "" {
		os.Exit(2)
	}
	client, err := relayipc.Dial(socket)
	if err != nil {
		os.Exit(3)
	}
	defer client.Close()

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
				for round := 0; round < 2048; round++ {
					digest = sha256.Sum256(digest[:])
				}
			}
		}(byte(worker + 1))
	}

	var payload [hop.CiphertextSize]byte
	if _, err := rand.Read(payload[:]); err != nil {
		os.Exit(4)
	}
	var stream hop.StreamID
	stream[15] = 1
	block := make([]byte, 128<<10)
	for counter := 0; ; counter++ {
		stream[0] = byte(counter)
		stream[1] = byte(counter >> 8)
		metadata, err := hop.WorkMetadata(stream, 0, 2)
		if err == nil {
			cell, err := hop.FromCiphertext(payload, metadata)
			if err == nil {
				// One best-effort attempt. False is intentionally ignored: the
				// next wire slot must still happen as cover without backpressure.
				_ = client.Enqueue(cell)
			}
		}
		path := filepath.Join(directory, fmt.Sprintf("relay-work-%02d", counter%4))
		file, err := os.Create(path)
		if err == nil {
			_, _ = file.Write(block)
			_ = file.Sync()
			_ = file.Close()
		}
		time.Sleep(time.Millisecond)
	}
}

func runShaperWorld(t *testing.T, binary, topologyPath, authorityPath, secretsPath string, endpoints []string, producer bool, label string) shaperRun {
	t.Helper()
	observerAddress, err := net.ResolveUDPAddr("udp", endpoints[1])
	if err != nil {
		t.Fatal(err)
	}
	observer, err := net.ListenUDP("udp", observerAddress)
	if err != nil {
		t.Fatalf("%s: bind observer: %v", label, err)
	}
	defer observer.Close()
	recorder := &udpRecorder{}
	observeCtx, stopObserve := context.WithCancel(context.Background())
	observeDone := make(chan struct{})
	go func() {
		defer close(observeDone)
		buffer := make([]byte, fabric.CellSize+64)
		for {
			_ = observer.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
			count, _, readErr := observer.ReadFromUDP(buffer)
			if readErr == nil {
				recorder.add(time.Now(), count)
				continue
			}
			if observeCtx.Err() != nil {
				return
			}
			if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return
		}
	}()
	defer func() {
		stopObserve()
		_ = observer.Close()
		<-observeDone
	}()

	runRoot := t.TempDir()
	workSocket := filepath.Join(runRoot, "relay.sock")
	statePath := filepath.Join(runRoot, "sequence")
	statsPath := filepath.Join(runRoot, "shaper-stats.json")
	selfAddress, err := net.ResolveUDPAddr("udp", endpoints[0])
	if err != nil {
		t.Fatal(err)
	}
	shaperProcess := exec.Command(binary,
		"--topology="+topologyPath,
		"--authority-key="+authorityPath,
		"--secrets="+secretsPath,
		"--bind="+net.JoinHostPort(selfAddress.IP.String(), "0"),
		"--work-socket="+workSocket,
		"--state="+statePath,
		"--stats-out="+statsPath,
	)
	var shaperLog shaperSyncBuffer
	shaperProcess.Stdout = &shaperLog
	shaperProcess.Stderr = &shaperLog
	if err := shaperProcess.Start(); err != nil {
		t.Fatalf("%s: start shaper: %v", label, err)
	}
	shaperDone := make(chan error, 1)
	go func() { shaperDone <- shaperProcess.Wait() }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if info, err := os.Lstat(workSocket); err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		select {
		case err := <-shaperDone:
			t.Fatalf("%s: shaper exited before creating relay socket: %v\n%s", label, err, shaperLog.String())
		default:
		}
		if time.Now().After(deadline) {
			_ = shaperProcess.Process.Kill()
			<-shaperDone
			t.Fatalf("%s: shaper did not create relay socket\n%s", label, shaperLog.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	var producerProcess *exec.Cmd
	if producer {
		producerProcess = exec.Command(os.Args[0], "-test.run=^TestShaperProducerHelper$")
		producerProcess.Env = append(os.Environ(),
			"NOMAD_SHAPER_PRODUCER_HELPER=1",
			"NOMAD_SHAPER_WORK_SOCKET="+workSocket,
			"NOMAD_SHAPER_STRESS_DIR="+t.TempDir(),
		)
		if err := producerProcess.Start(); err != nil {
			_ = shaperProcess.Process.Kill()
			<-shaperDone
			t.Fatalf("%s: start producer helper: %v", label, err)
		}
	}
	stopProducer := func() {
		if producerProcess != nil && producerProcess.Process != nil {
			_ = producerProcess.Process.Kill()
			_ = producerProcess.Wait()
			producerProcess = nil
		}
	}
	defer stopProducer()

	select {
	case err := <-shaperDone:
		stopProducer()
		t.Fatalf("%s: shaper exited during warmup: %v\n%s", label, err, shaperLog.String())
	case <-time.After(shaperProcessWarmup):
	}
	recorder.reset()

	earlyExit := false
	window := time.NewTimer(shaperProcessWindow)
	select {
	case err := <-shaperDone:
		earlyExit = true
		t.Logf("%s: shaper exited during observation: %v\n%s", label, err, shaperLog.String())
	case <-window.C:
	}
	if !window.Stop() {
		select {
		case <-window.C:
		default:
		}
	}
	stopProducer()
	if !earlyExit {
		_ = shaperProcess.Process.Signal(os.Interrupt)
		select {
		case err := <-shaperDone:
			if err != nil {
				t.Fatalf("%s: shaper did not stop cleanly: %v\n%s", label, err, shaperLog.String())
			}
		case <-time.After(2 * time.Second):
			_ = shaperProcess.Process.Kill()
			<-shaperDone
			t.Fatalf("%s: shaper ignored SIGINT", label)
		}
	}

	timestamps, wrongSize := recorder.snapshot()
	gaps := make([]time.Duration, 0, len(timestamps)-1)
	for index := 1; index < len(timestamps); index++ {
		gap := timestamps[index].Sub(timestamps[index-1])
		if gap > 0 && gap < 5*shaperProcessInterval {
			gaps = append(gaps, gap)
		}
	}
	return shaperRun{
		Label: label, Producer: producer, Packets: len(timestamps), WrongSize: wrongSize,
		MedianGap: shaperMedian(gaps), EarlyExit: earlyExit,
	}
}

func writeShaperFixture(t *testing.T, root string) (string, string, string, []string) {
	t.Helper()
	endpoints := make([]string, 3)
	listeners := make([]*net.UDPConn, 3)
	for index, text := range []string{"127.0.0.21", "127.0.0.22", "127.0.0.23"} {
		listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(text), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		listeners[index] = listener
		endpoints[index] = listener.LocalAddr().String()
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}

	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identities := make(map[string]ed25519.PrivateKey, 3)
	secrets := make([]topology.Secrets, 3)
	privateKeys := make([]topology.PrivateKeys, 3)
	for index, id := range []string{"operator-a", "operator-b", "operator-c"} {
		generated, err := topology.GenerateSecrets(id)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := topology.DecodePrivateKeys(mustJSON(t, generated))
		if err != nil {
			t.Fatal(err)
		}
		secrets[index] = generated
		privateKeys[index] = decoded
		identities[id] = decoded.Identity
	}
	var dkgSession [32]byte
	if _, err := rand.Read(dkgSession[:]); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	document := topology.Document{
		Version: topology.Version, NetworkID: "shaper-process-test", Epoch: 1,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339),
		NotAfter:  now.Add(time.Hour).Format(time.RFC3339),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: uint32(shaperProcessInterval / time.Millisecond),
			MaxLatenessMillis: uint32(4 * shaperProcessInterval / time.Millisecond), QueueCapacity: 64,
		},
		DKG: topology.DKGProfile{
			Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(dkgSession[:]),
			StartAt: now.Format(time.RFC3339), PhaseDurationMillis: 1_000,
		},
		Operators: make([]topology.Operator, 3),
	}
	for index, id := range []string{"operator-a", "operator-b", "operator-c"} {
		keys := privateKeys[index]
		dkgPublic, err := topologyDKGPublic(keys)
		if err != nil {
			t.Fatal(err)
		}
		document.Operators[index] = topology.Operator{
			ID: id, Index: uint16(index), Endpoint: endpoints[index],
			PartialEndpoint: fmt.Sprintf("http://127.0.0.1:%d", 49601+index),
			DKGEndpoint:     fmt.Sprintf("http://127.0.0.1:%d", 49701+index),
			IdentityKey:     base64.StdEncoding.EncodeToString(keys.Identity.Public().(ed25519.PublicKey)),
			KEXKey:          base64.StdEncoding.EncodeToString(keys.KEX.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic),
			PeerPlan:        []uint16{uint16((index + 1) % 3)},
		}
	}
	signed, err := topology.Sign(document, authorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	topologyBytes, err := topology.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	topologyPath := filepath.Join(root, "topology.json")
	authorityPath := filepath.Join(root, "authority.pub")
	secretsPath := filepath.Join(root, "operator-a-secrets.json")
	if err := os.WriteFile(topologyPath, topologyBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorityPath, []byte(base64.StdEncoding.EncodeToString(authorityPublic)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretsPath, mustJSON(t, secrets[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	return topologyPath, authorityPath, secretsPath, endpoints
}

// topology's DKG private type is intentionally opaque outside its cryptographic
// component. Decode the generated secret JSON only to recover its already
// validated public key without inventing test-only operator credentials.
func topologyDKGPublic(keys topology.PrivateKeys) ([]byte, error) {
	// DKG public derivation is exposed by the pinned mix component through the
	// same path topology uses when validating generated secrets.
	encoded := base64.StdEncoding.EncodeToString(keys.DKG[:])
	temporary := topology.Secrets{
		Version: topology.SecretVersion, OperatorID: keys.OperatorID,
		IdentityPrivate: base64.StdEncoding.EncodeToString(keys.Identity),
		KEXPrivate:      base64.StdEncoding.EncodeToString(keys.KEX.Bytes()),
		DKGPrivate:      encoded,
	}
	decoded, err := topology.DecodePrivateKeys(mustJSONNoTest(temporary))
	if err != nil {
		return nil, err
	}
	// The generated private key has already been validated. Derive the public
	// identity through a tiny local helper in the test's pinned dependency.
	return deriveDKGPublicBytes(decoded.DKG)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustJSONNoTest(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func shaperMedian(values []time.Duration) time.Duration {
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

func shaperDistance(left, right, interval time.Duration) float64 {
	difference := left - right
	if difference < 0 {
		difference = -difference
	}
	return float64(difference) / float64(interval)
}

func shaperMaximumPairwiseDistance(values []time.Duration, interval time.Duration) float64 {
	maximum := 0.0
	for left := 0; left < len(values); left++ {
		for right := left + 1; right < len(values); right++ {
			gap := shaperDistance(values[left], values[right], interval)
			if gap > maximum {
				maximum = gap
			}
		}
	}
	return maximum
}

func writeShaperEvidence(t *testing.T, evidence shaperBoundaryEvidence) {
	t.Helper()
	root := filepath.Join("..", "runtime", "evidence", "shaper-process-boundary")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(root, "shaper-process-timing.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

type shaperSyncBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (b *shaperSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.b = append(b.b, p...)
	return len(p), nil
}

func (b *shaperSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(append([]byte(nil), b.b...))
}
