package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"crypto/rand"

	"github.com/Jtensetti/nomad-testnet/live/entry"
)

// The publication path, as separate operating-system processes on a real
// socket, with a packet capture of what an observer between them sees.
//
// Everything known about this path was previously known from inside one test
// binary where the publisher, the entry operator and the committee shared an
// address space. That is enough to establish that the parts compose and not
// enough to establish anything about a boundary: a claim about what an entry
// operator can observe is a claim about a process that receives datagrams from
// strangers, and a function call is not that.
//
// What this covers: two shipped binaries, a real UDP socket, a session
// established in band across the process boundary, deposits reaching a mailbox
// the publisher cannot see, a batch sealed on a public schedule, and a capture
// judged by the same fail-closed rule the relay fabric's capture is judged by.
//
// What it does not cover: separate hosts. Loopback is a real interface and
// these are real processes, but a WAN adversary and a real network's loss and
// reordering are not here, and that needs infrastructure this project does not
// have (EB-3).

func buildBinary(t *testing.T, packagePath, name string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", binary, packagePath)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", packagePath, err, output)
	}
	return binary
}

func TestThePublicationPathAcrossRealProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("runs two binaries against a real socket")
	}
	// Gated like the other timing campaigns. This test runs two processes and
	// a packet capture for a quarter of a minute, and in the default sweep its
	// own load is enough to push the flood and cadence tests in other packages
	// past their thresholds -- so left ungated it would make the suite report
	// failures it caused itself.
	if os.Getenv("NOMAD_TIMING_CAMPAIGN") != "1" {
		t.Skip("cross-process boundary campaign; set NOMAD_TIMING_CAMPAIGN=1 to run it")
	}
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("tcpdump is not available, so no capture can be taken")
	}

	entryBinary := buildBinary(t, ".", "nomad-entry")
	publishBinary := buildBinary(t, "../nomad-publish", "nomad-publish")
	world := newEntryWorld(t)

	// One object queued with no network configured at all. Submitting is a
	// separate mode of the publisher for exactly this reason: queueing must not
	// require, or touch, an uplink.
	// Large enough that draining it spans several deposit cutoffs. At 504
	// bytes per fragment this is 54 of them, and the publisher can emit at
	// most ~43 in the run below, so the queue is still non-empty every time a
	// window shuts. A 4096-byte object drained inside the first open window,
	// which made the shut-window check further down examine an empty
	// directory and report success for having nothing to look at.
	object := make([]byte, 24576)
	if _, err := rand.Read(object); err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(world.directory, "object.bin")
	if err := os.WriteFile(objectPath, object, 0o600); err != nil {
		t.Fatal(err)
	}
	submit := exec.Command(publishBinary,
		"--queue", world.queuePath,
		"--submit", objectPath,
		"--publisher-key", world.publisherPath)
	if output, err := submit.CombinedOutput(); err != nil {
		t.Fatalf("submit: %v\n%s", err, output)
	}

	// The capture starts before either process, so the handshake -- which is
	// the first cell of the session and indistinguishable from any other -- is
	// in it.
	pcapPath := filepath.Join(world.directory, "publication.pcap")
	port := strconv.Itoa(world.entryAddress.Port)
	capture := exec.Command("tcpdump", "-i", "lo", "-U", "-w", pcapPath,
		"udp", "and", "port", port)
	captureOutput := &strings.Builder{}
	capture.Stderr = captureOutput
	if err := capture.Start(); err != nil {
		t.Fatalf("start tcpdump: %v", err)
	}
	captureStopped := false
	stopCapture := func() {
		if captureStopped {
			return
		}
		captureStopped = true
		// SIGTERM, not SIGKILL: tcpdump flushes on the way out, and a killed
		// capture loses whatever is still buffered. -U keeps the buffer small
		// but does not make the flush unnecessary.
		_ = capture.Process.Signal(syscall.SIGTERM)
		_ = capture.Wait()
	}
	defer stopCapture()
	// tcpdump needs a moment to attach before it sees anything.
	time.Sleep(500 * time.Millisecond)

	// A short release period so the run crosses at least one deposit cutoff and
	// one seal. A deployment's period is far longer; what is being exercised is
	// that the boundary rolls at all, not the number.
	operator := exec.Command(entryBinary,
		"--topology", world.topologyPath,
		"--authority-key", world.authorityPath,
		"--secrets", world.secretsPath,
		"--dkg-certificate", world.certificatePath,
		"--listen", world.entryAddress.String(),
		"--batches", world.batchDirectory,
		"--health", world.healthPath,
		"--period", "3s",
		"--deposit-cutoff", "1s",
		"--batch-size", "8",
		"--per-session", "8")
	operatorOutput := &strings.Builder{}
	operator.Stdout, operator.Stderr = operatorOutput, operatorOutput
	if err := operator.Start(); err != nil {
		t.Fatalf("start entry operator: %v", err)
	}
	defer func() {
		_ = operator.Process.Signal(syscall.SIGTERM)
		_ = operator.Wait()
	}()
	time.Sleep(300 * time.Millisecond)

	// The same schedule the operator was given, and this is load-bearing.
	// The publisher decides what to carry from the deposit window, so a
	// publisher configured with a different period or cutoff would hand work
	// to its emission path while the operator's window was shut, which is the
	// loss DEC-020 measured. These parameters are flags on both sides and
	// belong in the signed topology; until they are, matching them is the
	// deployment's job and this test is where that shows.
	publisher := exec.Command(publishBinary,
		"--topology", world.topologyPath,
		"--authority-key", world.authorityPath,
		"--queue", world.queuePath,
		"--state", filepath.Join(world.directory, "uplink-state.json"),
		"--committee-key", world.committeePath,
		"--entry", world.entryID,
		"--period", "3s",
		"--deposit-cutoff", "1s",
		"--batch-size", "8",
		"--per-session", "8")
	publisherOutput := &strings.Builder{}
	publisher.Stdout, publisher.Stderr = publisherOutput, publisherOutput
	if err := publisher.Start(); err != nil {
		t.Fatalf("start publisher: %v", err)
	}
	defer func() {
		_ = publisher.Process.Signal(syscall.SIGTERM)
		_ = publisher.Wait()
	}()

	// Long enough for a handshake, sixty-odd cells at the 200 ms cadence, and
	// several release epochs at the 3 s period. The queue is sampled
	// throughout: when a fragment leaves the durable queue is the whole
	// question, and it is answerable from the filesystem without decrypting
	// anything.
	samples := sampleQueue(t, world.queuePath, 13*time.Second, 50*time.Millisecond)

	_ = publisher.Process.Signal(syscall.SIGTERM)
	_ = publisher.Wait()
	_ = operator.Process.Signal(syscall.SIGTERM)
	_ = operator.Wait()
	stopCapture()

	// The publisher fails closed if it cannot seal within its interval, and on
	// a machine running every other package under -race it sometimes cannot.
	// That is the publisher behaving correctly and the machine being too busy
	// to host this test; it is not a fact about the boundary, and asserting
	// against it would report a boundary failure that did not happen.
	//
	// This is a skip rather than a pass because the process under test says so
	// itself, in as many words. Nothing here is inferred.
	if strings.Contains(publisherOutput.String(), "fixed-cadence deadline missed") {
		t.Skipf("the publisher could not hold its cadence on this machine and stopped, "+
			"which is what it is supposed to do; the boundary is untested on this run\n%s",
			publisherOutput)
	}

	stats := readEntryHealth(t, world.healthPath)
	t.Logf("entry operator: %+v", stats)
	if stats.Handshakes != 1 {
		t.Errorf("the entry operator established %d sessions; one publisher ran, "+
			"and a handshake is sent once per session\noperator:\n%s\npublisher:\n%s",
			stats.Handshakes, operatorOutput, publisherOutput)
	}
	if stats.Accepted < 15 {
		t.Errorf("only %d cells crossed the boundary into the mailbox\noperator:\n%s\n"+
			"publisher:\n%s", stats.Accepted, operatorOutput, publisherOutput)
	}
	if stats.Conflicted != 0 {
		t.Errorf("%d deposits collided; a publisher that retransmits its sealed cell "+
			"never does, and one that re-seals a fragment always does", stats.Conflicted)
	}

	// Cells still arrive outside the deposit window, and must: the cadence is
	// fixed and does not consult the schedule, so an observer sees the same
	// stream whatever the window is doing. What changed is what those cells
	// carry. They are cover, and the work that used to be in them is still on
	// the publisher's disk.
	total := stats.Accepted + stats.OutsideWindow + stats.RefusedCell + stats.Conflicted
	if total == 0 {
		t.Fatal("no cell reached the mailbox path at all")
	}
	if stats.OutsideWindow == 0 {
		t.Errorf("no cell arrived outside a deposit window in %s across a %s period; "+
			"the run did not cross a cutoff, so it does not exercise the boundary "+
			"this test exists for", 13*time.Second, 3*time.Second)
	}
	t.Logf("%d of %d cells (%.0f%%) arrived outside a deposit window; the cadence is "+
		"unchanged and every one of them was cover",
		stats.OutsideWindow, total, 100*float64(stats.OutsideWindow)/float64(total))

	// The fix DEC-022 records, at the boundary that decides it. Queue.Next
	// unlinks a fragment as it hands it out, so a fragment that leaves the
	// queue while the deposit window is shut is a fragment nothing holds any
	// more. Before the window gate that was 25-43% of a publisher's work.
	//
	// This is measured from the filesystem, on the two real processes, with no
	// access to either one's internals: a fragment count that falls between
	// two samples that both lie inside a shut window is work destroyed.
	shrinkages, considered := queueShrankWhileShut(t, samples, world.notBefore,
		3*time.Second, time.Second)
	// The positive control. An empty shrinkage list means nothing if no pair of
	// samples ever landed inside a shut window together -- the check would be
	// reporting that it had nothing to look at, in the same words it uses to
	// report that it looked and found nothing.
	if considered < 20 {
		t.Fatalf("only %d sample intervals fell inside a shut deposit window with work "+
			"still queued, across %s at a %s period; the shrinkage check below had "+
			"almost nothing to examine and its silence means nothing",
			considered, 13*time.Second, 3*time.Second)
	}
	t.Logf("%d sample intervals lay inside a shut deposit window with work queued",
		considered)
	if len(shrinkages) > 0 {
		t.Errorf("the publication queue lost %d fragment(s) while the deposit window was "+
			"shut: %v\nA fragment taken from the queue outside the window is refused by "+
			"the airlock and cannot be resent, so it is publication work destroyed "+
			"(DEC-020, DEC-022)", len(shrinkages), shrinkages)
	}
	if samples[len(samples)-1].fragments >= samples[0].fragments {
		t.Errorf("the queue went from %d fragments to %d; a publisher that never drains "+
			"would pass the check above by doing nothing",
			samples[0].fragments, samples[len(samples)-1].fragments)
	}
	if stats.WrongSize != 0 {
		t.Errorf("%d datagrams were not one cell", stats.WrongSize)
	}
	if stats.Sealed < 1 {
		t.Errorf("no release epoch was sealed in %s; the mailbox never moved", 13*time.Second)
	}

	// The mailbox produced something a shuffle chain could collect.
	batches, err := filepath.Glob(filepath.Join(world.batchDirectory, "release-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) < 1 {
		t.Fatalf("no sealed batch was written")
	}
	for _, path := range batches {
		if strings.HasSuffix(path, ".partial") {
			t.Errorf("%s is a half-written batch a collector could read", path)
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var batch struct {
			ReleaseEpoch uint64   `json:"release_epoch"`
			Digest       string   `json:"digest"`
			Columns      []string `json:"columns"`
		}
		if err := json.Unmarshal(encoded, &batch); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		// Every batch is the full fixed size whatever was deposited into it.
		// A batch whose length tracked its real deposits would publish the
		// epoch's occupancy to anybody who counted columns.
		if len(batch.Columns) != 8 {
			t.Errorf("%s carries %d columns, not the fixed batch size of 8",
				path, len(batch.Columns))
		}
		if batch.Digest == "" {
			t.Errorf("%s carries no digest", path)
		}
	}

	// The health check the operator would run.
	probe := exec.Command(entryBinary, "--check-health", world.healthPath,
		"--max-silence", "1m")
	if output, err := probe.CombinedOutput(); err != nil {
		t.Errorf("the service's own health check failed: %v\n%s", err, output)
	}

	verifyPublicationCapture(t, pcapPath, port, captureOutput.String())
}

// queueSample is the publication queue's depth at one instant.
type queueSample struct {
	at        time.Time
	fragments int
}

// sampleQueue counts queued fragments at a fixed interval for the whole run.
// It is deliberately dumb: a directory listing, no locking, no coordination
// with the publisher. A sample taken mid-unlink reads one fragment low, which
// can only produce a false shrinkage, never hide a real one -- and the
// shut-window check below requires BOTH samples to be inside the shut window,
// where the publisher should be doing nothing to the directory at all.
func sampleQueue(t *testing.T, queuePath string, duration, interval time.Duration) []queueSample {
	t.Helper()
	deadline := time.Now().Add(duration)
	samples := make([]queueSample, 0, int(duration/interval)+1)
	for {
		names, err := filepath.Glob(filepath.Join(queuePath, "*.fragment"))
		if err != nil {
			t.Fatalf("sample queue: %v", err)
		}
		samples = append(samples, queueSample{at: time.Now().UTC(), fragments: len(names)})
		if !time.Now().Before(deadline) {
			return samples
		}
		time.Sleep(interval)
	}
}

// queueShrankWhileShut reports every interval between consecutive samples that
// lies wholly inside a shut deposit window and across which the queue lost
// fragments.
//
// Both endpoints must be inside the shut part of the same epoch. An interval
// straddling the cutoff proves nothing: the fragment may have left while the
// window was still open, which is exactly what is supposed to happen.
func queueShrankWhileShut(t *testing.T, samples []queueSample, genesis time.Time,
	period, cutoff time.Duration) (shrinkages []string, considered int) {
	t.Helper()
	if len(samples) < 2 {
		t.Fatalf("only %d queue samples; the run measured nothing", len(samples))
	}
	shut := func(at time.Time) (uint64, bool) {
		if at.Before(genesis) {
			return 0, false
		}
		elapsed := at.Sub(genesis)
		epoch := uint64(elapsed / period)
		into := elapsed - time.Duration(epoch)*period
		return epoch, into >= period-cutoff
	}
	var found []string
	for i := 1; i < len(samples); i++ {
		previous, current := samples[i-1], samples[i]
		firstEpoch, firstShut := shut(previous.at)
		secondEpoch, secondShut := shut(current.at)
		if !firstShut || !secondShut || firstEpoch != secondEpoch {
			continue
		}
		// Only intervals where a shrinkage was possible count towards the
		// control. An empty queue cannot shrink, so counting those intervals
		// would let the check look thorough while examining nothing.
		if previous.fragments > 0 {
			considered++
		}
		if current.fragments >= previous.fragments {
			continue
		}
		found = append(found, fmt.Sprintf("epoch %d: %d -> %d fragments between %s and %s",
			firstEpoch, previous.fragments, current.fragments,
			previous.at.Format("15:04:05.000"), current.at.Format("15:04:05.000")))
	}
	return found, considered
}

func readEntryHealth(t *testing.T, path string) entry.Stats {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("entry health: %v", err)
	}
	var stats entry.Stats
	if err := json.Unmarshal(encoded, &stats); err != nil {
		t.Fatalf("entry health: %v", err)
	}
	return stats
}

// verifyPublicationCapture judges the wire with the same rule the relay
// fabric's capture is judged by.
//
// Reimplementing the cadence rule in Go for this one capture would let the two
// drift, and the direction they would drift is toward agreeing that a capture
// is fine. The script is fail-closed on anything it cannot parse, which is the
// property that matters: the packets an unfamiliar prefix would hide are
// exactly the ones a difference would appear in.
func verifyPublicationCapture(t *testing.T, pcapPath, port, captureLog string) {
	t.Helper()
	info, err := os.Stat(pcapPath)
	if err != nil {
		t.Fatalf("capture: %v\ntcpdump said:\n%s", err, captureLog)
	}
	if info.Size() == 0 {
		t.Fatalf("the capture is empty\ntcpdump said:\n%s", captureLog)
	}
	verify := exec.Command("python3", filepath.Join("..", "..", "scripts", "verify-pcap.py"),
		pcapPath, "200",
		"--filter", "udp port "+port,
		// One publisher, so one sender. The relay fabric's floor of three is
		// about a three-operator topology and says nothing here.
		"--min-senders", "1",
		"--min-cells", "20")
	verify.Dir = "."
	output, err := verify.CombinedOutput()
	if err != nil {
		t.Fatalf("the publication capture did not satisfy the cadence rule: %v\n%s\n"+
			"tcpdump said:\n%s", err, output, captureLog)
	}
	t.Logf("capture evidence: %s", strings.TrimSpace(string(output)))
}
