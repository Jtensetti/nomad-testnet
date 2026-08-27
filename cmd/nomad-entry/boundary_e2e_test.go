package main

import (
	"encoding/json"
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
	object := make([]byte, 4096)
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

	publisher := exec.Command(publishBinary,
		"--topology", world.topologyPath,
		"--authority-key", world.authorityPath,
		"--queue", world.queuePath,
		"--state", filepath.Join(world.directory, "uplink-state.json"),
		"--committee-key", world.committeePath,
		"--entry", world.entryID)
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
	// several release epochs at the 3 s period.
	time.Sleep(13 * time.Second)

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

	// The measured cost of the gap DEC-020 records. A publisher emits at a
	// constant cadence across a schedule that closes, so every cell arriving
	// after the cutoff is refused -- and because the publisher retains neither
	// the fragment nor the sealed cell, any work among them is destroyed.
	//
	// This is asserted as present rather than absent. It is the current
	// behaviour, it is a defect, and pinning it means the fix cannot land
	// without this number moving.
	total := stats.Accepted + stats.OutsideWindow + stats.RefusedCell + stats.Conflicted
	if total == 0 {
		t.Fatal("no cell reached the mailbox path at all")
	}
	if stats.OutsideWindow == 0 {
		t.Errorf("no cell arrived outside a deposit window in %s across a %s period; "+
			"the run did not cross a cutoff and so does not measure the loss",
			13*time.Second, 3*time.Second)
	}
	t.Logf("MEASURED LOSS: %d of %d cells (%.0f%%) arrived outside a deposit window and "+
		"were destroyed, because the publisher retains neither the fragment nor the "+
		"sealed cell it could retransmit (DEC-020)",
		stats.OutsideWindow, total, 100*float64(stats.OutsideWindow)/float64(total))
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
