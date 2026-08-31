package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// The generator against a real socket. The gate reads its report as evidence
// that a flood happened, so an instrument that silently sends nothing would
// make the gate report a quiet stack under a flood that never was.
func TestTheGeneratorDeliversWhatItReports(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	var received atomic.Uint64
	var wrongSize atomic.Uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			read, _, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if read != 1200 {
				wrongSize.Add(1)
			}
			received.Add(1)
		}
	}()

	directory := t.TempDir()
	reportPath := filepath.Join(directory, "load.json")
	binary := filepath.Join(directory, "nomad-load")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	command := exec.Command(binary,
		"--target", listener.LocalAddr().String(),
		"--rate", "2000", "--duration", "500ms", "--report", reportPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, output)
	}

	// The kernel drops datagrams a slow reader has not taken, so the received
	// count is a floor rather than an equality. What matters is that the
	// generator's own report is not fiction: it claims to have sent hundreds,
	// and hundreds have to arrive.
	time.Sleep(100 * time.Millisecond)
	_ = listener.SetReadDeadline(time.Now())
	<-done

	encoded, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var summary report
	if err := json.Unmarshal(encoded, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Sent < 500 {
		t.Fatalf("the generator reports %d datagrams for 500ms at 2000/s; it is not "+
			"producing the load a gate reading this report would assume", summary.Sent)
	}
	if summary.Failed != 0 {
		t.Errorf("%d sends failed: %s", summary.Failed, summary.FirstErr)
	}
	if got := received.Load(); got < summary.Sent/2 {
		t.Fatalf("the generator reported %d datagrams and only %d arrived; the report "+
			"is the gate's evidence that a flood happened and it must not overstate",
			summary.Sent, got)
	}
	if wrongSize.Load() != 0 {
		t.Errorf("%d datagrams were not the cell size, so they would be rejected on a "+
			"length comparison instead of costing the peer lookup this gate measures",
			wrongSize.Load())
	}
	t.Logf("reported %d sent, %d arrived at the socket", summary.Sent, received.Load())
}

// Every refusal the flags should make. One that accepted a zero rate or an
// absent target fails open in the gate: no load, no error, no finding.
func TestTheGeneratorRefusesArgumentsThatWouldSendNothing(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "nomad-load")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	for name, arguments := range map[string][]string{
		"no target":       {"--rate", "10", "--duration", "10ms"},
		"no rate":         {"--target", "127.0.0.1:9", "--duration", "10ms"},
		"no duration":     {"--target", "127.0.0.1:9", "--rate", "10"},
		"rate above cap":  {"--target", "127.0.0.1:9", "--rate", "200001", "--duration", "10ms"},
		"negative rate":   {"--target", "127.0.0.1:9", "--rate", "-1", "--duration", "10ms"},
		"impossible size": {"--target", "127.0.0.1:9", "--rate", "10", "--duration", "10ms", "--size", "70000"},
	} {
		t.Run(name, func(t *testing.T) {
			if output, err := exec.Command(binary, arguments...).CombinedOutput(); err == nil {
				t.Fatalf("accepted %v and exited zero\n%s", arguments, output)
			}
		})
	}
}
