//go:build linux

package nomadbrowser_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/Jtensetti/nomad-browser/internal/demotrust"
)

// What is needed is a measurement rather than an argument: zero browser-originated
// DNS, and zero ordinary networking.
//
// The dependency-graph tests establish that no networking package is linked and
// the namespace gate establishes that there is nowhere to reach. Neither counts
// what the process actually put on a wire. This does.
//
// The count comes from the interface counters in /proc/net/dev rather than from
// a packet capture. A capture was tried first and abandoned: tcpdump in a user
// namespace reported "48 packets received by filter, 0 packets captured" on
// roughly two runs in three, so the same traffic produced 32 packets or 0
// depending on the run. Every one of those zeros looks exactly like this test's
// own claim. The counters have no attach to race, need no external tool and no
// privilege, and count every frame the namespace's only interface carried.
//
// What this cannot see is a packet that was never emitted because there was no
// route -- but neither could a capture, since no frame exists. That the client
// has nowhere to reach is the namespace gate's claim; this one is that it does
// not even try.
const (
	captureChildMarker = "NOMAD_BROWSER_CAPTURE_CHILD"
	captureClientVar   = "NOMAD_BROWSER_CAPTURE_CLIENT"
	captureObjectsVar  = "NOMAD_BROWSER_CAPTURE_OBJECTS"
	captureModeVar     = "NOMAD_BROWSER_CAPTURE_MODE"
)

type interfaceRequest struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// bringLoopbackUp starts loopback inside a fresh namespace through an ioctl.
// iproute2 is not installed here or on the runners, and adding a dependency to
// a test that exists to bound dependencies would be an odd trade.
//
// A new namespace's one interface is DOWN. Leaving it down would make this
// measurement meaningless: nothing could be carried, so a count of zero would
// say nothing about the client.
func bringLoopbackUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)

	var request interfaceRequest
	copy(request.name[:], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&request))); errno != 0 {
		return fmt.Errorf("read loopback flags: %w", errno)
	}
	request.flags |= syscall.IFF_UP | syscall.IFF_RUNNING
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&request))); errno != 0 {
		return fmt.Errorf("bring loopback up: %w", errno)
	}
	return nil
}

// packetsCarried totals the transmitted and received packet counters across
// every interface in this network namespace.
func packetsCarried() (int64, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, err
	}
	var total int64
	for _, line := range strings.Split(string(data), "\n") {
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue // the two header lines
		}
		fields := strings.Fields(line[colon+1:])
		// receive: bytes packets ... (2nd), transmit: bytes packets (10th).
		if len(fields) < 10 {
			return 0, fmt.Errorf("/proc/net/dev line has %d fields: %q", len(fields), line)
		}
		for _, index := range []int{1, 9} {
			count, err := strconv.ParseInt(fields[index], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("/proc/net/dev field %d: %w", index, err)
			}
			total += count
		}
	}
	return total, nil
}

type namespaceMechanism struct {
	name string
	argv []string
}

// Least privilege first. Ubuntu 24.04 restricts unprivileged user namespaces
// through AppArmor, which is why the runners need the third.
var namespaceMechanisms = []namespaceMechanism{
	{"userns", []string{"unshare", "--user", "--map-root-user", "--net"}},
	{"root", []string{"unshare", "--net"}},
	{"sudo", []string{"sudo", "-n", "-E", "unshare", "--net"}},
}

func namespaceRunner() (namespaceMechanism, bool) {
	for _, mechanism := range namespaceMechanisms {
		if forced := os.Getenv("NOMAD_NETNS_KIND"); forced != "" && forced != mechanism.name {
			continue
		}
		if _, err := exec.LookPath(mechanism.argv[0]); err != nil {
			continue
		}
		probe := exec.Command(mechanism.argv[0],
			append(append([]string{}, mechanism.argv[1:]...), "true")...)
		if probe.Run() == nil {
			return mechanism, true
		}
	}
	return namespaceMechanism{}, false
}

// skipOrFail uses requireCapabilityGates from runtime_boundary_test.go rather
// than declaring a second copy: two copies of that switch could drift apart,
// and the one that drifted would be the gate that quietly stopped being
// required.
func skipOrFail(t *testing.T, reason string) {
	t.Helper()
	if requireCapabilityGates("tcpdump") {
		t.Fatalf("%s -- and this environment declared the tcpdump capability, so it "+
			"is supposed to run this gate; skipping would report what passing reports", reason)
	}
	t.Skip(reason)
}

func TestTheClientEmitsNoPacketsAndNoDNS(t *testing.T) {
	if os.Getenv(captureChildMarker) == "1" {
		runCountedChild(t)
		return
	}
	mechanism, available := namespaceRunner()
	if !available {
		skipOrFail(t, "no way to obtain a network namespace on this host; an "+
			"environment limit and not a pass")
	}

	client := buildClientBinary(t)
	objects := materializeCorpus(t)

	// The control first. If the counters do not move for traffic that certainly
	// happened, a zero from the client would mean nothing.
	control := countedRun(t, mechanism, "control", client, objects)
	if control == 0 {
		t.Fatalf("the control carried no packets, so the counters are not measuring " +
			"and a zero from the client would be meaningless")
	}
	t.Logf("MEASURED: the control carried %d packets, so the counters move", control)

	emitted := countedRun(t, mechanism, "client", client, objects)
	if emitted != 0 {
		t.Fatalf("the client put %d packets on the wire in a namespace where the "+
			"control carried %d; a reader of local objects emits nothing, DNS "+
			"included", emitted, control)
	}
	t.Logf("MEASURED: the client loaded and searched the corpus and put 0 packets on "+
		"the wire, DNS included, where a control run carried %d", control)
}

// countedRun runs one mode inside the namespace and returns the packet delta
// the child measured there.
func countedRun(t *testing.T, mechanism namespaceMechanism, mode, client, objects string) int64 {
	t.Helper()
	argv := append(append([]string{}, mechanism.argv[1:]...),
		os.Args[0], "-test.run", "^TestTheClientEmitsNoPacketsAndNoDNS$", "-test.v")
	command := exec.Command(mechanism.argv[0], argv...)
	command.Env = append(os.Environ(),
		captureChildMarker+"=1",
		captureClientVar+"="+client,
		captureObjectsVar+"="+objects,
		captureModeVar+"="+mode)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s run failed (%s namespace):\n%s", mode, mechanism.name, output)
	}
	if strings.Contains(string(output), "SKIP") {
		t.Fatalf("the %s child skipped:\n%s", mode, output)
	}
	return parseDelta(t, mode, string(output))
}

// parseDelta reads the one line the child prints. It is parsed rather than
// inferred, so a child that failed to report is an error and not a zero.
func parseDelta(t *testing.T, mode, output string) int64 {
	t.Helper()
	const marker = "PACKETS-CARRIED "
	for _, line := range strings.Split(output, "\n") {
		index := strings.Index(line, marker)
		if index < 0 {
			continue
		}
		delta, err := strconv.ParseInt(strings.TrimSpace(line[index+len(marker):]), 10, 64)
		if err != nil {
			t.Fatalf("%s child reported an unparsable count: %v", mode, err)
		}
		return delta
	}
	t.Fatalf("the %s child reported no count:\n%s", mode, output)
	return 0
}

func runCountedChild(t *testing.T) {
	if err := bringLoopbackUp(); err != nil {
		t.Fatalf("could not start loopback in the namespace: %v", err)
	}
	before, err := packetsCarried()
	if err != nil {
		t.Fatal(err)
	}
	switch os.Getenv(captureModeVar) {
	case "control":
		emitControlTraffic(t)
	case "client":
		runClientCounted(t)
	default:
		t.Fatal("the child was started with no mode")
	}
	after, err := packetsCarried()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PACKETS-CARRIED %d\n", after-before)
}

// emitControlTraffic makes packets the counters must record. It is loopback
// traffic rather than an attempt to leave, because there is nowhere to go:
// what is proved is that the counters see what the client would put on the
// wire if it put anything.
func emitControlTraffic(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("control listener: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = connection.Write([]byte("control"))
			_ = connection.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		connection, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatalf("control connection %d: %v", i, err)
		}
		_, _ = io.ReadAll(connection)
		_ = connection.Close()
	}
}

func runClientCounted(t *testing.T) {
	client := os.Getenv(captureClientVar)
	objects := os.Getenv(captureObjectsVar)
	if client == "" || objects == "" {
		t.Fatal("the child was started without a client or a corpus")
	}
	command := exec.Command(client, "-objects", objects, "-trust", demotrust.PublisherKey)
	command.Stdin = strings.NewReader("list\nsearch nomad\nquit\n")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the client failed inside the namespace: %v\n%s", err, output)
	}
	// A client that did nothing would emit nothing, which is not the claim.
	if !strings.Contains(string(output), "verified objects") {
		t.Fatalf("the client did not load the corpus:\n%s", output)
	}
	if !strings.Contains(string(output), "lexical ranking") {
		t.Fatalf("the client did not rank the corpus:\n%s", output)
	}
}

func buildClientBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "nomad-browser")
	build := exec.Command("go", "build", "-o", binary, "./cmd/nomad-browser")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the client: %v\n%s", err, output)
	}
	return binary
}

func materializeCorpus(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("macos", "Sources", "NomadBrowser",
		"Resources", "demo-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelopes []json.RawMessage
	if err := json.Unmarshal(data, &envelopes); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for index, envelope := range envelopes {
		name := filepath.Join(directory, fmt.Sprintf("object-%d.nomadobject", index))
		if err := os.WriteFile(name, envelope, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}
