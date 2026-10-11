//go:build linux

package nomadbrowser_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-browser/update"
)

// Runtime evidence about a release binary, as distinct from evidence about a
// package graph.
//
// architecture_test.go already gates the graph: the browser core's packages do
// not link net, net/http, crypto/tls or os/exec, so no binary built from them
// can open a socket. That is a strong argument and it is still an argument. It
// reasons from what the compiler was given to what the program does, and a
// reader is entitled to ask for the second thing directly.
//
// So the shipped binary is run, doing its real work, under a system-call trace,
// and every syscall that could reach a network is counted. DNS is included by
// construction: a resolver opens a socket like anything else, so there is no
// separate DNS check to forget.
//
// A trace is used rather than a packet capture on purpose. A capture sees what
// left; a trace sees what was *attempted*, including a connect that failed
// because nothing was listening, a resolver that gave up, and a socket opened
// and never used. For "cannot egress" the attempt is the interesting event.
//
// What this does not cover: QUIC, WebSockets, WebRTC, service workers,
// extensions and speculative fetch live in an engine, and the engine forks are
// parked. This is evidence about the Go binaries this repository ships and
// about nothing else.

// networkSyscalls is every way a Linux process reaches a network. socketpair is
// deliberately absent: it makes a bidirectional pipe between two file
// descriptors in one process and cannot address anything.
var networkSyscalls = []string{
	"socket", "connect", "sendto", "sendmsg", "sendmmsg",
	"recvfrom", "recvmsg", "bind", "listen", "accept", "accept4",
}

// strace writes "<pid>  syscall(...)" when -f and -o are combined, and
// "[pid N] syscall(...)" when it writes to stderr. An earlier version of this
// matched only the second form, so it parsed nothing and reported zero network
// syscalls for every binary -- including the control that opens one. The
// control is why that was caught rather than recorded as evidence.
var syscallLine = regexp.MustCompile(`^(?:\[pid\s+(?:\d+)\]\s+|\d+\s+)?(\w+)\(`)

// requireCapabilityGates reports whether this environment has declared that a
// named gate -- one depending on an external tool or a kernel capability -- can
// run here.
//
// A skip is green, so a gate that quietly stopped running is indistinguishable
// from one that passed, and where the environment has promised the capability
// its absence has to be a failure.
//
// Two ways to promise. NOMAD_REQUIRE_CAPABILITY_GATES=1 means everything, which
// is what the Linux job says. NOMAD_REQUIRE_CAPABILITIES is a comma-separated
// list, which is what a platform with some of the tools and not others needs:
// the macOS runner has python3 and no strace, and under the all-or-nothing
// version it could declare neither -- so the parser-differential gate would
// have become a silent skip on the platform the browser actually ships to.
func requireCapabilityGates(capability string) bool {
	if os.Getenv("NOMAD_REQUIRE_CAPABILITY_GATES") == "1" {
		return true
	}
	for _, declared := range strings.Split(os.Getenv("NOMAD_REQUIRE_CAPABILITIES"), ",") {
		if strings.TrimSpace(declared) == capability && capability != "" {
			return true
		}
	}
	return false
}

func traceAvailable(t *testing.T) string {
	t.Helper()
	strace, err := exec.LookPath("strace")
	if err == nil {
		return strace
	}
	if requireCapabilityGates("strace") {
		t.Fatal("strace is unavailable, and this environment declared the strace " +
			"capability, so it is supposed to run this gate. Skipping here would " +
			"report what passing reports.")
	}
	t.Skip("strace is unavailable, so the runtime boundary cannot be observed; " +
		"an environment limit and not a pass")
	return ""
}

// traceNetworkCalls runs a command under strace and returns the network
// syscalls it made, plus the command's own combined output.
func traceNetworkCalls(t *testing.T, strace string, name string, arguments ...string) ([]string, string) {
	t.Helper()
	tracePath := filepath.Join(t.TempDir(), "trace.txt")
	traced := append([]string{
		"-f", "-e", "trace=" + strings.Join(networkSyscalls, ","),
		"-o", tracePath, name,
	}, arguments...)
	command := exec.Command(strace, traced...)
	output, _ := command.CombinedOutput()

	content, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read trace: %v", err)
	}
	var found []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		match := syscallLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		call := match[1]
		for _, watched := range networkSyscalls {
			if call == watched {
				found = append(found, line)
				break
			}
		}
	}
	return found, string(output)
}

// buildBinary compiles one of this repository's commands the way a release
// does, so what is traced is a binary rather than a test process.
func buildBinary(t *testing.T, packagePath string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), filepath.Base(packagePath))
	build := exec.Command("go", "build", "-o", binary, packagePath)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", packagePath, err, output)
	}
	return binary
}

// releaseFixture writes a manifest, its artifact and a watermark, so the
// verifier can be traced doing the work it exists for rather than printing a
// usage message.
func releaseFixture(t *testing.T) (manifestPath, artifactPath, watermarkPath, keys string) {
	t.Helper()
	directory := t.TempDir()
	artifact := make([]byte, 4096)
	if _, err := rand.Read(artifact); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifact)

	manifest := update.Prepare(update.Manifest{
		Release: "1.2.3", Channel: "stable",
		ArtifactName:   "NomadBrowser-1.2.3.dmg",
		ArtifactDigest: hex.EncodeToString(digest[:]),
		ArtifactBytes:  int64(len(artifact)),
	})
	var trusted []string
	for approver := 0; approver < update.MinimumApprovals; approver++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if manifest, err = update.Approve(manifest, private); err != nil {
			t.Fatal(err)
		}
		trusted = append(trusted, hex.EncodeToString(public))
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	manifestPath = filepath.Join(directory, "manifest.json")
	artifactPath = filepath.Join(directory, manifest.ArtifactName)
	watermarkPath = filepath.Join(directory, "watermark.json")
	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath, artifactPath, watermarkPath, strings.Join(trusted, ",")
}

func TestTheReleaseVerifierMakesNoNetworkSyscallDoingItsWork(t *testing.T) {
	strace := traceAvailable(t)
	binary := buildBinary(t, "./cmd/nomad-browser-verify")
	manifestPath, artifactPath, watermarkPath, keys := releaseFixture(t)

	calls, output := traceNetworkCalls(t, strace, binary,
		"-manifest", manifestPath, "-artifact", artifactPath,
		"-watermark", watermarkPath, "-release-key", keys)

	// The run has to have done something, or zero syscalls means the binary
	// printed a usage message.
	if !strings.Contains(output, "1.2.3") {
		t.Fatalf("the verifier did not verify the fixture, so nothing was traced:\n%s", output)
	}
	if len(calls) != 0 {
		t.Fatalf("the release verifier made %d network syscall(s) while verifying a "+
			"release:\n%s", len(calls), strings.Join(calls, "\n"))
	}
	t.Logf("MEASURED: the shipped verifier completes a real verification with zero calls "+
		"to %s", strings.Join(networkSyscalls, ", "))
}

// Without this, "zero network syscalls" is indistinguishable from "the trace
// was not running". A binary that opens one socket must be caught.
func TestTheSyscallTraceCatchesABinaryThatOpensASocket(t *testing.T) {
	strace := traceAvailable(t)
	directory := t.TempDir()
	source := filepath.Join(directory, "main.go")
	program := `package main

import (
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("udp", "127.0.0.1:9")
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	_, _ = conn.Write([]byte("x"))
	_ = conn.Close()
	fmt.Println("control reached the network")
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "go.mod"),
		[]byte("module egresscontrol\n\ngo 1.25.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "control")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = directory
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the control: %v\n%s", err, output)
	}

	calls, output := traceNetworkCalls(t, strace, binary)
	if len(calls) == 0 {
		t.Fatalf("the trace saw no network syscall from a binary that opens a socket, "+
			"so it would see none from anything:\n%s", output)
	}
	t.Logf("MEASURED: the control produced %d network syscall(s), so a binary that "+
		"reached the network would not pass unnoticed", len(calls))
}

// The same measurement for the update verifier's library path, exercised
// through the binary with a manifest it must refuse. A refusal path that
// opened a socket -- to report, to check a revocation list, to phone home
// about a bad signature -- would be egress on exactly the input an attacker
// controls.
func TestARefusedReleaseAlsoMakesNoNetworkSyscall(t *testing.T) {
	strace := traceAvailable(t)
	binary := buildBinary(t, "./cmd/nomad-browser-verify")
	manifestPath, artifactPath, watermarkPath, keys := releaseFixture(t)

	// Corrupt the artifact so the digest no longer matches.
	if err := os.WriteFile(artifactPath, []byte("not the release"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls, output := traceNetworkCalls(t, strace, binary,
		"-manifest", manifestPath, "-artifact", artifactPath,
		"-watermark", watermarkPath, "-release-key", keys)

	if !strings.Contains(strings.ToLower(output), "digest") &&
		!strings.Contains(strings.ToLower(output), "artifact") {
		t.Fatalf("the verifier did not refuse the corrupted artifact, so the refusal "+
			"path was not traced:\n%s", output)
	}
	if len(calls) != 0 {
		t.Fatalf("refusing a release made %d network syscall(s):\n%s",
			len(calls), strings.Join(calls, "\n"))
	}
	t.Logf("MEASURED: refusing a corrupted release makes no network syscall either")
}

// The declaration is what turns a skip into a failure, so a typo in a workflow
// would quietly disarm every gate it names. These pin what each form means.
func TestACapabilityIsRequiredOnlyWhenTheEnvironmentSaysSo(t *testing.T) {
	for name, environment := range map[string]struct {
		blanket, list string
		capability    string
		want          bool
	}{
		"nothing declared":               {"", "", "strace", false},
		"blanket covers any capability":  {"1", "", "strace", true},
		"blanket covers another":         {"1", "", "python3", true},
		"blanket set to something else":  {"yes", "", "strace", false},
		"named and asked for":            {"", "python3", "python3", true},
		"named and not asked for":        {"", "python3", "strace", false},
		"one of several named":           {"", "python3,tcpdump", "tcpdump", true},
		"spaces around the names":        {"", " python3 , tcpdump ", "python3", true},
		"empty list matches nothing":     {"", "", "", false},
		"empty capability never matches": {"", "python3", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("NOMAD_REQUIRE_CAPABILITY_GATES", environment.blanket)
			t.Setenv("NOMAD_REQUIRE_CAPABILITIES", environment.list)
			if got := requireCapabilityGates(environment.capability); got != environment.want {
				t.Fatalf("with GATES=%q CAPABILITIES=%q, %q was %v and should be %v",
					environment.blanket, environment.list, environment.capability,
					got, environment.want)
			}
		})
	}
}
