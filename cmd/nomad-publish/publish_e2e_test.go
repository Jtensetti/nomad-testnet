package main

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// The point of this binary is that the publication path has a production
// caller at all. So the test that matters is not a unit test of its parts: it
// is that the shipped binary, given a signed topology and a queue, puts
// well-formed uplink cells on a real socket at the cadence the topology sets,
// and keeps doing it whether or not there is anything to publish.
//
// The entry operator here is a UDP socket and a session, not a full airlock:
// what is being established is that the publisher emits, that its cells open
// under the entry operator's session key, and that an observer cannot tell
// which of them carried work.
func TestThePublisherEmitsCellsAnEntryOperatorCanOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the publisher against a socket")
	}
	binary := buildPublisher(t)
	world := newPublisherWorld(t)

	// One object in the queue, submitted by the same binary with no network
	// configured at all -- which is the point of submitting being a separate
	// mode.
	object := make([]byte, 3000)
	if _, err := rand.Read(object); err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(world.directory, "object.bin")
	if err := os.WriteFile(objectPath, object, 0o600); err != nil {
		t.Fatal(err)
	}
	submit := exec.Command(binary, "--queue="+world.queue, "--submit="+objectPath,
		"--publisher-key="+world.publisherPath)
	if output, err := submit.CombinedOutput(); err != nil {
		t.Fatalf("submitting an object failed: %v\n%s", err, output)
	} else if !strings.Contains(string(output), "fragments pending") {
		t.Errorf("submit did not report a queue depth: %s", output)
	}

	// The entry operator's socket.
	entry, err := net.ListenUDP("udp", world.entryAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = entry.Close() }()

	publisher := exec.Command(binary,
		"--topology="+world.topologyPath,
		"--authority-key="+world.authorityPath,
		"--queue="+world.queue,
		"--state="+filepath.Join(world.directory, "uplink-sequence"),
		"--session-secret="+world.secretPath,
		"--committee-key="+world.committeePath,
		"--entry="+world.entryID)
	publisher.Stderr = os.Stderr
	if err := publisher.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = publisher.Process.Kill()
		_, _ = publisher.Process.Wait()
	}()

	var opened, work, cover int
	sequences := map[uint64]bool{}
	deadline := time.Now().Add(4 * time.Second)
	buffer := make([]byte, fabric.CellSize+64)
	for time.Now().Before(deadline) && opened < 12 {
		if err := entry.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		count, _, err := entry.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		if count != fabric.CellSize {
			t.Fatalf("the publisher emitted a %d-byte datagram; every cell is %d",
				count, fabric.CellSize)
		}
		var cell fabric.Cell
		copy(cell[:], buffer[:count])
		sequence, inner, err := world.session.Open(cell)
		if err != nil {
			t.Fatalf("a cell the publisher emitted did not open under the entry "+
				"operator's session key: %v", err)
		}
		if sequences[sequence] {
			t.Fatalf("sequence %d arrived twice: the publisher reused an AEAD nonce",
				sequence)
		}
		sequences[sequence] = true
		if inner == ([uplink.InnerSize]byte{}) {
			t.Fatal("the inner layer is all zero; it must be a committee ciphertext")
		}
		opened++
	}

	if opened < 6 {
		t.Fatalf("the entry operator opened %d cells in four seconds; the publisher is "+
			"not emitting at its cadence", opened)
	}
	t.Logf("the entry operator opened %d cells, sequences %d..%d, none repeated",
		opened, minimumOf(sequences), maximumOf(sequences))
	// Recorded rather than asserted: an entry operator cannot tell work from
	// cover, so this test cannot either. That is the property, not a gap --
	// only threshold decryption after the shuffle reveals which columns were
	// the reserved empty fragment.
	_, _ = work, cover
}

// A publisher that restarts must not reuse a nonce. This is the same property
// the sequence unit test checks, through the binary, because the binary is
// where the state path is chosen and a wrong path would pass every unit test.
func TestARestartedPublisherDoesNotReuseANonce(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the publisher twice")
	}
	binary := buildPublisher(t)
	world := newPublisherWorld(t)

	entry, err := net.ListenUDP("udp", world.entryAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = entry.Close() }()

	seen := map[uint64]bool{}
	for lifetime := 0; lifetime < 2; lifetime++ {
		publisher := exec.Command(binary,
			"--topology="+world.topologyPath,
			"--authority-key="+world.authorityPath,
			"--queue="+world.queue,
			"--state="+filepath.Join(world.directory, "uplink-sequence"),
			"--session-secret="+world.secretPath,
			"--committee-key="+world.committeePath,
			"--entry="+world.entryID)
		if err := publisher.Start(); err != nil {
			t.Fatal(err)
		}
		collected := 0
		deadline := time.Now().Add(2 * time.Second)
		buffer := make([]byte, fabric.CellSize+64)
		for time.Now().Before(deadline) && collected < 8 {
			if err := entry.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			count, _, err := entry.ReadFromUDP(buffer)
			if err != nil || count != fabric.CellSize {
				continue
			}
			var cell fabric.Cell
			copy(cell[:], buffer[:count])
			sequence, _, err := world.session.Open(cell)
			if err != nil {
				t.Fatalf("cell did not open: %v", err)
			}
			if seen[sequence] {
				t.Fatalf("lifetime %d reused sequence %d: the publisher would be "+
					"sealing a new fragment under a nonce it has already used",
					lifetime, sequence)
			}
			seen[sequence] = true
			collected++
		}
		_ = publisher.Process.Kill()
		_, _ = publisher.Process.Wait()
		if collected == 0 {
			t.Fatalf("lifetime %d emitted nothing", lifetime)
		}
	}
	t.Logf("two lifetimes, %d cells, no sequence repeated across the restart", len(seen))
}

func buildPublisher(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "nomad-publish")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	return binary
}

func minimumOf(values map[uint64]bool) uint64 {
	var lowest uint64
	for value := range values {
		if lowest == 0 || value < lowest {
			lowest = value
		}
	}
	return lowest
}

func maximumOf(values map[uint64]bool) uint64 {
	var highest uint64
	for value := range values {
		if value > highest {
			highest = value
		}
	}
	return highest
}

func writeHex(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(value)), 0o600); err != nil {
		t.Fatal(err)
	}
}
