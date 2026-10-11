package main

import (
	"bufio"
	"os/exec"
	"strings"
	"testing"
)

// A publisher process necessarily holds both halves the Selection Firewall
// separates: a local queue of private publication work, and an uplink that
// puts cells on a wire. That is not a violation -- it is the one process where
// the two must meet -- and it is exactly why the meeting point needs a gate of
// its own.
//
// What keeps it honest is the direction. The queue is drained by a goroutine
// on its own clock into a one-slot buffer, and the cadence tick does a
// non-blocking receive; the tick never asks the queue anything. So what is
// emitted is a function of the clock, and what it carries is a function of the
// queue, and no code path lets the second reach the first.
//
// This test bounds what else the binary may reach. A publisher has no business
// with reader selection, semantic basins, object reconstruction or peer
// choice: importing any of them would put private *reader* state in the one
// process that also owns a socket.
func TestThePublisherCannotReachReaderSelection(t *testing.T) {
	deps := dependencies(t, ".")
	for _, forbidden := range []string{
		"github.com/Jtensetti/nomad-semantic-basins/basin",
		"github.com/Jtensetti/nomad-local-reconstruction/reconstruct",
		"github.com/Jtensetti/nomad-selection-firewall/firewall",
		"github.com/Jtensetti/nomad-testnet/live/fetchplan",
		"github.com/Jtensetti/nomad-testnet/live/partialfetch",
		"github.com/Jtensetti/nomad-testnet/live/materialize",
		"github.com/Jtensetti/nomad-testnet/live/node",
		"os/exec",
	} {
		if deps[forbidden] {
			t.Errorf("nomad-publish links %s: the process that owns the publication "+
				"queue and a socket must not also reach reader selection", forbidden)
		}
	}
}

// The other direction, checked here rather than only in CI so that a developer
// finds out at `go test`: adding this binary must not have given the
// publication API a network capability. The queue is a purely local object and
// the only way a fragment leaves it is a pull by the scheduler.
func TestThePublicationQueueStillHasNoNetworkCapability(t *testing.T) {
	deps := dependencies(t, "github.com/Jtensetti/nomad-testnet/live/publish")
	for _, forbidden := range []string{
		"net", "net/http", "os/exec",
		"github.com/Jtensetti/nomad-constant-rate-fabric/fabric",
		"github.com/Jtensetti/nomad-testnet/live/uplink",
		"github.com/Jtensetti/nomad-testnet/live/hop",
	} {
		if deps[forbidden] {
			t.Errorf("live/publish reaches %s: a queue that can transmit is a queue "+
				"that can decide when to transmit from what it holds", forbidden)
		}
	}
}

func dependencies(t *testing.T, pkg string) map[string]bool {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	deps := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		deps[strings.TrimSpace(scanner.Text())] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return deps
}
