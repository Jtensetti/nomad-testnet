package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// PROD-28 asks that backup and incident response are exercised, not described.
// A runbook nobody has run is a document about what someone hopes would
// happen, so these destroy each piece of a node's durable state in turn and
// check what the code actually does.
//
// A node's durable state is four things: the immutable raw cache, the hop
// sequence reservation, the topology watermark, and its operator secrets. They
// recover differently and two of them recover *unsafely* if an operator treats
// them as ordinary files to restore from backup. That asymmetry is the point
// of the exercise and it is what deploy/RECOVERY.md is written from.

// destroyedState is one way an operator can lose or mishandle node state.
type destroyedState struct {
	name string
	// break is applied between the first run and the second.
	breakIt func(t *testing.T, scratch string, first Stats)
	// expectStart says whether the node should come back at all.
	expectStart bool
	why         string
}

func TestANodeRecoversOrRefusesForEachPieceOfLostState(t *testing.T) {
	if testing.Short() {
		t.Skip("restarts nodes against a cadence")
	}
	cases := []destroyedState{
		{
			name: "the raw cache is lost",
			breakIt: func(t *testing.T, scratch string, _ Stats) {
				if err := os.RemoveAll(filepath.Join(scratch, "raw")); err != nil {
					t.Fatal(err)
				}
			},
			expectStart: true,
			why: "the cache holds public replicated content and is rebuilt from peers; " +
				"losing it costs availability of what it held, never correctness",
		},
		{
			name: "the hop sequence file is lost",
			breakIt: func(t *testing.T, scratch string, _ Stats) {
				if err := os.Remove(filepath.Join(scratch, "sequence")); err != nil {
					t.Fatal(err)
				}
			},
			expectStart: true,
			why: "a lost reservation restarts from zero, which is the dangerous case: " +
				"the node reuses sequence numbers its peers have already seen",
		},
		{
			name: "the topology watermark is lost",
			breakIt: func(t *testing.T, scratch string, _ Stats) {
				_ = os.Remove(filepath.Join(scratch, "topology-watermark.json"))
			},
			expectStart: true,
			why: "the watermark only bounds rollback; losing it loses that bound but " +
				"does not stop the node running the topology it has",
		},
		{
			name: "the whole state directory is lost",
			breakIt: func(t *testing.T, scratch string, _ Stats) {
				for _, name := range []string{"sequence", "topology-watermark.json"} {
					_ = os.Remove(filepath.Join(scratch, name))
				}
			},
			expectStart: true,
			why:         "the combination of the two above",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, identities, endpoints := nodeTestTopologyWithCadence(
				t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
			scratch := t.TempDir()

			first := runOneNodeLifetime(t, network, identities, endpoints, scratch)
			if first.Sent == 0 {
				t.Fatalf("the node emitted nothing before the failure; the exercise is vacuous")
			}
			testCase.breakIt(t, scratch, first)

			second, err := restartAfterFailure(t, network, identities, endpoints, scratch)
			if testCase.expectStart && err != nil {
				t.Fatalf("the node did not come back after %s: %v", testCase.name, err)
			}
			if !testCase.expectStart {
				if err == nil {
					t.Fatalf("the node came back after %s, which it must refuse", testCase.name)
				}
				t.Logf("refused, as required: %v", err)
				return
			}
			if second.Sent == 0 {
				t.Errorf("the node came back but emitted nothing after %s", testCase.name)
			}
			t.Logf("%s: recovered, %d cells before and %d after. %s",
				testCase.name, first.Sent, second.Sent, testCase.why)
		})
	}
}

// The finding this exercise exists to produce. A node whose hop sequence state
// goes backwards -- lost, or restored from a backup taken earlier -- emits
// perfectly well-formed cells that every peer silently discards, because they
// replay sequence numbers the peer has already seen. The sender's own health
// file says it is emitting: `sent` climbs, `send_dropped` stays zero. Nothing
// on the sending side knows.
//
// The signal exists, but only on the receiver, as `replay_rejected` climbing
// against one sender. deploy/RECOVERY.md is written around that, because an
// operator reading only their own node's health cannot see this at all.
func TestASequenceRollbackIsInvisibleToTheSenderAndFatalToItsTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("runs two nodes against a cadence")
	}
	// A slower cadence with the widest lateness the topology permits (ten
	// intervals), because this exercise is about the replay window and not
	// about timing. Three nodes and a full test suite on one container make a
	// 200 ms budget a coin flip, and a receiver that stops on a host stall
	// reports as "the rollback was accepted" -- which is how the first
	// version of this test failed.
	const rollbackIntervalMillis = 50
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, rollbackIntervalMillis, rollbackIntervalMillis*10, singlePeerPlan)

	// The receiver: operator 1, which accepts cells from operator 0.
	receiverScratch := t.TempDir()
	receiver := buildPeerNode(t, network, identities, endpoints, receiverScratch, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var group sync.WaitGroup
	var receiverError error
	group.Add(1)
	go func() { defer group.Done(); receiverError = receiver.Run(ctx) }()

	senderScratch := t.TempDir()
	sequencePath := filepath.Join(senderScratch, "sequence")

	// First lifetime: the receiver accepts what the sender emits.
	sender := buildPeerNode(t, network, identities, endpoints, senderScratch, 0)
	runFor(t, sender, 900*time.Millisecond)
	backup, err := os.ReadFile(sequencePath)
	if err != nil {
		t.Fatal(err)
	}
	afterFirst := receiver.Snapshot()
	if afterFirst.Received == 0 {
		t.Fatalf("the receiver saw nothing in the first lifetime (%+v); vacuous", afterFirst)
	}
	// Without this the exercise passes for the wrong reason. A first version
	// keyed the two ends differently, so every cell died at authentication and
	// never reached the replay window at all -- and the test still reported
	// that the receiver had "accepted" the rollback.
	if afterFirst.AuthRejected != 0 {
		t.Fatalf("the two nodes do not share a pairwise key (%d cells failed "+
			"authentication): nothing below reaches the replay window",
			afterFirst.AuthRejected)
	}

	// Second lifetime, so the sender is well past the backup's reservation.
	second := buildPeerNode(t, network, identities, endpoints, senderScratch, 0)
	runFor(t, second, 900*time.Millisecond)
	afterSecond := receiver.Snapshot()

	// Now the mistake: restore the sequence file from the earlier backup, the
	// way an operator restores any other file.
	if err := os.WriteFile(sequencePath, backup, 0o600); err != nil {
		t.Fatal(err)
	}
	rolledBack := buildPeerNode(t, network, identities, endpoints, senderScratch, 0)
	senderStats := runFor(t, rolledBack, 900*time.Millisecond)
	afterRollback := receiver.Snapshot()
	cancel()
	group.Wait()

	accepted := afterRollback.Received - afterSecond.Received
	replayed := afterRollback.ReplayRejected - afterSecond.ReplayRejected

	// A receiver that stopped early would report as "the rollback was
	// accepted", which is how an earlier version of this test failed on a
	// loaded host. Say what happened instead of inferring a finding from it.
	if receiverError != nil {
		t.Skipf("the receiver could not run this exercise on this host: %v", receiverError)
	}
	if senderStats.Sent == 0 {
		t.Fatalf("the rolled-back sender emitted nothing; the finding cannot be shown")
	}
	// The sender is unaware.
	if senderStats.SendDropped != 0 {
		t.Errorf("the rolled-back sender counted %d local drops; it is supposed to be "+
			"unaware, which is what makes this dangerous", senderStats.SendDropped)
	}
	// The receiver refuses. Fail-closed is right; silence on the sender is not.
	if replayed == 0 {
		t.Errorf("the receiver accepted a rolled-back sender's replays without counting "+
			"any: %d received, %d replay-rejected", accepted, replayed)
	}
	t.Logf("MEASURED: after restoring an older hop sequence file, the sender emitted %d "+
		"cells and reported %d local drops -- it cannot tell. The receiver counted %d "+
		"replays rejected over the same window. The only signal is on the receiving "+
		"side, which is why RECOVERY.md tells operators to watch a peer's "+
		"replay_rejected rather than their own health file.",
		senderStats.Sent, senderStats.SendDropped, replayed)
}

// A topology restored from a backup taken before a rotation is the other
// unsafe restore: it is perfectly signed and inside its own validity window,
// so nothing about verification refuses it, and it puts a removed operator or
// a rotated-away key back. The watermark is what refuses it, and this checks
// that the refusal survives a restart rather than living only in memory.
func TestARolledBackTopologyIsRefusedAcrossARestart(t *testing.T) {
	network, _, _ := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	older, _, _ := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)

	scratch := t.TempDir()
	watermark := filepath.Join(scratch, "topology-watermark.json")

	current := network
	current.Document.Epoch = 9
	previous := older
	previous.Document.Epoch = 8

	if err := topology.AcceptMonotonic(watermark, current); err != nil {
		t.Fatalf("accepting the current topology failed: %v", err)
	}
	// A restart on the same topology is ordinary.
	if err := topology.AcceptMonotonic(watermark, current); err != nil {
		t.Fatalf("restarting on the same topology was refused: %v", err)
	}
	// The restore-from-backup mistake.
	err := topology.AcceptMonotonic(watermark, previous)
	if err == nil {
		t.Fatal("an older topology was accepted after a newer one; a restored backup " +
			"would reinstate a removed operator or a rotated-away key")
	}
	if !errors.Is(err, topology.ErrTopologyRollback) {
		t.Errorf("the refusal was %v, which does not name a rollback", err)
	}

	// And equivocation at the same epoch fails closed rather than choosing.
	equivocal := current
	equivocal.Digest[0] ^= 0x01
	if err := topology.AcceptMonotonic(watermark, equivocal); err == nil {
		t.Error("two different topologies at the same epoch were both accepted")
	} else if !errors.Is(err, topology.ErrTopologyEquivocation) {
		t.Errorf("the refusal was %v, which does not name equivocation", err)
	}
}

// linkKey is the pairwise key for one direction of one link. Both ends have to
// derive the same value or every cell fails authentication rather than
// reaching the replay window -- which is exactly what the first version of the
// rollback exercise did, silently, while appearing to prove its point. The
// node test helpers elsewhere in this package key inbound and outbound
// differently on purpose, because they drive a node from a synthetic peer
// rather than from another node.
func linkKey(from, to uint16) [32]byte {
	return [32]byte{byte(from + 1), byte(to + 1), 0xA7}
}

// buildPeerNode builds the node for a chosen operator index, with keys that
// agree with every other node built the same way.
func buildPeerNode(t *testing.T, network topology.Verified,
	identities map[string]ed25519.PrivateKey, endpoints []string,
	scratch string, index int) *Node {
	t.Helper()
	self := network.Document.Operators[index]
	cache, err := rawcache.Open(filepath.Join(scratch, "raw"), 64)
	if err != nil {
		t.Fatal(err)
	}
	outbound := map[uint16][32]byte{}
	for _, peer := range self.PeerPlan {
		outbound[peer] = linkKey(self.Index, peer)
	}
	inbound := map[uint16][32]byte{}
	for _, peer := range network.IncomingPeers(self.Index) {
		inbound[peer.Index] = linkKey(peer.Index, self.Index)
	}
	worker, err := New(Config{
		Topology: network,
		Secrets: topology.VerifiedSecrets{
			Operator: self, Identity: identities[self.ID],
			OutboundKeys: outbound, InboundKeys: inbound,
		},
		ListenAddress: endpoints[index], Cache: cache,
		SequencePath: filepath.Join(scratch, "sequence"),
		HealthPath:   filepath.Join(scratch, "health.json"),
		CacheSweep:   time.Hour,
	})
	if err != nil {
		t.Fatalf("build node %d: %v", index, err)
	}
	return worker
}

func runOneNodeLifetime(t *testing.T, network topology.Verified,
	identities map[string]ed25519.PrivateKey, endpoints []string, scratch string) Stats {
	t.Helper()
	worker := buildLimitedNode(t, network, identities, endpoints, scratch, 64)
	return runFor(t, worker, 400*time.Millisecond)
}

// restartAfterFailure rebuilds a node on the same state directory, reporting
// whether it could start at all.
func restartAfterFailure(t *testing.T, network topology.Verified,
	identities map[string]ed25519.PrivateKey, endpoints []string, scratch string) (Stats, error) {
	t.Helper()
	self := network.Document.Operators[0]
	cache, err := rawcache.Open(filepath.Join(scratch, "raw"), 64)
	if err != nil {
		return Stats{}, err
	}
	outbound := map[uint16][32]byte{}
	for _, peer := range self.PeerPlan {
		outbound[peer] = [32]byte{byte(peer + 1)}
	}
	inbound := map[uint16][32]byte{}
	for _, peer := range network.IncomingPeers(self.Index) {
		inbound[peer.Index] = [32]byte{byte(peer.Index + 11)}
	}
	worker, err := New(Config{
		Topology: network,
		Secrets: topology.VerifiedSecrets{
			Operator: self, Identity: identities[self.ID],
			OutboundKeys: outbound, InboundKeys: inbound,
		},
		ListenAddress: endpoints[0], Cache: cache,
		SequencePath: filepath.Join(scratch, "sequence"),
		HealthPath:   filepath.Join(scratch, "health.json"),
		CacheSweep:   time.Hour,
	})
	if err != nil {
		return Stats{}, err
	}
	return runFor(t, worker, 400*time.Millisecond), nil
}

func runFor(t *testing.T, worker *Node, duration time.Duration) Stats {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(duration, cancel)
	defer stop.Stop()
	if err := worker.Run(ctx); err != nil && !errors.Is(err, fabric.ErrDeadlineMissed) {
		t.Logf("node stopped: %v", err)
	}
	return worker.Snapshot()
}
