package node

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/bundle"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// Public cache replication is the sweep that re-offers complete streams held in
// this node's cache to its relay queue. It is how an object reaches operators
// that were not on the path when it was published, and PROD-18 names it.
//
// Nothing exercised it. Every node test in this package sets CacheSweep to an
// hour so the sweep never fires, and enqueueCached measured at 0.0% coverage --
// not "the campaign does not reach it" but no test reaching it at all. What
// follows is the first coverage the replication path has had.

func replicationNode(t *testing.T, cacheCapacity int) (*Node, *rawcache.Store) {
	t.Helper()
	network, identities, endpoints := nodeTestTopology(t)
	cache, err := rawcache.Open(filepath.Join(t.TempDir(), "raw"), cacheCapacity)
	if err != nil {
		t.Fatal(err)
	}
	self := network.Document.Operators[1]
	worker, err := New(Config{
		Topology: network,
		Secrets: topology.VerifiedSecrets{
			Operator: self, Identity: identities[self.ID],
			OutboundKeys: map[uint16][32]byte{2: {2}},
			InboundKeys:  map[uint16][32]byte{0: {1}},
		},
		ListenAddress: endpoints[1], Cache: cache,
		SequencePath: filepath.Join(t.TempDir(), "sequence"),
		HealthPath:   filepath.Join(t.TempDir(), "health.json"),
		CacheSweep:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.conn.Close() })
	return worker, cache
}

// streamPayloads builds a stream's payloads and its identifier.
//
// A stream ID is the hash of its own payloads -- rawcache.Load recomputes it
// and refuses the stream if it does not match, which is what stops a peer
// filling the cache with content under an identifier of its choosing. So a
// fixture cannot pick an identifier; it derives one, exactly as the receive
// path does.
func streamPayloads(t *testing.T, tag byte, count int) ([][hop.CiphertextSize]byte, hop.StreamID) {
	t.Helper()
	payloads := make([][hop.CiphertextSize]byte, count)
	for ordinal := range payloads {
		payloads[ordinal][0] = tag
		payloads[ordinal][1] = byte(ordinal)
	}
	stream, err := hop.StreamFor(payloads)
	if err != nil {
		t.Fatal(err)
	}
	return payloads, stream
}

// storeStream writes a complete stream into the cache the way receive does:
// through Put, with metadata the hop package validated.
func storeStream(t *testing.T, cache *rawcache.Store, tag byte, count int) hop.StreamID {
	t.Helper()
	payloads, stream := streamPayloads(t, tag, count)
	for ordinal, payload := range payloads {
		metadata, err := hop.WorkMetadata(stream, uint16(ordinal), uint16(count))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cache.Put(metadata, payload); err != nil {
			t.Fatal(err)
		}
	}
	return stream
}

func drainQueue(t *testing.T, worker *Node) []hop.Metadata {
	t.Helper()
	seen := make([]hop.Metadata, 0, worker.queue.Len())
	for worker.queue.Len() > 0 {
		cell, err := worker.queue.NextCell(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := hop.LocalMetadata(cell)
		if err != nil {
			t.Fatalf("the sweep enqueued a cell with no readable local header: %v", err)
		}
		seen = append(seen, metadata)
	}
	return seen
}

// The property the criterion asks for: a complete stream this node holds is
// offered for relay, in full, as work.
func TestTheSweepReplicatesACompleteStream(t *testing.T) {
	worker, cache := replicationNode(t, 64)
	const payloads = 4
	stream := storeStream(t, cache, 7, payloads)

	if worker.queue.Len() != 0 {
		t.Fatalf("the queue was not empty before the sweep: %d", worker.queue.Len())
	}
	if err := worker.enqueueCached(); err != nil {
		t.Fatalf("the replication sweep failed: %v", err)
	}
	seen := drainQueue(t, worker)
	if len(seen) != payloads {
		t.Fatalf("the sweep offered %d cells for a %d-cell stream", len(seen), payloads)
	}
	ordinals := make(map[uint16]bool, payloads)
	for _, metadata := range seen {
		if !hop.IsWork(metadata) {
			t.Fatalf("the sweep offered a cached work cell as cover: %+v", metadata)
		}
		if metadata.Stream != stream {
			t.Fatalf("the sweep offered a cell from stream %x, not %x", metadata.Stream, stream)
		}
		if metadata.BatchSize != payloads {
			t.Fatalf("the sweep offered batch size %d, not %d", metadata.BatchSize, payloads)
		}
		ordinals[metadata.Ordinal] = true
	}
	if len(ordinals) != payloads {
		t.Fatalf("the sweep offered %d distinct ordinals of %d", len(ordinals), payloads)
	}
}

// An incomplete stream must not be relayed. Relaying part of a stream spends
// this node's fixed relay share on cells no one can reconstruct from, and the
// partial set is exactly what a node holds while a publication is still
// arriving.
func TestTheSweepDoesNotReplicateAnIncompleteStream(t *testing.T) {
	worker, cache := replicationNode(t, 64)
	payloads, stream := streamPayloads(t, 9, 4)
	for ordinal := 0; ordinal < len(payloads)-1; ordinal++ {
		metadata, err := hop.WorkMetadata(stream, uint16(ordinal), uint16(len(payloads)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cache.Put(metadata, payloads[ordinal]); err != nil {
			t.Fatal(err)
		}
	}
	if err := worker.enqueueCached(); err != nil {
		t.Fatal(err)
	}
	if worker.queue.Len() != 0 {
		t.Fatalf("the sweep offered %d cells from an incomplete stream", worker.queue.Len())
	}

	// What actually enforces that, which is not the sweep's own guard.
	//
	// Deleting `if !complete { continue }` from enqueueCached leaves this test
	// passing, measured. The reason is Load's contract: on an incomplete
	// stream it returns no payloads at all, so the sweep's inner loop has
	// nothing to iterate and the guard is defence in depth rather than the
	// mechanism. That contract is what a future change could break without
	// touching the sweep, so it is asserted here rather than assumed -- a Load
	// that returned the fragments it did find would put partial streams on the
	// wire through a sweep nobody had edited.
	partial, complete, err := cache.Load(stream)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("the cache called a stream missing a cell complete")
	}
	if len(partial) != 0 {
		t.Fatalf("the cache returned %d payloads for an incomplete stream; the sweep "+
			"would relay them", len(partial))
	}

	// Vacuity: the same stream completed must be offered, or this test would
	// pass against a sweep that replicates nothing at all.
	last := uint16(len(payloads) - 1)
	metadata, err := hop.WorkMetadata(stream, last, uint16(len(payloads)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Put(metadata, payloads[last]); err != nil {
		t.Fatal(err)
	}
	if err := worker.enqueueCached(); err != nil {
		t.Fatal(err)
	}
	if worker.queue.Len() != 4 {
		t.Fatalf("completing the stream offered %d cells, not 4", worker.queue.Len())
	}
}

// What the sweep offers, and the order it offers it in, must be a function of
// public state alone. Here that is the stream identifiers, sorted -- not the
// order the streams arrived in, which is a fact about the network at one node,
// and not anything about what has been read.
func TestTheSweepsOrderIsAFunctionOfTheStreamIdentifiersAlone(t *testing.T) {
	first, cacheOne := replicationNode(t, 64)
	second, cacheTwo := replicationNode(t, 64)

	tags := []byte{3, 1, 2}
	for _, tag := range tags {
		storeStream(t, cacheOne, tag, 2)
	}
	// The same streams, arriving in the opposite order.
	for index := len(tags) - 1; index >= 0; index-- {
		storeStream(t, cacheTwo, tags[index], 2)
	}

	if err := first.enqueueCached(); err != nil {
		t.Fatal(err)
	}
	if err := second.enqueueCached(); err != nil {
		t.Fatal(err)
	}
	one, two := drainQueue(t, first), drainQueue(t, second)
	if len(one) != len(tags)*2 {
		t.Fatalf("the sweep offered %d cells for %d two-cell streams", len(one), len(tags))
	}
	if len(one) != len(two) {
		t.Fatalf("arrival order changed how much was offered: %d against %d", len(one), len(two))
	}
	for index := range one {
		if one[index] != two[index] {
			t.Fatalf("arrival order changed what was offered at %d: %+v against %+v",
				index, one[index], two[index])
		}
	}
	// And it is sorted, which is the public rule rather than an accident of
	// two runs agreeing.
	for index := 1; index < len(one); index++ {
		if bytes.Compare(one[index].Stream[:], one[index-1].Stream[:]) < 0 {
			t.Fatalf("the sweep offered stream %x after %x",
				one[index].Stream, one[index-1].Stream)
		}
	}
}

// A full queue must stop the sweep without losing the node. Relay capacity is
// this operator's fixed share; running out of it is ordinary, and the sweep's
// job is to stop offering rather than to fail.
func TestAFullQueueStopsTheSweepWithoutFailingTheNode(t *testing.T) {
	worker, cache := replicationNode(t, 64)
	capacity := worker.queue.PerSource()
	// Enough streams to overrun this node's own share several times over.
	for index := 0; index < capacity && index < 200; index++ {
		storeStream(t, cache, byte(index), 2)
	}
	if err := worker.enqueueCached(); err != nil {
		t.Fatalf("a full queue failed the sweep rather than stopping it: %v", err)
	}
	if worker.queue.Len() == 0 {
		t.Fatal("the sweep offered nothing at all, so it did not fill anything")
	}
	if dropped := worker.stats.queueDropped.Load(); dropped == 0 {
		t.Fatal("the sweep filled the queue and counted no refusal")
	}
	// Draining and sweeping again must make progress rather than deadlock.
	before := worker.queue.Len()
	drainQueue(t, worker)
	if err := worker.enqueueCached(); err != nil {
		t.Fatal(err)
	}
	if worker.queue.Len() == 0 {
		t.Fatalf("after draining %d cells the sweep offered nothing", before)
	}
}

// enqueueCached discards the error from WorkMetadata where seed, twelve lines
// above it, checks the same call. Today nothing reaches it: rawcache's
// readBatchSize refuses a stored batch size outside [2, MaximumBatch], so Load
// can only return a payload count the hop package will accept.
//
// That makes this a cross-package invariant with no local statement of it. If
// the bound in rawcache were ever relaxed, enqueueCached would build a zero
// Metadata -- which is a valid *cover* header -- and relay a work payload
// labelled as cover, which every receiver drops. Silent loss in the
// replication path, from a discarded error.
//
// So the bound is asserted here, in the package that depends on it, rather
// than left as a property of somewhere else that happens to hold.
func TestTheCacheCannotHandTheSweepACountTheHopPackageRefuses(t *testing.T) {
	for _, count := range []int{0, 1, hop.MaximumBatch + 1, 1 << 16} {
		if _, err := hop.WorkMetadata(hop.StreamID{1}, 0, uint16(count)); err == nil {
			t.Fatalf("hop accepts a batch size of %d, so the sweep's coordinates are "+
				"not bounded by it", count)
		}
	}
	root := t.TempDir()
	cache, err := rawcache.Open(filepath.Join(root, "raw"), 8)
	if err != nil {
		t.Fatal(err)
	}
	stream := storeStream(t, cache, 5, 2)

	// Rewrite the stored batch size to one the hop package refuses, which is
	// what a corrupted or tampered cache directory looks like.
	sizePath := filepath.Join(root, "raw", hex.EncodeToString(stream[:]), "batch-size")
	if err := os.WriteFile(sizePath, []byte{0, 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.Load(stream); err == nil {
		t.Fatal("the cache returned a stream whose batch size the hop package refuses; " +
			"the sweep would relay its payloads as cover and every receiver would drop them")
	}
}

// Seeding is the other half of replication and had no coverage either: an
// operator joining a running network starts with --seed, and node.seed puts
// the bundle's payloads into both the cache and this node's relay queue so it
// begins contributing immediately rather than waiting to be sent what it
// already has.
//
// It measured 0.0% alongside enqueueCached. The branch below -- a bundle
// larger than this operator's own relay share -- is the one that matters: it
// is a startup failure by design, because a node that silently dropped half
// its seed would look healthy while serving an object it cannot complete.
func TestSeedingFillsTheCacheAndTheRelayQueue(t *testing.T) {
	network, identities, endpoints := nodeTestTopology(t)
	payloads, stream := streamPayloads(t, 11, 4)
	cache, err := rawcache.Open(filepath.Join(t.TempDir(), "raw"), 8)
	if err != nil {
		t.Fatal(err)
	}
	self := network.Document.Operators[1]
	worker, err := New(Config{
		Topology: network,
		Secrets: topology.VerifiedSecrets{
			Operator: self, Identity: identities[self.ID],
			OutboundKeys: map[uint16][32]byte{2: {2}},
			InboundKeys:  map[uint16][32]byte{0: {1}},
		},
		ListenAddress: endpoints[1], Cache: cache,
		SequencePath: filepath.Join(t.TempDir(), "sequence"),
		HealthPath:   filepath.Join(t.TempDir(), "health.json"),
		CacheSweep:   time.Hour,
		Seed:         &bundle.Verified{Stream: stream, Payloads: payloads},
	})
	if err != nil {
		t.Fatalf("a node could not start from a seed bundle: %v", err)
	}
	t.Cleanup(func() { _ = worker.conn.Close() })

	if worker.queue.Len() != len(payloads) {
		t.Fatalf("seeding offered %d of %d cells for relay", worker.queue.Len(), len(payloads))
	}
	stored, complete, err := cache.Load(stream)
	if err != nil {
		t.Fatal(err)
	}
	if !complete || len(stored) != len(payloads) {
		t.Fatalf("seeding left the cache holding %d payloads, complete=%v", len(stored), complete)
	}
	for _, metadata := range drainQueue(t, worker) {
		if !hop.IsWork(metadata) || metadata.Stream != stream {
			t.Fatalf("seeding offered a cell that is not this stream's work: %+v", metadata)
		}
	}
}

func TestASeedLargerThanThisOperatorsShareFailsStartup(t *testing.T) {
	network, identities, endpoints := nodeTestTopology(t)
	cache, err := rawcache.Open(filepath.Join(t.TempDir(), "raw"), 8)
	if err != nil {
		t.Fatal(err)
	}
	self := network.Document.Operators[1]
	build := func(count int) error {
		payloads, stream := streamPayloads(t, 12, count)
		built, err := New(Config{
			Topology: network,
			Secrets: topology.VerifiedSecrets{
				Operator: self, Identity: identities[self.ID],
				OutboundKeys: map[uint16][32]byte{2: {2}},
				InboundKeys:  map[uint16][32]byte{0: {1}},
			},
			ListenAddress: endpoints[1], Cache: cache,
			SequencePath: filepath.Join(t.TempDir(), "sequence"),
			HealthPath:   filepath.Join(t.TempDir(), "health.json"),
			CacheSweep:   time.Hour,
			Seed:         &bundle.Verified{Stream: stream, Payloads: payloads},
		})
		// The socket is bound before the seed is applied, so a node that did
		// start holds the endpoint the next attempt needs.
		if built != nil {
			_ = built.conn.Close()
		}
		return err
	}
	// Vacuity: a seed inside the share must start, or the refusal below would
	// be about something else entirely.
	if err := build(4); err != nil {
		t.Fatalf("a seed well inside this operator's share was refused: %v", err)
	}
	err = build(hop.MaximumBatch)
	if err == nil {
		t.Fatal("a seed larger than this operator's relay share started anyway, so it " +
			"dropped cells while reporting a healthy node")
	}
	if !strings.Contains(err.Error(), "relay share") {
		t.Fatalf("the refusal does not say what was exceeded: %v", err)
	}
}
