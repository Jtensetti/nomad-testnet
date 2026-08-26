package node

import (
	"context"
	"errors"
	"sync"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
)

// FairQueue holds relay work with a per-source share instead of one shared
// line.
//
// The relay queue used to be a single bounded FIFO that every peer filled.
// That bounds memory, which is what it was built for, and it does not bound
// *access*: an operator sending faster than the rest takes the whole queue, and
// every other operator's work is dropped at the door until it stops. Admission
// is signed, so this is not a stranger flooding the network -- but a signed
// operator can misbehave, an operator's host can be compromised, and PROD-20
// asks for fair access under exactly that, not only for a memory bound.
//
// So each source gets its own line and its own share of the capacity, and the
// scheduler takes from the lines in turn. A source that floods fills its own
// share, drops its own cells, and takes nothing from anyone else.
//
// What this deliberately does not do is change when anything is emitted. The
// scheduler asks for one cell per tick on a fixed cadence whether the queue is
// empty or overflowing; this only decides *which* cell that is. Relay work is
// scheduled by public replication policy, so which source is served on a given
// tick is public information, and a round robin over a signed operator set
// reveals nothing a packet count does not.
type FairQueue struct {
	mu sync.Mutex
	// capacity is the total across every source, so the memory bound is
	// exactly the bound the old single queue had.
	capacity int
	// perSource is the most any one source may hold. It is derived from the
	// capacity and the size of the signed operator set rather than
	// configured separately: a share that does not add up to the capacity is
	// either wasted memory or an unenforced bound.
	perSource int
	order     []uint16
	lines     map[uint16][]fabric.Cell
	// turn is the round-robin cursor. It advances on every dequeue attempt,
	// including one that finds an empty line, so the order a source is served
	// in is a function of the tick and not of who has work.
	turn    int
	dropped map[uint16]uint64
}

// NewFairQueue builds a queue whose sources are exactly the signed operator
// slots that may send to this node.
//
// The source set is fixed at construction from the topology. Nothing at
// runtime adds a line: a cell from a slot that is not in the set is refused,
// which is the same rule the peer set already follows and the reason a Sybil
// cannot buy itself a share by sending.
func NewFairQueue(capacity int, sources []uint16) (*FairQueue, error) {
	if capacity < 1 {
		return nil, errors.New("queue capacity must be positive")
	}
	if len(sources) == 0 {
		return nil, errors.New("a fair queue needs at least one source")
	}
	perSource := capacity / len(sources)
	if perSource < 1 {
		// More signed operators than queue slots. Giving each a slot would
		// exceed the configured memory bound, and giving some none would be
		// an unfair queue wearing the name, so this is a configuration error
		// rather than something to round away.
		return nil, errors.New("queue capacity is smaller than the operator set, so no " +
			"per-source share exists that respects it")
	}
	queue := &FairQueue{
		capacity:  capacity,
		perSource: perSource,
		order:     make([]uint16, 0, len(sources)),
		lines:     make(map[uint16][]fabric.Cell, len(sources)),
		dropped:   make(map[uint16]uint64, len(sources)),
	}
	seen := make(map[uint16]struct{}, len(sources))
	for _, source := range sources {
		if _, repeated := seen[source]; repeated {
			continue
		}
		seen[source] = struct{}{}
		queue.order = append(queue.order, source)
		queue.lines[source] = nil
	}
	return queue, nil
}

// Enqueue adds one cell to its source's line, reporting whether it was taken.
//
// A full line drops the incoming cell rather than evicting an older one from
// this or any other line. Dropping the newest keeps the decision local to the
// source that overflowed: an eviction policy that reached into another line
// would be the unfairness this type exists to remove, and one that evicted
// this line's oldest would let a flood displace the same source's earlier work
// for no gain.
func (queue *FairQueue) Enqueue(source uint16, cell fabric.Cell) bool {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	line, known := queue.lines[source]
	if !known {
		return false
	}
	if len(line) >= queue.perSource {
		queue.dropped[source]++
		return false
	}
	queue.lines[source] = append(line, cell)
	return true
}

// NextCell serves the lines in a fixed rotation.
//
// The cursor advances once per call whatever it finds, so a source's position
// in the rotation does not depend on how much work anyone has. It then scans
// forward for the first non-empty line, so an idle source costs a turn rather
// than a tick -- the scheduler still gets a cell if any source has one.
func (queue *FairQueue) NextCell(context.Context) (fabric.Cell, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(queue.order) == 0 {
		return fabric.Cell{}, fabric.ErrNoWork
	}
	start := queue.turn % len(queue.order)
	queue.turn = (queue.turn + 1) % len(queue.order)
	for offset := 0; offset < len(queue.order); offset++ {
		source := queue.order[(start+offset)%len(queue.order)]
		line := queue.lines[source]
		if len(line) == 0 {
			continue
		}
		cell := line[0]
		copy(line, line[1:])
		queue.lines[source] = line[:len(line)-1]
		return cell, nil
	}
	return fabric.Cell{}, fabric.ErrNoWork
}

// Len is the number of cells waiting across every line. Like the queue it
// replaces, it is local diagnostic state: nothing on the emission path may
// consult it, because a rate that responds to queue depth is a rate that
// reports it.
func (queue *FairQueue) Len() int {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	total := 0
	for _, line := range queue.lines {
		total += len(line)
	}
	return total
}

// PerSource is the share each source may hold.
func (queue *FairQueue) PerSource() int {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.perSource
}

// Dropped is how many cells each source lost to its own full line. It
// attributes an overflow to whoever caused it, which is what makes a flood
// visible to an operator as somebody else's behaviour rather than as their own
// node misbehaving.
func (queue *FairQueue) Dropped() map[uint16]uint64 {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	out := make(map[uint16]uint64, len(queue.dropped))
	for source, count := range queue.dropped {
		out[source] = count
	}
	return out
}
