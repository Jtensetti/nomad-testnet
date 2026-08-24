// Package deposit connects the publication queue to the airlock across the
// network: a publisher's fixed-cadence uplink emission on one side, an entry
// operator's ingress on the other.
//
// The two halves existed and nothing joined them. The queue held encrypted
// fragments, the uplink could seal work and cover indistinguishably, and the
// airlock could accept and seal a batch -- but no code path took a fragment
// from a queue and turned it into a deposit, so publication had no distributed
// form at all.
package deposit

import (
	"errors"
	"sync"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/publish"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// Drain turns a publication queue into a fixed-cadence uplink stream.
//
// The emission path must not depend on whether there is work. Calling
// Queue.Next on the cadence tick would break that immediately: an empty queue
// costs one directory read, while a non-empty one costs a read, a decrypt, an
// unlink and a directory sync. That difference is publication timing, visible
// as jitter to anyone watching the interface.
//
// So the queue is drained by a separate goroutine into a one-slot buffer, and
// the tick does a non-blocking receive. Both branches then perform the same
// AEAD seal over a full-size payload and touch no disk. What the tick does is
// a function of the clock; what it carries is a function of the queue, and the
// two are decoupled by construction rather than by care.
type Drain struct {
	session *uplink.Session
	ready   chan publish.Fragment
	stop    chan struct{}
	closed  sync.Once

	// counters are for local assertions and tests. They must never reach
	// telemetry: work versus cover is exactly the private fact this design
	// exists to hide.
	mutex sync.Mutex
	work  uint64
	cover uint64
}

// NewDrain starts draining queue into a one-slot buffer. Close stops it.
//
// queue may be nil, which is a publisher that never publishes: the drain then
// emits cover forever, which is the same externally observable behaviour as a
// publisher whose queue happens to be empty.
func NewDrain(session *uplink.Session, queue *publish.Queue) (*Drain, error) {
	if session == nil {
		return nil, errors.New("uplink session is required")
	}
	drain := &Drain{
		session: session,
		ready:   make(chan publish.Fragment, 1),
		stop:    make(chan struct{}),
	}
	if queue != nil {
		go drain.fill(queue)
	}
	return drain, nil
}

// fill keeps the one-slot buffer occupied. Every cost of reading the queue --
// the directory listing, the decrypt, the unlink, the sync -- is paid here,
// off the emission path.
func (drain *Drain) fill(queue *publish.Queue) {
	for {
		select {
		case <-drain.stop:
			return
		default:
		}
		fragment, err := queue.Next()
		if err != nil {
			// ErrNoWork is the ordinary case and not a condition to report:
			// an idle publisher is indistinguishable from a busy one by
			// design, so nothing here may log or count it differently.
			select {
			case <-drain.stop:
				return
			default:
			}
			continue
		}
		select {
		case drain.ready <- fragment:
		case <-drain.stop:
			return
		}
	}
}

// Emit produces this tick's cell. It always produces one.
//
// A caller that skipped a tick because it had no work would announce the
// absence of work, so there is no path here that declines to emit.
func (drain *Drain) Emit(sequence uint64) (fabric.Cell, error) {
	select {
	case fragment := <-drain.ready:
		var payload [uplink.PayloadSize]byte
		copy(payload[:], fragment.Payload[:])
		cell, err := drain.session.SealWork(sequence, payload)
		if err != nil {
			return fabric.Cell{}, err
		}
		drain.count(true)
		return cell, nil
	default:
		cell, err := drain.session.SealCover(sequence)
		if err != nil {
			return fabric.Cell{}, err
		}
		drain.count(false)
		return cell, nil
	}
}

func (drain *Drain) count(isWork bool) {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	if isWork {
		drain.work++
		return
	}
	drain.cover++
}

// Counts reports work and cover emissions. For tests and local assertions
// only; see the note on the counters.
func (drain *Drain) Counts() (work, cover uint64) {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	return drain.work, drain.cover
}

// Close stops the filling goroutine. A fragment already taken from the queue
// and sitting in the buffer is lost, which is the intended direction: the
// queue is durable and the publisher will re-submit, whereas holding work
// across a shutdown to emit it later would be catch-up traffic.
func (drain *Drain) Close() {
	drain.closed.Do(func() { close(drain.stop) })
}
