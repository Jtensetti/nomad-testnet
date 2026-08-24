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
	"time"

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
// DefaultPollInterval is how often the filling goroutine looks for work.
//
// It polls at a fixed rate whether or not it finds any. Retrying immediately
// after an empty queue and pausing after a full one would make the polling
// rate a function of queue depth, which is private; polling at a constant rate
// makes it a function of nothing. It also stops the goroutine spinning on an
// empty queue, which it otherwise does at whatever rate the filesystem can
// list a directory -- enough to starve the emission loop it exists to serve.
const DefaultPollInterval = time.Millisecond

type Drain struct {
	session *uplink.Session
	ready   chan publish.Fragment
	stop    chan struct{}
	poll    time.Duration
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
	return NewDrainWithPoll(session, queue, DefaultPollInterval)
}

// NewDrainWithPoll is NewDrain with an explicit poll interval, for tests that
// need the buffer filled faster than the default.
func NewDrainWithPoll(session *uplink.Session, queue *publish.Queue,
	poll time.Duration) (*Drain, error) {
	if session == nil {
		return nil, errors.New("uplink session is required")
	}
	if poll <= 0 {
		return nil, errors.New("poll interval must be positive")
	}
	drain := &Drain{
		session: session,
		ready:   make(chan publish.Fragment, 1),
		stop:    make(chan struct{}),
		poll:    poll,
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
	ticker := time.NewTicker(drain.poll)
	defer ticker.Stop()
	for {
		select {
		case <-drain.stop:
			return
		case <-ticker.C:
		}
		fragment, err := queue.Next()
		if err != nil {
			// ErrNoWork is the ordinary case and not a condition to report:
			// an idle publisher is indistinguishable from a busy one by
			// design, so nothing here may log or count it differently. The
			// next attempt waits for the same tick either way.
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
