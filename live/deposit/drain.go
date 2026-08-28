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
	"fmt"
	"sync"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/airlock"
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

// ErrSequenceReused refuses a sequence this drain has already sealed under.
//
// The sequence is the AEAD nonce (live/uplink/sequence.go). Sealing twice
// under one session key and one sequence encrypts two plaintexts under one
// key and nonce, which hands an observer their XOR and, with GCM's polynomial
// MAC, the authentication key. Nothing in Session.seal can catch it, because
// a session holds no sequence state by design -- the caller owns it. So the
// caller that has the state checks it, and fails closed.
//
// This is not hypothetical bookkeeping. The retry design this drain was asked
// to implement -- seal the same fragment again for a refused deposit -- is
// exactly this call, and it was described in DEC-020 only as something the
// airlock refuses as a conflict. The airlock refusing it second is no comfort
// if the nonce was already reused first.
var ErrSequenceReused = errors.New("uplink sequence reused")

type Drain struct {
	session *uplink.Session
	// schedule is the public deposit window policy, from the signed epoch
	// descriptor. It is the only reason this type knows what time it is, and
	// it carries nothing private: every publisher and every operator derives
	// the same boundaries from the same signed bytes.
	schedule airlock.Schedule
	ready    chan publish.Fragment
	stop     chan struct{}
	poll     time.Duration
	closed   sync.Once

	// counters are for local assertions and tests. They must never reach
	// telemetry: work versus cover is exactly the private fact this design
	// exists to hide, and deferred is worse -- it counts ticks on which
	// there was work.
	mutex sync.Mutex
	// now is the clock, guarded because tests move it across the deposit
	// cutoff while the filling goroutine is running. Production reads the
	// wall clock; nothing here depends on anything but it and the schedule.
	now          func() time.Time
	work         uint64
	cover        uint64
	deferred     uint64
	lastSequence uint64
}

// NewDrain starts draining queue into a one-slot buffer. Close stops it.
//
// queue may be nil, which is a publisher that never publishes: the drain then
// emits cover forever, which is the same externally observable behaviour as a
// publisher whose queue happens to be empty.
//
// schedule is required, and there is no permissive default. A drain without
// one would have to decide what an unknown deposit window means, and every
// answer is wrong: treating it as open destroys work at the cutoff, and
// treating it as closed silently publishes nothing at all.
func NewDrain(session *uplink.Session, queue *publish.Queue,
	schedule airlock.Schedule) (*Drain, error) {
	return NewDrainWithPoll(session, queue, schedule, DefaultPollInterval)
}

// NewDrainWithPoll is NewDrain with an explicit poll interval, for tests that
// need the buffer filled faster than the default.
func NewDrainWithPoll(session *uplink.Session, queue *publish.Queue,
	schedule airlock.Schedule, poll time.Duration) (*Drain, error) {
	if session == nil {
		return nil, errors.New("uplink session is required")
	}
	if err := schedule.Validate(); err != nil {
		return nil, fmt.Errorf("deposit window: %w", err)
	}
	if poll <= 0 {
		return nil, errors.New("poll interval must be positive")
	}
	drain := &Drain{
		session:  session,
		schedule: schedule,
		ready:    make(chan publish.Fragment, 1),
		stop:     make(chan struct{}),
		poll:     poll,
		now:      func() time.Time { return time.Now().UTC() },
	}
	if queue != nil {
		go drain.fill(queue)
	}
	return drain, nil
}

// depositWindowOpen reports whether a deposit made now would be inside the
// open part of its epoch.
//
// It fails closed. A schedule that cannot name an epoch for this instant --
// before genesis, past the representable range, invalid -- is not an excuse
// to emit work into a window that may already have shut; it is a reason to
// leave the work on disk. Failing closed here costs a deferred fragment.
// Failing open costs the fragment outright.
// clock reads the current instant under the mutex, so the filling goroutine
// and the emission path never race a test moving time across the cutoff.
func (drain *Drain) clock() time.Time {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	if drain.now == nil {
		return time.Now().UTC()
	}
	return drain.now()
}

func (drain *Drain) depositWindowOpen(now time.Time) bool {
	epoch, err := drain.schedule.EpochAt(now)
	if err != nil {
		return false
	}
	opens, closes, err := drain.schedule.DepositWindow(epoch)
	if err != nil {
		return false
	}
	return !now.Before(opens) && now.Before(closes)
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
		// The window is public policy, so consulting it is not a private
		// input to anything. What it prevents is: Queue.Next unlinks the
		// fragment as it hands it out, so a fragment taken while the window
		// is shut is one the airlock will refuse and nothing holds any more.
		// Measured across real processes, that was 38-43% of a publisher's
		// work at a three-second period, and 25% of every period at the
		// default one-minute schedule -- destroyed silently, with neither
		// side reporting it (DEC-020).
		//
		// Leaving it on disk costs nothing. The emission cadence is not
		// involved: this goroutine is not the one that emits, and the tick
		// keeps producing a cell either way.
		if !drain.depositWindowOpen(drain.clock()) {
			continue
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
//
// Outside the open deposit window it emits cover and leaves any buffered
// fragment where it is. That is the one thing separating this from the retry
// mechanism DEC-020 asked for and this rejects: a cell held back has never
// been on the wire, so nothing has to be sent twice, and the sequence -- eight
// cleartext bytes at the head of every cell -- never repeats. A publisher that
// retransmitted a refused cell verbatim would show the entry operator a
// sequence it had already seen, an epoch late. Cover is never retransmitted,
// so that repeat would say "this publisher had work", to precisely the party
// this construction exists to blind.
func (drain *Drain) Emit(sequence uint64) (fabric.Cell, error) {
	if err := drain.reserve(sequence); err != nil {
		return fabric.Cell{}, err
	}
	open := drain.depositWindowOpen(drain.clock())
	if open {
		select {
		case fragment := <-drain.ready:
			var payload [uplink.PayloadSize]byte
			copy(payload[:], fragment.Payload[:])
			cell, err := drain.session.SealWork(sequence, payload)
			if err != nil {
				return fabric.Cell{}, err
			}
			drain.count(emissionWork)
			return cell, nil
		default:
		}
	}
	cell, err := drain.session.SealCover(sequence)
	if err != nil {
		return fabric.Cell{}, err
	}
	kind := emissionCover
	// Only the shut branch can defer. Inside an open window an empty buffer
	// that the filling goroutine refills a microsecond later is an idle tick,
	// not a held fragment, and counting it as deferred would report work that
	// was never withheld.
	if !open && len(drain.ready) > 0 {
		kind = emissionDeferred
	}
	drain.count(kind)
	return cell, nil
}

// reserve refuses a sequence that is not strictly beyond every sequence this
// drain has sealed under. See ErrSequenceReused.
func (drain *Drain) reserve(sequence uint64) error {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	if sequence == 0 {
		return errors.New("uplink sequence must be non-zero")
	}
	if drain.lastSequence != 0 && sequence <= drain.lastSequence {
		return fmt.Errorf("%w: %d does not follow %d", ErrSequenceReused,
			sequence, drain.lastSequence)
	}
	drain.lastSequence = sequence
	return nil
}

type emissionKind int

const (
	emissionWork emissionKind = iota
	emissionCover
	emissionDeferred
)

func (drain *Drain) count(kind emissionKind) {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	switch kind {
	case emissionWork:
		drain.work++
	case emissionDeferred:
		drain.deferred++
		drain.cover++
	default:
		drain.cover++
	}
}

// Counts reports work and cover emissions. For tests and local assertions
// only; see the note on the counters.
func (drain *Drain) Counts() (work, cover uint64) {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	return drain.work, drain.cover
}

// Deferred reports cover emissions made while a fragment was buffered and the
// deposit window was shut. It is the count of work this drain declined to
// destroy, and it is a subset of the cover count, not a third category on the
// wire. Local assertions and tests only -- it counts ticks on which there was
// work, which is the private fact itself.
func (drain *Drain) Deferred() uint64 {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	return drain.deferred
}

// Close stops the filling goroutine. At most one fragment -- whatever is in
// the one-slot buffer -- is lost, and it is gone for good: Queue.Next unlinks
// as it hands out, and nothing puts a fragment back. Holding it across a
// shutdown to emit later would be catch-up traffic, which is worse than losing
// it, so this is the intended direction rather than an oversight.
//
// It is a bounded loss now. Before the window gate above, a shutdown was the
// small case: a quarter of every period's work was being taken from the queue
// into cells the airlock would refuse.
func (drain *Drain) Close() {
	drain.closed.Do(func() { close(drain.stop) })
}
