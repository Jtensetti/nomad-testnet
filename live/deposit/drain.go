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
// The sequence is the AEAD nonce (live/uplink/sequence.go), so sealing twice
// under one key and sequence hands an observer the XOR of two plaintexts and,
// through GHASH, the authentication key. A session holds no sequence state by
// design, so the caller that has it does the check. DEC-020's retry -- seal
// the fragment again -- is exactly this call.
var ErrSequenceReused = errors.New("uplink sequence reused")

type Drain struct {
	session *uplink.Session
	// Public deposit window policy from the signed epoch descriptor: the only
	// reason this type knows what time it is, derived from the same bytes
	// every operator derives it from.
	schedule airlock.Schedule
	ready    chan publish.Fragment
	stop     chan struct{}
	poll     time.Duration
	closed   sync.Once

	// Counters are for local assertions only. They must never reach telemetry:
	// work versus cover is the private fact this design hides, and deferred is
	// worse -- it counts the ticks on which there was work.
	mutex sync.Mutex
	// Guarded because tests move it across the cutoff while fill is running.
	now          func() time.Time
	work         uint64
	cover        uint64
	deferred     uint64
	lastSequence uint64
	// Deposits this session has already spent in quotaEpoch. The airlock
	// counts every in-window cell against MaxDepositsPerSession, cover
	// included, because it cannot tell them apart -- so this counts every
	// in-window cell too. Derived from the public bound and this drain's own
	// clock; the operator answers nothing.
	quotaEpoch uint64
	quotaSpent int
}

// NewDrain starts draining queue into a one-slot buffer. Close stops it.
//
// queue may be nil, which is a publisher that never publishes: the drain then
// emits cover forever, which is the same externally observable behaviour as a
// publisher whose queue happens to be empty.
//
// schedule is required and has no permissive default: an unknown window
// treated as open destroys work at the cutoff, and treated as shut publishes
// nothing at all.
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

// clock reads the instant under the mutex; fill and Emit both call it.
func (drain *Drain) clock() time.Time {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	if drain.now == nil {
		return time.Now().UTC()
	}
	return drain.now()
}

// windowState reports the release epoch containing now and whether a deposit
// made now lands inside its open part.
//
// It fails closed: a schedule that cannot name an epoch for this instant costs
// a deferred fragment, where failing open costs the fragment outright.
func (drain *Drain) windowState(now time.Time) (uint64, bool) {
	epoch, err := drain.schedule.EpochAt(now)
	if err != nil {
		return 0, false
	}
	opens, closes, err := drain.schedule.DepositWindow(epoch)
	if err != nil {
		return 0, false
	}
	return epoch, !now.Before(opens) && now.Before(closes)
}

func (drain *Drain) depositWindowOpen(now time.Time) bool {
	_, open := drain.windowState(now)
	return open
}

func (drain *Drain) quotaRemaining(epoch uint64) bool {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	return drain.quotaRemainingLocked(epoch)
}

func (drain *Drain) quotaRemainingLocked(epoch uint64) bool {
	if drain.quotaEpoch != epoch {
		return true
	}
	return drain.quotaSpent < drain.schedule.MaxDepositsPerSession
}

// spendDepositSlot records that a cell was emitted inside epoch's deposit
// window, whether it carried work or cover. The airlock charges both.
func (drain *Drain) spendDepositSlot(epoch uint64) {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	if drain.quotaEpoch != epoch {
		drain.quotaEpoch = epoch
		drain.quotaSpent = 0
	}
	drain.quotaSpent++
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
		// Queue.Next unlinks as it hands out, so a fragment taken while the
		// window is shut is one the airlock refuses and nothing holds any
		// more -- 25% of every period at the default schedule, 38-43%
		// measured at three seconds (DEC-020). Leaving it on disk costs
		// nothing, and this goroutine is not the one that emits.
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
// Outside the open deposit window, and inside it once this session has spent
// its per-session deposit bound, it emits cover and leaves any buffered
// fragment alone. That is what separates this from the retry DEC-020 asked
// for: a cell held back was never on the wire, so nothing is sent twice and
// the sequence -- eight cleartext bytes at the head of every cell -- never
// repeats. Cover is never retransmitted, so a repeat would tell the entry
// operator this publisher had work refused.
//
// Both gates are computed from public policy and this drain's own clock. The
// operator answers nothing, so neither gate is a feedback channel.
func (drain *Drain) Emit(sequence uint64) (fabric.Cell, error) {
	if err := drain.reserve(sequence); err != nil {
		return fabric.Cell{}, err
	}
	epoch, open := drain.windowState(drain.clock())
	// A slot is spent by a cell that actually leaves, so the error paths below
	// must not charge one. The airlock charges work and cover alike, because
	// it cannot tell them apart.
	spend := func() {
		if open {
			drain.spendDepositSlot(epoch)
		}
	}
	if open && drain.quotaRemaining(epoch) {
		select {
		case fragment := <-drain.ready:
			var payload [uplink.PayloadSize]byte
			copy(payload[:], fragment.Payload[:])
			cell, err := drain.session.SealWork(sequence, payload)
			if err != nil {
				// The receive already took it off the buffer, and Queue.Next
				// unlinked it before that, so returning early here would
				// destroy the fragment for a reason that has nothing to do
				// with the deposit window -- the same loss DEC-022 exists to
				// prevent, arriving down a different path. The buffer holds
				// one slot and this emptied it, so the send only fails if
				// fill refilled it first, and then nothing was idle anyway.
				select {
				case drain.ready <- fragment:
				default:
				}
				return fabric.Cell{}, err
			}
			drain.count(emissionWork)
			spend()
			return cell, nil
		default:
		}
	}
	cell, err := drain.session.SealCover(sequence)
	if err != nil {
		return fabric.Cell{}, err
	}
	kind := emissionCover
	// An empty buffer refilled a microsecond later is an idle tick, not a held
	// fragment, so an open window with quota left never counts as deferred.
	if (!open || !drain.quotaRemaining(epoch)) && len(drain.ready) > 0 {
		kind = emissionDeferred
	}
	drain.count(kind)
	spend()
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

// Deferred counts cover emitted while a fragment was buffered and the drain
// declined to spend it -- the window was shut, or this session's deposit bound
// was spent. Work this drain declined to destroy. A subset of the cover count,
// not a third category on the wire. Local assertions only.
func (drain *Drain) Deferred() uint64 {
	drain.mutex.Lock()
	defer drain.mutex.Unlock()
	return drain.deferred
}

// Close stops the filling goroutine. At most one fragment -- whatever is in
// the one-slot buffer -- is lost, and nothing puts it back. Holding it across
// a shutdown to emit later would be catch-up traffic, which is worse, so this
// is the intended direction.
func (drain *Drain) Close() {
	drain.closed.Do(func() { close(drain.stop) })
}
