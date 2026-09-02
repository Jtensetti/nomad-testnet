package deposit

import (
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/airlock"
	"github.com/Jtensetti/nomad-testnet/live/publish"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// quotaSchedule is the shared test schedule with a per-session bound well
// below what a publisher with a full queue would try to emit in one window.
func quotaSchedule() airlock.Schedule {
	schedule := testSchedule()
	schedule.MaxDepositsPerSession = 2
	return schedule
}

// emitPaced drives ticks spaced well beyond the fill goroutine's poll
// interval. These tests are about the quota gate, and a tick that outruns the
// refill emits cover because the buffer is momentarily empty -- which spends a
// deposit slot for a reason that has nothing to do with the bound. At the
// deployed cadence the tick is 25ms against a 1ms poll, so the buffer is full
// whenever the queue is; here it has to be paced deliberately.
func emitPaced(t *testing.T, drain *Drain, ticks int) {
	t.Helper()
	waitForBufferedWork(t, drain)
	for sequence := uint64(1); sequence <= uint64(ticks); sequence++ {
		if _, err := drain.Emit(sequence); err != nil {
			t.Fatalf("tick %d: %v", sequence, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitForBufferedWork blocks until the fill goroutine has primed the one-slot
// buffer.
//
// A cold drain's first tick races that goroutine, and a tick that wins the race
// emits cover -- spending a deposit slot for a reason that has nothing to do
// with the bound. In steady state the buffer is already primed when a window
// opens, because a fragment buffered before the cutoff is held across it
// rather than dropped.
func waitForBufferedWork(t *testing.T, drain *Drain) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(drain.ready) > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the fill goroutine never buffered a fragment, so no test below " +
		"is measuring the quota gate")
}

func newQuotaDrain(t *testing.T, session *uplink.Session, queue *publish.Queue,
	now time.Time) *Drain {
	t.Helper()
	drain, err := NewDrainWithPoll(session, queue, quotaSchedule(), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	drain.mutex.Lock()
	drain.now = func() time.Time { return now }
	drain.mutex.Unlock()
	t.Cleanup(drain.Close)
	return drain
}

// A publisher knows its own per-session bound: it is public policy in the
// signed epoch descriptor, the same bytes the operator reads it from. Emitting
// past it does not get the work in -- the airlock refuses every deposit over
// the bound -- and Queue.Next has already unlinked the fragment, so the work
// is destroyed rather than deferred. That is the same loss DEC-022 closed for
// the window, arriving through the quota instead.
func TestWorkIsNotDrainedPastThisSessionsOwnQuota(t *testing.T) {
	queue := newQueue(t, "alpha", "beta", "gamma", "delta", "epsilon", "zeta")
	pending, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if pending <= quotaSchedule().MaxDepositsPerSession {
		t.Fatalf("the fixture queued %d fragments, which cannot exceed a bound of %d",
			pending, quotaSchedule().MaxDepositsPerSession)
	}

	drain := newQuotaDrain(t, newSession(t), queue, testDepositInstant())
	emitTicks(t, "inside the window", drain, 32)

	work, _ := drain.Counts()
	bound := uint64(quotaSchedule().MaxDepositsPerSession)
	if work > bound {
		t.Fatalf("emitted %d work cells against a per-session bound of %d; "+
			"the excess is refused by the airlock and already unlinked from the queue",
			work, bound)
	}

	// The rest must still be on the queue rather than gone.
	left, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if uint64(pending)-uint64(left) > bound+1 {
		t.Fatalf("queue went from %d to %d fragments while only %d could be deposited",
			pending, left, bound)
	}
}

// The loss end to end, through a real airlock rather than through a counter.
// Cover past the bound is refused too and that is unavoidable -- the publisher
// must keep emitting at cadence, and the airlock cannot tell cover from work
// so it charges both. What must not happen is a *fragment* leaving the queue
// to be refused: Queue.Next unlinks as it hands out, so such a fragment is
// gone rather than deferred.
func TestOverQuotaFragmentsAreNeitherDepositedNorDestroyed(t *testing.T) {
	f := newPathFixture(t)
	bound := quotaSchedule().MaxDepositsPerSession
	lock, err := airlock.New(quotaSchedule(), f.committee, 1)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := NewIngress(lock)
	if err != nil {
		t.Fatal(err)
	}
	queue := newQueue(t, "alpha", "beta", "gamma", "delta", "epsilon", "zeta")
	before, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	drain := newQuotaDrain(t, f.session, queue, f.now)

	for sequence := uint64(1); sequence <= 40; sequence++ {
		cell, err := drain.Emit(sequence)
		if err != nil {
			t.Fatalf("tick %d: %v", sequence, err)
		}
		if err := ingress.Accept(f.session, f.sessionID, cell, f.now); err != nil {
			t.Fatalf("tick %d: %v", sequence, err)
		}
		time.Sleep(time.Millisecond)
	}

	if held := lock.Pending(); held != bound {
		t.Fatalf("the airlock holds %d deposits from this session, want the bound %d",
			held, bound)
	}
	after, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	// The bound's worth of fragments were deposited. One more may sit in the
	// drain's one-slot buffer, which is the shutdown exposure DEC-022 records
	// and accepts; anything beyond that was unlinked and refused.
	if taken := before - after; taken > bound+1 {
		t.Fatalf("%d fragments left the queue but only %d could be deposited; "+
			"%d were unlinked and refused", taken, bound, taken-bound-1)
	}
}

// The gate must be the quota rather than the window: inside an open window,
// with work available on every tick, work stops at exactly the bound while
// cover keeps flowing at the same rate.
func TestTheQuotaGateStopsWorkWhileCoverContinues(t *testing.T) {
	bound := uint64(quotaSchedule().MaxDepositsPerSession)
	queue := newQueue(t, "alpha", "beta", "gamma", "delta", "epsilon", "zeta")
	drain := newQuotaDrain(t, newSession(t), queue, testDepositInstant())

	const ticks = 12
	emitPaced(t, drain, ticks)

	work, cover := drain.Counts()
	if work != bound {
		t.Fatalf("emitted %d work cells inside an open window with a full queue, "+
			"want exactly the bound %d", work, bound)
	}
	if work+cover != ticks {
		t.Fatalf("%d ticks produced %d cells", ticks, work+cover)
	}
	if drain.Deferred() == 0 {
		t.Fatal("no tick was recorded as deferred, so the fragment held back " +
			"by the quota was not counted as work declined")
	}
}

// The bound is per epoch. A publisher that spent it in one epoch may spend it
// again in the next, without anything having told it so.
func TestTheQuotaIsRestoredAtTheEpochBoundary(t *testing.T) {
	bound := uint64(quotaSchedule().MaxDepositsPerSession)
	queue := newQueue(t, "alpha", "beta", "gamma", "delta", "epsilon", "zeta")
	drain := newQuotaDrain(t, newSession(t), queue, testDepositInstant())

	emitPaced(t, drain, 8)
	first, _ := drain.Counts()
	if first != bound {
		t.Fatalf("epoch 1 emitted %d work cells, want the bound %d", first, bound)
	}

	next := testDepositInstant().Add(quotaSchedule().Period)
	drain.mutex.Lock()
	drain.now = func() time.Time { return next }
	drain.mutex.Unlock()

	for sequence := uint64(9); sequence <= 16; sequence++ {
		if _, err := drain.Emit(sequence); err != nil {
			t.Fatalf("epoch 2 tick %d: %v", sequence, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	total, _ := drain.Counts()
	if total != 2*bound {
		t.Fatalf("two epochs emitted %d work cells, want %d", total, 2*bound)
	}
}

// The core invariant at this gate. A drain that stops taking work at its bound
// must be indistinguishable from one that never had work: same number of
// cells, same shape, same sequence prefixes. The gate reads public policy and
// a clock, so there is nothing for it to leak -- but the emission path is
// where that would show up, so it is measured there rather than argued.
func TestTheQuotaGateIsInvisibleOnTheWire(t *testing.T) {
	const ticks = 24
	busy := newQuotaDrain(t, newSession(t), newQueue(t,
		"alpha", "beta", "gamma", "delta", "epsilon", "zeta"), testDepositInstant())
	waitForBufferedWork(t, busy)
	idle := newQuotaDrain(t, newSession(t), nil, testDepositInstant())

	busyPrefixes := emitTicks(t, "past its bound", busy, ticks)
	idlePrefixes := emitTicks(t, "with no queue at all", idle, ticks)

	if len(busyPrefixes) != len(idlePrefixes) {
		t.Fatalf("%d cells against %d for the same %d ticks",
			len(busyPrefixes), len(idlePrefixes), ticks)
	}
	for index := range busyPrefixes {
		if busyPrefixes[index] != idlePrefixes[index] {
			t.Fatalf("cell %d carries sequence %d for a publisher past its bound "+
				"and %d for one with nothing to publish",
				index, busyPrefixes[index], idlePrefixes[index])
		}
	}
	work, _ := busy.Counts()
	if work != uint64(quotaSchedule().MaxDepositsPerSession) {
		t.Fatalf("the busy drain emitted %d work cells, so it was not past its bound", work)
	}
	if idleWork, _ := idle.Counts(); idleWork != 0 {
		t.Fatalf("the idle drain emitted %d work cells with no queue", idleWork)
	}
}
