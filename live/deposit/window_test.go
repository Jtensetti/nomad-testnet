package deposit

import (
	"crypto/rand"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"

	"github.com/Jtensetti/nomad-testnet/live/publish"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// testDepositInstant is an instant inside epoch 1's deposit window under
// testSchedule -- the same instant newPathFixture uses, so a drain and the
// airlock it feeds agree about the window instead of each keeping its own.
func testDepositInstant() time.Time {
	schedule := testSchedule()
	return schedule.Genesis.Add(schedule.Period).Add(time.Minute)
}

// testShutInstant is inside the same epoch but past its deposit cutoff.
func testShutInstant() time.Time {
	schedule := testSchedule()
	_, closes, err := schedule.DepositWindow(1)
	if err != nil {
		panic(err)
	}
	return closes.Add(time.Second)
}

// newTestDrain builds a drain on the shared test schedule with its clock
// pinned, so a test states which side of the deposit cutoff it is on rather
// than depending on when it happens to run.
func newTestDrain(t *testing.T, session *uplink.Session, queue *publish.Queue,
	now time.Time) *Drain {
	t.Helper()
	drain, err := NewDrainWithPoll(session, queue, testSchedule(), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	drain.mutex.Lock()
	drain.now = func() time.Time { return now }
	drain.mutex.Unlock()
	t.Cleanup(drain.Close)
	return drain
}

// The gate itself, on both sides of the cutoff and outside the schedule
// entirely. A window helper that quietly reported "open" everywhere would make
// every test below pass while testing nothing.
func TestTheDepositWindowGateAgreesWithTheSchedule(t *testing.T) {
	schedule := testSchedule()
	opens, closes, err := schedule.DepositWindow(1)
	if err != nil {
		t.Fatal(err)
	}
	drain := &Drain{schedule: schedule}
	for _, testCase := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"before genesis", schedule.Genesis.Add(-time.Second), false},
		{"the instant the window opens", opens, true},
		{"inside the window", testDepositInstant(), true},
		{"the instant the window closes", closes, false},
		{"after the cutoff", testShutInstant(), false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := drain.depositWindowOpen(testCase.at); got != testCase.want {
				t.Fatalf("window open=%v at %s, want %v", got, testCase.at, testCase.want)
			}
		})
	}
}

// An unusable schedule must report the window shut, not open. Failing open
// here would destroy work; failing closed defers it.
func TestAnUnusableScheduleReportsTheWindowShut(t *testing.T) {
	drain := &Drain{}
	if drain.depositWindowOpen(time.Now().UTC()) {
		t.Fatal("a zero schedule reported an open deposit window; it must fail closed")
	}
}

// The defect DEC-020 recorded, at the boundary that decides it: past the
// cutoff, a queued fragment must still be on disk after the drain has had
// every chance to take it.
func TestWorkIsNotTakenFromTheQueueAfterTheCutoff(t *testing.T) {
	f := newPathFixture(t)
	queue := newQueue(t, `{"title":"held","body":"cccc"}`)
	pending, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if pending == 0 {
		t.Fatal("the fixture queued nothing, so this test could not fail")
	}
	drain := newTestDrain(t, f.session, queue, testShutInstant())

	// Long enough for the filling goroutine to have polled hundreds of times.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for sequence := uint64(1); sequence <= 20; sequence++ {
		cell, err := drain.Emit(sequence)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.ingress.Accept(f.session, f.sessionID, cell, f.now); err != nil {
			t.Fatalf("cell %d was refused: %v", sequence, err)
		}
	}

	work, cover := drain.Counts()
	if work != 0 {
		t.Fatalf("the drain emitted %d work cells past the deposit cutoff; "+
			"every one of them is a fragment the airlock would refuse and "+
			"nothing holds any more", work)
	}
	if cover != 20 {
		t.Fatalf("emitted %d cover cells for 20 ticks; the cadence must not "+
			"change with the window", cover)
	}
	after, err := queue.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if after != pending {
		t.Fatalf("the queue went from %d to %d fragments while the deposit "+
			"window was shut; work taken now is work destroyed", pending, after)
	}
}

// The same drain, before the cutoff, must publish. A gate that never opened
// would pass the test above and lose everything.
func TestWorkIsTakenFromTheQueueInsideTheWindow(t *testing.T) {
	f := newPathFixture(t)
	queue := newQueue(t, `{"title":"sent","body":"dddd"}`)
	drain := newTestDrain(t, f.session, queue, testDepositInstant())

	deadline := time.Now().Add(2 * time.Second)
	for sequence := uint64(1); time.Now().Before(deadline); sequence++ {
		if work, _ := drain.Counts(); work > 0 {
			break
		}
		if _, err := drain.Emit(sequence); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if work, _ := drain.Counts(); work == 0 {
		t.Fatal("no work left the queue inside an open deposit window")
	}
	if drain.Deferred() != 0 {
		t.Fatalf("deferred %d cells inside an open window", drain.Deferred())
	}
}

// A fragment buffered just before the cutoff is held, not sent into a shut
// window and not thrown away. This is the case that separates deferring from
// dropping: the fragment is already off the durable queue.
func TestABufferedFragmentIsHeldAcrossTheCutoffAndSentWhenTheWindowReopens(t *testing.T) {
	f := newPathFixture(t)
	queue := newQueue(t, `{"title":"straddles","body":"eeee"}`)
	drain := newTestDrain(t, f.session, queue, testDepositInstant())

	// Let the filling goroutine take the fragment while the window is open.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(drain.ready) == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if len(drain.ready) == 0 {
		t.Fatal("the buffer never filled, so the case under test did not arise")
	}

	shut := testShutInstant()
	drain.mutex.Lock()
	drain.now = func() time.Time { return shut }
	drain.mutex.Unlock()

	for sequence := uint64(1); sequence <= 5; sequence++ {
		if _, err := drain.Emit(sequence); err != nil {
			t.Fatal(err)
		}
	}
	if work, _ := drain.Counts(); work != 0 {
		t.Fatalf("emitted %d work cells past the cutoff", work)
	}
	if drain.Deferred() != 5 {
		t.Fatalf("deferred %d of 5 ticks while holding a fragment past the "+
			"cutoff; a held fragment that is not counted is one nobody can "+
			"tell was held", drain.Deferred())
	}
	if len(drain.ready) == 0 {
		t.Fatal("the buffered fragment was consumed by a cover emission")
	}

	open := testDepositInstant()
	drain.mutex.Lock()
	drain.now = func() time.Time { return open }
	drain.mutex.Unlock()

	cell, err := drain.Emit(6)
	if err != nil {
		t.Fatal(err)
	}
	if work, _ := drain.Counts(); work != 1 {
		t.Fatal("the held fragment was not emitted when the window reopened")
	}
	if err := f.ingress.Accept(f.session, f.sessionID, cell, f.now); err != nil {
		t.Fatalf("the deferred fragment was refused on its retry window: %v", err)
	}
}

// The gate must not become a wire signal. Whatever the window and whatever the
// queue, a tick produces exactly one cell and the cleartext sequence prefix
// advances by one, so an observer counting cells or reading the prefix learns
// the same thing in all four combinations.
//
// Cell size is deliberately not compared: fabric.Cell is a fixed-size array,
// so a size assertion restates the type rather than testing the drain.
func TestTheWindowGateIsInvisibleOnTheWire(t *testing.T) {
	const ticks = 40
	situations := []struct {
		name    string
		objects []string
		at      time.Time
	}{
		{"work, window open", []string{`{"title":"a","body":"aaaa"}`}, testDepositInstant()},
		{"work, window shut", []string{`{"title":"a","body":"aaaa"}`}, testShutInstant()},
		{"no work, window open", nil, testDepositInstant()},
		{"no work, window shut", nil, testShutInstant()},
	}
	observed := make([][]uint64, len(situations))
	for index, situation := range situations {
		f := newPathFixture(t)
		var queue *publish.Queue
		if situation.objects != nil {
			queue = newQueue(t, situation.objects...)
		}
		drain := newTestDrain(t, f.session, queue, situation.at)
		time.Sleep(50 * time.Millisecond)
		observed[index] = emitTicks(t, situation.name, drain, ticks)
	}
	for index, candidate := range observed[1:] {
		if !slices.Equal(candidate, observed[0]) {
			t.Fatalf("%q is separable from %q on the wire:\n %v\n %v",
				situations[index+1].name, situations[0].name, candidate, observed[0])
		}
	}
}

// The retransmission DEC-020 proposed, refused where it would be written.
//
// Re-emitting under a sequence already used is an AEAD nonce reuse before it
// is anything else, and the drain is the only party holding the state to see
// it. This is the negative control for the whole design: if this passes, the
// "just resend the sealed cell" implementation cannot be written by accident.
func TestASequenceIsNeverSealedTwice(t *testing.T) {
	f := newPathFixture(t)
	drain := newTestDrain(t, f.session, nil, testDepositInstant())

	if _, err := drain.Emit(9); err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []uint64{9, 8, 1} {
		_, err := drain.Emit(sequence)
		if !errors.Is(err, ErrSequenceReused) {
			t.Fatalf("sealing sequence %d again returned %v, want ErrSequenceReused; "+
				"a repeated sequence is a repeated GCM nonce under the session key",
				sequence, err)
		}
	}
	if _, err := drain.Emit(10); err != nil {
		t.Fatalf("a sequence that does advance was refused: %v", err)
	}
	if _, err := drain.Emit(0); err == nil {
		t.Fatal("sequence zero was accepted; seal refuses it and so must this")
	}
}

// A seal that fails must not cost the fragment.
//
// Emit takes the fragment off the buffer before it can seal it, and Queue.Next
// unlinked it from disk before that, so an early return on a seal error
// destroys publication work for a reason that has nothing to do with the
// deposit window. That is the loss DEC-022 exists to prevent, reached down a
// different path.
func TestASealFailureDoesNotCostTheFragment(t *testing.T) {
	queue := newQueue(t, `{"title":"kept","body":"ffff"}`)

	// An all-zero committee key is a small-order point, which mix refuses, so
	// every seal on this session fails.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], []byte("seal-failure-topology-digest----"))
	var unusable mix.PublicKey
	session, err := uplink.NewSession(secret, unusable, uplink.Context{
		NetworkID: "seal-failure", Epoch: 3, TopologyDigest: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	drain := newTestDrain(t, session, queue, testDepositInstant())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(drain.ready) == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if len(drain.ready) == 0 {
		t.Fatal("the buffer never filled, so the case under test did not arise")
	}

	for sequence := uint64(1); sequence <= 5; sequence++ {
		if _, err := drain.Emit(sequence); err == nil {
			t.Fatalf("emit %d sealed with an unusable committee key", sequence)
		}
		if len(drain.ready) == 0 {
			t.Fatalf("the fragment was destroyed by a failed seal on emit %d; "+
				"it is off the durable queue and nothing else holds it", sequence)
		}
	}
	if work, _ := drain.Counts(); work != 0 {
		t.Fatalf("counted %d work emissions that never left", work)
	}
}
