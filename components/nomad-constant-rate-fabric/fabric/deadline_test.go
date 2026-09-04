package fabric

import (
	"context"
	"sort"
	"testing"
	"time"
)

// The send instant must be a property of the deadline, not of the timer that
// woke the scheduler.
//
// A sleep does not end when it is asked to: a timer set for one interval fires
// somewhere inside the millisecond after it, and where inside depends on what
// else the process is doing. That made the emission instant carry ambient
// state, and a world with private work to do is not ambiently identical to one
// without -- which is how the two-world campaign could tell them apart from
// the inter-arrival distribution alone.
//
// This is the mechanism on its own, so it runs everywhere rather than only in
// the gated campaign. The numbers are deliberately loose: what must hold is
// that the spin binds the return to the deadline far more tightly than the
// timer alone does, on whatever host this runs on, and the assertion is a
// ratio between the two rather than an absolute figure that would make this a
// measurement of the runner.
func TestWaitingIsBoundToTheDeadlineAndNotToTheTimer(t *testing.T) {
	if testing.Short() {
		t.Skip("measures wall-clock wake behaviour")
	}
	const samples = 60
	const interval = 20 * time.Millisecond

	gather := func(spin time.Duration) []time.Duration {
		errors := make([]time.Duration, 0, samples)
		next := time.Now().Add(interval)
		for index := 0; index < samples; index++ {
			if err := waitUntil(context.Background(), next, spin); err != nil {
				t.Fatal(err)
			}
			errors = append(errors, time.Since(next))
			next = next.Add(interval)
		}
		sort.Slice(errors, func(a, b int) bool { return errors[a] < errors[b] })
		return errors
	}
	median := func(values []time.Duration) time.Duration { return values[len(values)/2] }

	sleeping := median(gather(0))
	spinning := median(gather(DeadlineSpinFor(interval)))
	t.Logf("median wake error: sleeping %s, spinning %s", sleeping, spinning)

	// A tenth is far short of what was measured -- 585us against 1.6us, some
	// two orders of magnitude -- and is chosen so a loaded shared runner
	// cannot fail this for being loaded. Anything near parity means the spin
	// is not happening.
	if spinning*10 > sleeping {
		t.Fatalf("spinning to the deadline gave a median error of %s against %s "+
			"for sleeping alone; the emission instant is still the timer's, not "+
			"the deadline's", spinning, sleeping)
	}
}

// The spin window is a function of the public cell interval and nothing else.
// A sender that derived it from load or from queue depth would put private
// state back into the wake instant.
func TestTheSpinWindowIsAFunctionOfThePublicIntervalAlone(t *testing.T) {
	for _, testCase := range []struct {
		interval time.Duration
		want     time.Duration
	}{
		{50 * time.Millisecond, 2 * time.Millisecond},
		{20 * time.Millisecond, 2 * time.Millisecond},
		{8 * time.Millisecond, 2 * time.Millisecond},
		{4 * time.Millisecond, time.Millisecond},
		{time.Millisecond, 250 * time.Microsecond},
		{0, 0},
		{-time.Second, 0},
	} {
		if got := DeadlineSpinFor(testCase.interval); got != testCase.want {
			t.Errorf("DeadlineSpinFor(%s) = %s, want %s", testCase.interval, got, testCase.want)
		}
	}
	// The cap is what stops a short cadence spending the whole interval in the
	// spin, so it must actually bind below the nominal window.
	if spin := DeadlineSpinFor(4 * time.Millisecond); spin >= 4*time.Millisecond {
		t.Fatalf("the spin window is not shorter than the interval it serves: %s", spin)
	}
}

// A configuration whose spin would swallow the interval is refused rather than
// accepted and clamped, because a sender spinning through its whole cadence is
// a busy loop wearing a scheduler's name.
func TestASpinLongerThanTheIntervalIsRefused(t *testing.T) {
	base := Config{Epoch: 20 * time.Millisecond, CellsPerEpoch: 1, MaxLateness: time.Second}
	if err := base.Validate(); err != nil {
		t.Fatalf("vacuity arm: the base configuration was refused: %v", err)
	}
	for name, spin := range map[string]time.Duration{
		"equal to the interval":    20 * time.Millisecond,
		"longer than the interval": 21 * time.Millisecond,
		"negative":                 -time.Millisecond,
	} {
		config := base
		config.DeadlineSpin = spin
		if err := config.Validate(); err == nil {
			t.Errorf("%s: a spin of %s was accepted", name, spin)
		}
	}
}

// Cancellation must be honoured inside the spin window, not only in the sleep
// before it. A scheduler shutting down must not have to wait out the deadline.
func TestCancellationEndsTheSpin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := waitUntil(ctx, start.Add(time.Second), 2*time.Second)
	if err == nil {
		t.Fatal("a cancelled context waited out the deadline")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("cancellation took %s to be noticed", elapsed)
	}
}
