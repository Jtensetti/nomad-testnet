package fabric

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A fixed-cadence sender's whole purpose is that its emissions are a function
// of a public clock and nothing else. That makes "what happens when one
// emission fails" a privacy question rather than only an availability one: a
// sender that stops, retries, or catches up after a local failure has turned a
// local condition into an externally observable event.
//
// The local conditions are real. WriteToUDP returns ENOBUFS when the host's
// socket buffers are exhausted, EPERM when a local rate limiter rejects the
// datagram, and ENETUNREACH across a route flap; the hop sequence file is
// reserved from disk and that reservation fails when the disk is full. Before
// these tests the scheduler returned on any one of them, which closed the
// socket and ended emission permanently -- the loudest possible signal, from
// the quietest possible cause.

type failingSink struct {
	attempts []time.Time
	cells    []Cell
	fail     func(attempt int) error
}

func (sink *failingSink) Send(_ context.Context, cell Cell) error {
	attempt := len(sink.attempts)
	sink.attempts = append(sink.attempts, time.Now())
	if sink.fail != nil {
		if err := sink.fail(attempt); err != nil {
			return err
		}
	}
	sink.cells = append(sink.cells, cell)
	return nil
}

func schedulerConfig() Config {
	return Config{Epoch: 80 * time.Millisecond, CellsPerEpoch: 8, MaxLateness: 40 * time.Millisecond}
}

// A cell the sink could not deliver is lost. The schedule is not.
func TestADroppedCellDoesNotEndTheSchedule(t *testing.T) {
	sink := &failingSink{fail: func(attempt int) error {
		if attempt == 2 || attempt == 5 {
			return ErrCellDropped
		}
		return nil
	}}
	scheduler, err := NewScheduler(schedulerConfig(), byteSource(0x21), sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = scheduler.RunCells(ctx, 8)
	if errors.Is(err, ErrDeadlineMissed) {
		t.Skipf("host stalled past the cadence budget: %v", err)
	}
	if err != nil {
		t.Fatalf("two dropped cells ended the schedule: %v", err)
	}
	if len(sink.attempts) != 8 {
		t.Errorf("scheduler made %d emission attempts, want 8", len(sink.attempts))
	}
	if len(sink.cells) != 6 {
		t.Errorf("sink delivered %d cells, want 6 (8 attempts less 2 drops)", len(sink.cells))
	}
	if dropped := scheduler.Dropped(); dropped != 2 {
		t.Errorf("scheduler counted %d drops, want 2", dropped)
	}
}

// The dangerous failure mode is not the drop, it is what a sender does next.
// After a lost cell the following emission must land on the same absolute
// deadline it would have had anyway: no immediate retry, no shortened
// interval, no second cell to make up for the first.
func TestADroppedCellIsNeverRetriedOrMadeUpFor(t *testing.T) {
	config := schedulerConfig()
	sink := &failingSink{fail: func(attempt int) error {
		if attempt == 3 {
			return ErrCellDropped
		}
		return nil
	}}
	scheduler, err := NewScheduler(config, byteSource(0x22), sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := scheduler.RunCells(ctx, 8); err != nil {
		if errors.Is(err, ErrDeadlineMissed) {
			t.Skipf("host stalled past the cadence budget: %v", err)
		}
		t.Fatal(err)
	}
	if len(sink.attempts) < 6 {
		t.Fatalf("only %d attempts; the gap comparison would be vacuous", len(sink.attempts))
	}

	// The gap that spans the drop is the one under test: attempt 3 failed, so
	// if the scheduler retried or caught up, the gap from 3 to 4 would be
	// short. It must be an ordinary interval.
	interval := config.CellInterval()
	across := sink.attempts[4].Sub(sink.attempts[3])
	if across < interval/2 {
		t.Errorf("the emission after a dropped cell came %s after it, less than half the "+
			"%s interval: the drop produced a retry or a catch-up", across, interval)
	}

	// And nothing was re-emitted: every delivered cell is distinct in arrival
	// order, and there are exactly as many as there were successful attempts.
	if len(sink.cells) != len(sink.attempts)-1 {
		t.Errorf("sink holds %d cells for %d attempts and one drop", len(sink.cells), len(sink.attempts))
	}
}

// Dropping is opt-in. A sink that reports anything else still stops the
// scheduler, so a genuine misconfiguration fails closed instead of running
// forever emitting nothing.
func TestASinkErrorThatIsNotADropStillStopsTheSchedule(t *testing.T) {
	sentinel := errors.New("the sink is misconfigured")
	sink := &failingSink{fail: func(attempt int) error {
		if attempt == 1 {
			return sentinel
		}
		return nil
	}}
	scheduler, err := NewScheduler(schedulerConfig(), byteSource(0x23), sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = scheduler.RunCells(ctx, 8)
	if !errors.Is(err, sentinel) {
		t.Fatalf("scheduler returned %v, want the sink's own error", err)
	}
	if len(sink.attempts) != 2 {
		t.Errorf("scheduler made %d attempts after a fatal sink error, want 2", len(sink.attempts))
	}
	if dropped := scheduler.Dropped(); dropped != 0 {
		t.Errorf("a fatal error was counted as %d drops", dropped)
	}
}

// A sink that fails every single time is the disk-full and unreachable-peer
// case. It must not turn into a burst when the condition clears, and it must
// not stop: an operator's node that goes permanently silent on a transient
// local error is both an outage and a signal.
func TestATotallyFailingSinkStillHoldsCadence(t *testing.T) {
	config := schedulerConfig()
	sink := &failingSink{fail: func(int) error { return ErrCellDropped }}
	scheduler, err := NewScheduler(config, byteSource(0x24), sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	if err := scheduler.RunCells(ctx, 8); err != nil {
		if errors.Is(err, ErrDeadlineMissed) {
			t.Skipf("host stalled past the cadence budget: %v", err)
		}
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if len(sink.cells) != 0 {
		t.Fatalf("sink recorded %d deliveries while failing every send", len(sink.cells))
	}
	if dropped := scheduler.Dropped(); dropped != 8 {
		t.Errorf("scheduler counted %d drops, want 8", dropped)
	}
	// Eight intervals of work still take eight intervals. A scheduler that
	// spun on failures would finish far sooner.
	if minimum := 7 * config.CellInterval(); elapsed < minimum {
		t.Errorf("eight failing emissions took %s, less than the %s the cadence requires: "+
			"failure accelerated the loop", elapsed, minimum)
	}
}
