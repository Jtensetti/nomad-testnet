package fabric

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
)

// Source supplies one complete fixed-size cell. Choosing what protocol work
// fills a cell is intentionally separate from the wall-clock scheduler.
type Source interface {
	NextCell(context.Context) (Cell, error)
}

type RandomSource struct{}

func (RandomSource) NextCell(context.Context) (Cell, error) { return RandomCell() }

// Config describes a traffic class. Epoch is the accounting window; cells are
// evenly spaced across that window by Run rather than emitted as an epoch burst.
type Config struct {
	Epoch         time.Duration
	CellsPerEpoch int
	// MaxLateness is a public operational limit. The scheduler fails instead of
	// emitting a catch-up burst after this limit is exceeded.
	MaxLateness time.Duration
	// DeadlineSpin is how long before each deadline the scheduler stops
	// sleeping and busies itself until the deadline arrives.
	//
	// It exists because a sleep does not end when it is asked to. A timer set
	// for 20 ms fires somewhere inside the millisecond after it, and *where*
	// inside depends on what else the process is doing: measured on a quiet
	// process the wake landed a median 585 us late, and with one unrelated
	// goroutine sleeping on a 2 ms cycle the same wake landed a median 446 us
	// late -- every percentile shifted, reproducibly, reverting when the
	// goroutine stopped. Send immediately after the wake and that shift is the
	// packet's timestamp. An observer comparing two worlds that differ only in
	// whether the node has private work to do can read the difference off the
	// inter-arrival distribution: quiet emission lands on the timer's coarse
	// grid and is visibly bimodal, busy emission is dithered off it and is
	// smooth. No statistics are needed to see it; the histogram has a hole in
	// it or it does not.
	//
	// Sleeping to just short of the deadline and spinning the remainder makes
	// the send instant a function of the deadline instead of the wake. The same
	// measurement with a 1.5 ms spin: a median error of 1.6 us against 0.8 us,
	// where it had been 585 against 446. The residual difference is smaller
	// than the cost of building and sending the cell.
	//
	// The cost is real and is paid deliberately: the spin burns a core for its
	// window every interval, unconditionally, whatever the queue holds. An
	// unconditional cost carries no information, which is the point -- this is
	// the invariant's own trade, where availability and efficiency lose to a
	// private-dependent signal. Zero disables it and restores the sleep-only
	// behaviour, which is correct on a host that cannot spare the cycles and is
	// a decision to leave the signal in place.
	DeadlineSpin time.Duration
}

func (c Config) Validate() error {
	if c.Epoch <= 0 {
		return errors.New("epoch must be positive")
	}
	if c.CellsPerEpoch <= 0 {
		return errors.New("cells per epoch must be positive")
	}
	if c.CellInterval() <= 0 {
		return errors.New("epoch is too short for the configured cell count")
	}
	if c.Epoch%time.Duration(c.CellsPerEpoch) != 0 {
		return errors.New("epoch must divide exactly into equal cell intervals")
	}
	if c.MaxLateness < 0 {
		return errors.New("maximum lateness must not be negative")
	}
	if c.DeadlineSpin < 0 {
		return errors.New("deadline spin must not be negative")
	}
	if c.DeadlineSpin >= c.CellInterval() {
		return errors.New("deadline spin must be shorter than the cell interval")
	}
	return nil
}

// DeadlineSpinFor is the spin window a sender should use for a given public
// cell interval, so that every Nomad sender derives it the same way from a
// value the signed topology already publishes rather than each choosing one.
//
// Two milliseconds covers the wake error measured on this project's hosts with
// room over it -- the spread was about one millisecond -- and the quarter-
// interval cap keeps a very short cadence from spending most of a core in the
// spin. At the deployed 50 ms cadence it is 2 ms, so one core is busy 4% of
// the time; at 8 ms or less the cap takes over.
//
// It is a function of a public number and nothing else. A sender that chose
// its spin from load, from queue depth, or from anything else it knows would
// be back to a wake instant that carries private state, which is the whole
// thing this exists to remove.
func DeadlineSpinFor(interval time.Duration) time.Duration {
	const nominal = 2 * time.Millisecond
	if interval <= 0 {
		return 0
	}
	if quarter := interval / 4; quarter < nominal {
		return quarter
	}
	return nominal
}

// CellInterval is the target spacing between externally visible cells.
func (c Config) CellInterval() time.Duration {
	if c.CellsPerEpoch <= 0 {
		return 0
	}
	return c.Epoch / time.Duration(c.CellsPerEpoch)
}

type Sink interface {
	Send(context.Context, Cell) error
}

type Scheduler struct {
	cfg     Config
	source  Source
	sink    Sink
	dropped atomic.Uint64
}

var ErrDeadlineMissed = errors.New("fixed-cadence deadline missed")

// ErrCellDropped is how a Source or Sink says that this one cell could not be
// produced or delivered for a local reason: a transient socket error, an
// exhausted socket buffer, a full disk under a local state write. The
// scheduler counts it and continues on the same absolute schedule. The cell is
// lost -- never retried, never re-emitted later, never followed by a catch-up
// -- because losing work is the only response to a local condition that does
// not turn that condition into an externally observable event.
//
// Returning it is deliberate and narrow. Any other error still stops the
// scheduler, so a real misconfiguration fails closed rather than running
// forever emitting nothing. Callers that wrap it must use %w.
var ErrCellDropped = errors.New("sink dropped one cell")

func NewScheduler(cfg Config, source Source, sink Sink) (*Scheduler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if source == nil || sink == nil {
		return nil, errors.New("source and sink are required")
	}
	return &Scheduler{cfg: cfg, source: source, sink: sink}, nil
}

// EmitOne executes one scheduled emission. It exists so the actual source/sink
// path can be exercised without wall-clock sleeps in unit tests.
func (s *Scheduler) EmitOne(ctx context.Context) error {
	cell, err := s.source.NextCell(ctx)
	if err != nil {
		return err
	}
	return s.sink.Send(ctx, cell)
}

// Run emits one cell per CellInterval until the context ends. Deadlines are
// absolute, not delays after Send, so sink latency cannot accumulate as drift.
// A missed slot is never followed by a catch-up burst.
func (s *Scheduler) Run(ctx context.Context) error {
	return s.run(ctx, -1)
}

// RunCells is the finite form used by the testnet and black-box UDP tests.
func (s *Scheduler) RunCells(ctx context.Context, count int) error {
	if count < 0 {
		return errors.New("cell count must not be negative")
	}
	return s.run(ctx, count)
}

func (s *Scheduler) run(ctx context.Context, count int) error {
	if count == 0 {
		return nil
	}
	interval := s.cfg.CellInterval()
	allowed := s.cfg.MaxLateness
	if allowed == 0 {
		allowed = interval
	}
	// The cell is built before the deadline it is sent at, never after it.
	//
	// Building it after waking meant the wire timestamp was the deadline plus
	// however long NextCell took, and NextCell takes a different amount of
	// time depending on whether the queue had work: dequeuing and handing on a
	// real cell is not the same work as generating a cover cell. The deadlines
	// themselves are exact, so the mean interval was exact too and looked
	// correct -- but the construction cost landed on each packet's timestamp,
	// and the *shape* of the inter-arrival distribution carried it.
	//
	// Measured on the two-world campaign before this change, pooling four
	// rounds: means identical to the configured interval in every world
	// (20.010, 20.003, 19.995 ms against 20), and the idle distribution
	// bimodal -- deciles bunched at 19.5-19.9 and then 20.57-20.71 with a gap
	// between -- while the world with private work was smooth and unimodal
	// across the same range. An observer needed no statistics for that: the
	// histogram has a hole in it or it does not. The preregistered rule
	// rejected at p ~ 0 on every stressor, reproducibly, since the campaign
	// first ran.
	//
	// So the deadline path holds nothing but the send. Cell n+1 is built in
	// the interval after cell n leaves, where the slack already is, and the
	// lateness guard below is what bounds it: a source too slow to have a cell
	// ready by the next deadline misses that deadline and fails closed, which
	// is the existing behaviour for a slow source and not a new one.
	//
	// What this does not fix, stated because the distinction matters: Send
	// itself still runs on the deadline path. It is a write of a fixed-size
	// cell to a destination the public plan chose, so its cost does not depend
	// on private state -- but that is an argument, not a measurement, and the
	// campaign measures the pair rather than the parts.
	cell, cellErr := s.source.NextCell(ctx)
	next := time.Now().Add(interval)
	for emitted := 0; count < 0 || emitted < count; emitted++ {
		if err := waitUntil(ctx, next, s.cfg.DeadlineSpin); err != nil {
			return err
		}
		if late := time.Since(next); late > allowed {
			return fmt.Errorf("%w by %s", ErrDeadlineMissed, late)
		}
		// A source that could not produce a cell costs this slot and nothing
		// else, exactly as it did when the failure happened here rather than
		// an interval ago. The error is carried to the slot it belongs to so
		// that a dropped cell is still one lost emission, never a shifted one.
		err := cellErr
		if err == nil {
			err = s.sink.Send(ctx, cell)
		}
		if err != nil {
			if !errors.Is(err, ErrCellDropped) {
				return err
			}
			s.dropped.Add(1)
		}
		next = next.Add(interval)
		if !time.Now().Before(next) {
			return ErrDeadlineMissed
		}
		// Only when another slot is coming. A finite run that prefetched past
		// its last emission would take a cell off the queue and discard it,
		// so RunCells(n) would consume n+1 cells to emit n.
		if count < 0 || emitted+1 < count {
			cell, cellErr = s.source.NextCell(ctx)
		}
	}
	return nil
}

// Dropped is the number of scheduled emissions this scheduler lost to
// ErrCellDropped. It is local diagnostic state for whoever owns the scheduler,
// and it never feeds back into scheduling.
//
// It is not what an operator reads: a Sink that wants a drop count published
// keeps its own, because the Sink knows which peer and which cause, and the
// scheduler only knows that one emission did not happen. nomad-testnet's node
// does exactly that and publishes send_dropped from the sink.
func (s *Scheduler) Dropped() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

// waitUntil sleeps until spin before the deadline and then yields in a loop
// until the deadline itself.
//
// The spin is what makes the return instant a property of the deadline rather
// than of the timer that woke it; see Config.DeadlineSpin for the measurement
// that motivates it. runtime.Gosched rather than a tight loop, so the spinning
// goroutine gives up its processor on every pass and a single-processor host
// still makes progress -- the measurements above were taken this way.
//
// Cancellation is checked on every pass, so a cancelled context still ends the
// wait within the spin window rather than at the deadline.
func waitUntil(ctx context.Context, deadline time.Time, spin time.Duration) error {
	if delay := time.Until(deadline) - spin; delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		runtime.Gosched()
	}
	return nil
}

// EpochTrace returns the planned byte count per accounting epoch. It is a
// planning helper, not a packet capture or timing measurement.
func EpochTrace(cfg Config, epochs int) ([]int, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if epochs < 0 {
		return nil, errors.New("epochs must be non-negative")
	}
	out := make([]int, epochs)
	for i := range out {
		out[i] = cfg.CellsPerEpoch * CellSize
	}
	return out, nil
}
