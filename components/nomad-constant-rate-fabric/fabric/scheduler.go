package fabric

import (
	"context"
	"errors"
	"fmt"
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
	return nil
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
	next := time.Now().Add(interval)
	for emitted := 0; count < 0 || emitted < count; emitted++ {
		if err := waitUntil(ctx, next); err != nil {
			return err
		}
		if late := time.Since(next); late > allowed {
			return fmt.Errorf("%w by %s", ErrDeadlineMissed, late)
		}
		if err := s.EmitOne(ctx); err != nil {
			if !errors.Is(err, ErrCellDropped) {
				return err
			}
			s.dropped.Add(1)
		}
		next = next.Add(interval)
		if !time.Now().Before(next) {
			return ErrDeadlineMissed
		}
	}
	return nil
}

// Dropped is the number of scheduled emissions lost to ErrCellDropped. It is
// local diagnostic state -- it is published in the node health file so an
// operator can see a failing link -- and it never feeds back into scheduling.
func (s *Scheduler) Dropped() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

func waitUntil(ctx context.Context, deadline time.Time) error {
	delay := time.Until(deadline)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
