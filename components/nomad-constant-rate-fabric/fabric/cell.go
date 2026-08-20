package fabric

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync/atomic"
)

const CellSize = 1200

// Cell is the fixed-size unit emitted by the research traffic shaper.
type Cell [CellSize]byte

func RandomCell() (Cell, error) {
	return RandomCellFrom(rand.Reader)
}

func RandomCellFrom(r io.Reader) (Cell, error) {
	if r == nil {
		return Cell{}, errors.New("random source is required")
	}
	var c Cell
	_, err := io.ReadFull(r, c[:])
	return c, err
}

var ErrNoWork = errors.New("no protocol work available")

type queueSlot struct {
	// published is position+1 when cell is ready for the consumer. A producer
	// reserves its position before copying the 1200-byte cell, so the consumer
	// can observe a reserved-but-not-ready slot and return cover immediately
	// instead of waiting on producer work.
	published atomic.Uint64
	cell      Cell
}

// QueueSource is filled by public replication and cache-maintenance policy.
// It has no query or reader-state API.
//
// There is deliberately no producer/consumer mutex. Producers reserve bounded
// positions with enqueue CAS, copy outside the scheduler path, then publish the
// slot with a sequentially-consistent atomic store. The scheduler is the single
// consumer: it only reads the next already-published slot. If the queue is
// empty, or the oldest reserved producer has not published yet, NextCell returns
// ErrNoWork immediately and CoverSource supplies filler for that public slot.
// It never waits for useful work.
//
// This fail-open-to-cover behavior is security-relevant. Producer scheduling,
// queue depth and producer stalls may decide whether a slot carries work or
// cover, but they cannot hold the scheduler's deadline path behind a lock.
type QueueSource struct {
	capacity uint64
	slots    []queueSlot
	enqueue  atomic.Uint64
	dequeue  atomic.Uint64
}

func NewQueueSource(capacity int) (*QueueSource, error) {
	if capacity < 1 {
		return nil, errors.New("queue capacity must be positive")
	}
	return &QueueSource{capacity: uint64(capacity), slots: make([]queueSlot, capacity)}, nil
}

func (q *QueueSource) Enqueue(cell Cell) bool {
	if q == nil || q.capacity == 0 {
		return false
	}
	for {
		position := q.enqueue.Load()
		consumed := q.dequeue.Load()
		if position-consumed >= q.capacity {
			return false
		}
		if !q.enqueue.CompareAndSwap(position, position+1) {
			continue
		}
		slot := &q.slots[position%q.capacity]
		slot.cell = cell
		// Publishing after the cell copy is the handoff to the consumer.
		slot.published.Store(position + 1)
		return true
	}
}

func (q *QueueSource) NextCell(context.Context) (Cell, error) {
	if q == nil || q.capacity == 0 {
		return Cell{}, ErrNoWork
	}
	position := q.dequeue.Load()
	if position >= q.enqueue.Load() {
		return Cell{}, ErrNoWork
	}
	slot := &q.slots[position%q.capacity]
	if slot.published.Load() != position+1 {
		// A producer reserved this FIFO position but has not published it yet.
		// Do not spin, sleep, lock, skip ahead, or otherwise let producer timing
		// extend this emission slot. CoverSource will emit filler instead.
		return Cell{}, ErrNoWork
	}
	cell := slot.cell
	// The queue has one consumer (the scheduler). Advance only after copying the
	// cell so a wrapped producer cannot reuse the slot while it is being read.
	q.dequeue.Store(position + 1)
	return cell, nil
}

// CoverSource turns an unavailable work source into a filler cell without
// changing the scheduler. The fallback count is diagnostic state only.
type CoverSource struct {
	Work     Source
	Filler   Source
	fallback atomic.Uint64
}

func (s *CoverSource) NextCell(ctx context.Context) (Cell, error) {
	if s == nil || s.Filler == nil {
		return Cell{}, errors.New("filler source is required")
	}
	if s.Work != nil {
		if cell, err := s.Work.NextCell(ctx); err == nil {
			return cell, nil
		}
	}
	s.fallback.Add(1)
	return s.Filler.NextCell(ctx)
}

func (s *CoverSource) Fallbacks() uint64 {
	if s == nil {
		return 0
	}
	return s.fallback.Load()
}
