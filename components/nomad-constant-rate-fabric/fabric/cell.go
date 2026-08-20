package fabric

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
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

// QueueSource is filled by public replication and cache-maintenance policy.
// It has no query or reader-state API.
//
// The queue is a preallocated ring. This is security-relevant rather than a
// throughput micro-optimization: the scheduler calls NextCell on its emission
// path, so producer activity must not make that call perform work proportional
// to queue depth. The previous slice implementation shifted every remaining
// 1200-byte cell on each dequeue while holding the producer mutex; a busy
// producer could therefore measurably change scheduler timing.
type QueueSource struct {
	mu    sync.Mutex
	cells []Cell
	head  int
	size  int
}

func NewQueueSource(capacity int) (*QueueSource, error) {
	if capacity < 1 {
		return nil, errors.New("queue capacity must be positive")
	}
	return &QueueSource{cells: make([]Cell, capacity)}, nil
}

func (q *QueueSource) Enqueue(cell Cell) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.size == len(q.cells) {
		return false
	}
	tail := (q.head + q.size) % len(q.cells)
	q.cells[tail] = cell
	q.size++
	return true
}

func (q *QueueSource) NextCell(context.Context) (Cell, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.size == 0 {
		return Cell{}, ErrNoWork
	}
	cell := q.cells[q.head]
	q.head++
	if q.head == len(q.cells) {
		q.head = 0
	}
	q.size--
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
