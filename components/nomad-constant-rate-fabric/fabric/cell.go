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
	if _, err := io.ReadFull(r, c[:]); err != nil {
		// The zero value, not the partially filled cell. A short read leaves
		// entropy in the prefix and zeros in the tail, and a caller that
		// ignored the error would emit a cover cell with a constant tail --
		// which is the one thing cover must not have. Every caller here does
		// check, so this is depth rather than a live defect, and it is one
		// line either way.
		return Cell{}, err
	}
	return c, nil
}

var ErrNoWork = errors.New("no protocol work available")

// QueueSource is filled by public replication and cache-maintenance policy.
// It has no query or reader-state API.
type QueueSource struct {
	mu       sync.Mutex
	capacity int
	cells    []Cell
}

func NewQueueSource(capacity int) (*QueueSource, error) {
	if capacity < 1 {
		return nil, errors.New("queue capacity must be positive")
	}
	return &QueueSource{capacity: capacity}, nil
}

func (q *QueueSource) Enqueue(cell Cell) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.cells) == q.capacity {
		return false
	}
	q.cells = append(q.cells, cell)
	return true
}

func (q *QueueSource) NextCell(context.Context) (Cell, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.cells) == 0 {
		return Cell{}, ErrNoWork
	}
	cell := q.cells[0]
	copy(q.cells, q.cells[1:])
	q.cells = q.cells[:len(q.cells)-1]
	return cell, nil
}

// Len is the number of cells waiting. It is local diagnostic state, used to
// check that the bound is enforced rather than to make any scheduling
// decision: nothing on the emission path may consult it, because a rate that
// responds to queue depth is a rate that reports it.
func (q *QueueSource) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.cells)
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
