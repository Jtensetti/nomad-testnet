package hop

import (
	"errors"
	"sync"
)

var ErrReplay = errors.New("replayed or expired hop sequence")

// ReplayWindow accepts bounded UDP reordering while rejecting duplicates and
// old packets. A window is scoped to one signed topology epoch and one sender.
type ReplayWindow struct {
	mu          sync.Mutex
	initialized bool
	highest     uint32
	bitmap      uint64
}

func (window *ReplayWindow) Accept(sequence uint32) error {
	if sequence == 0 {
		return ErrReplay
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	if !window.initialized {
		window.initialized = true
		window.highest = sequence
		window.bitmap = 1
		return nil
	}
	if sequence > window.highest {
		shift := sequence - window.highest
		if shift >= 64 {
			window.bitmap = 1
		} else {
			window.bitmap = window.bitmap<<shift | 1
		}
		window.highest = sequence
		return nil
	}
	delta := window.highest - sequence
	if delta >= 64 || window.bitmap&(uint64(1)<<delta) != 0 {
		return ErrReplay
	}
	window.bitmap |= uint64(1) << delta
	return nil
}
