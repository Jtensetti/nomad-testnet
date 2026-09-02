package fabric

import (
	"context"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"
)

func numberedCell(value uint64) Cell {
	var cell Cell
	binary.BigEndian.PutUint64(cell[:8], value)
	return cell
}

func cellNumber(cell Cell) uint64 { return binary.BigEndian.Uint64(cell[:8]) }

func TestQueueSourceIsBoundedFIFOAcrossWraparound(t *testing.T) {
	queue, err := NewQueueSource(3)
	if err != nil {
		t.Fatal(err)
	}
	for value := uint64(1); value <= 3; value++ {
		if !queue.Enqueue(numberedCell(value)) {
			t.Fatalf("enqueue %d rejected before capacity", value)
		}
	}
	if queue.Enqueue(numberedCell(99)) {
		t.Fatal("queue accepted a cell past its public capacity")
	}

	ctx := context.Background()
	for _, want := range []uint64{1, 2} {
		cell, err := queue.NextCell(ctx)
		if err != nil || cellNumber(cell) != want {
			t.Fatalf("dequeue: got %d, %v; want %d", cellNumber(cell), err, want)
		}
	}
	for _, value := range []uint64{4, 5} {
		if !queue.Enqueue(numberedCell(value)) {
			t.Fatalf("wraparound enqueue %d rejected", value)
		}
	}
	for _, want := range []uint64{3, 4, 5} {
		cell, err := queue.NextCell(ctx)
		if err != nil || cellNumber(cell) != want {
			t.Fatalf("wraparound dequeue: got %d, %v; want %d", cellNumber(cell), err, want)
		}
	}
	if _, err := queue.NextCell(ctx); !errors.Is(err, ErrNoWork) {
		t.Fatalf("empty queue returned %v, want ErrNoWork", err)
	}
}

func TestQueueSourceConcurrentProducerConsumerPreservesOrder(t *testing.T) {
	queue, err := NewQueueSource(8)
	if err != nil {
		t.Fatal(err)
	}
	const count = 2000
	done := make(chan struct{})
	go func() {
		defer close(done)
		for value := uint64(1); value <= count; {
			if queue.Enqueue(numberedCell(value)) {
				value++
				continue
			}
			runtime.Gosched()
		}
	}()

	ctx := context.Background()
	for want := uint64(1); want <= count; {
		cell, err := queue.NextCell(ctx)
		if errors.Is(err, ErrNoWork) {
			runtime.Gosched()
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := cellNumber(cell); got != want {
			t.Fatalf("got %d, want %d", got, want)
		}
		want++
	}
	<-done
}

func TestQueueSourceReservedProducerNeverBlocksConsumer(t *testing.T) {
	queue, err := NewQueueSource(2)
	if err != nil {
		t.Fatal(err)
	}

	// Reserve FIFO position zero exactly as Enqueue does, but intentionally do
	// not publish it yet. This models a producer being descheduled while copying
	// a cell. A deadline-path consumer must return ErrNoWork rather than wait.
	if !queue.enqueue.CompareAndSwap(0, 1) {
		t.Fatal("could not reserve first producer position")
	}
	if !queue.Enqueue(numberedCell(2)) {
		t.Fatal("second producer could not publish its bounded position")
	}
	if _, err := queue.NextCell(context.Background()); !errors.Is(err, ErrNoWork) {
		t.Fatalf("consumer crossed an unpublished FIFO position: %v", err)
	}

	queue.slots[0].cell = numberedCell(1)
	queue.slots[0].published.Store(1)
	for _, want := range []uint64{1, 2} {
		cell, err := queue.NextCell(context.Background())
		if err != nil || cellNumber(cell) != want {
			t.Fatalf("after publish got %d, %v; want %d", cellNumber(cell), err, want)
		}
	}
}
