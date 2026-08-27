package fabric

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type byteSource byte

func (s byteSource) NextCell(context.Context) (Cell, error) {
	var c Cell
	for i := range c {
		c[i] = byte(s)
	}
	return c, nil
}

type recordingSink struct {
	cells []Cell
	at    []time.Time
}

func (s *recordingSink) Send(_ context.Context, c Cell) error {
	s.cells = append(s.cells, c)
	s.at = append(s.at, time.Now())
	return nil
}

func TestCellInterval(t *testing.T) {
	cfg := Config{Epoch: 100 * time.Millisecond, CellsPerEpoch: 16}
	if got, want := cfg.CellInterval(), 6250*time.Microsecond; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// The claim here is that four cells arrive as a cadence rather than a burst.
// It is not a claim about how fast the host is.
//
// Those come apart on a loaded machine. When a stall pushes an emission past
// MaxLateness the scheduler returns ErrDeadlineMissed, which is the production
// code doing exactly what it should: refusing to emit a catch-up burst. Failing
// the test on that outcome turns it into an assertion that the host never
// stalls, and it duly failed once in a full-repository sweep at 42 ms over a
// 40 ms budget, while a full race-instrumented crypto suite ran alongside it.
//
// So a missed deadline means this test could not run, and it says so loudly
// rather than passing quietly or failing for the wrong reason. Every other
// error is still a failure, and the burst assertion below is unchanged.
func TestRunCellsUsesCadenceInsteadOfBurst(t *testing.T) {
	cfg := Config{Epoch: 80 * time.Millisecond, CellsPerEpoch: 4, MaxLateness: 40 * time.Millisecond}
	sink := &recordingSink{}
	scheduler, err := NewScheduler(cfg, byteSource(0x11), sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := scheduler.RunCells(ctx, 4); err != nil {
		if errors.Is(err, ErrDeadlineMissed) {
			t.Skipf("the host could not hold a %s cadence within %s, so this run "+
				"measures the machine rather than the scheduler: %v",
				cfg.CellInterval(), cfg.MaxLateness, err)
		}
		t.Fatal(err)
	}
	if len(sink.cells) != 4 {
		t.Fatalf("got %d cells", len(sink.cells))
	}
	elapsed := sink.at[len(sink.at)-1].Sub(sink.at[0])
	if elapsed < 45*time.Millisecond {
		t.Fatalf("four cells were emitted as a burst: span %s", elapsed)
	}
}

type failingSource struct{}

func (failingSource) NextCell(context.Context) (Cell, error) {
	return Cell{}, errors.New("work source failed")
}

func TestCoverSourceUsesFillerWithoutChangingEmissionCount(t *testing.T) {
	cover := &CoverSource{Work: failingSource{}, Filler: byteSource(0xee)}
	sink := &recordingSink{}
	scheduler, err := NewScheduler(Config{Epoch: time.Second, CellsPerEpoch: 2}, cover, sink)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if err := scheduler.EmitOne(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if cover.Fallbacks() != 8 || len(sink.cells) != 8 {
		t.Fatalf("fallbacks=%d cells=%d", cover.Fallbacks(), len(sink.cells))
	}
	if !bytes.Equal(sink.cells[0][:], bytes.Repeat([]byte{0xee}, CellSize)) {
		t.Fatal("fallback source did not fill the cell")
	}
}

func TestQueueSourceIsBounded(t *testing.T) {
	queue, err := NewQueueSource(1)
	if err != nil {
		t.Fatal(err)
	}
	var cell Cell
	cell[0] = 7
	if !queue.Enqueue(cell) {
		t.Fatal("first enqueue failed")
	}
	if queue.Enqueue(cell) {
		t.Fatal("queue exceeded its public capacity")
	}
	got, err := queue.NextCell(context.Background())
	if err != nil || got != cell {
		t.Fatalf("got cell=%v err=%v", got[0], err)
	}
	if _, err := queue.NextCell(context.Background()); !errors.Is(err, ErrNoWork) {
		t.Fatalf("got %v, want ErrNoWork", err)
	}
}

func TestUDPObserverSeesFixedSizeSpacedDatagrams(t *testing.T) {
	observer, err := ListenUDPObserver(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	sink, err := NewUDPSink(sender, []*net.UDPAddr{observer.LocalAddr()}, []uint16{0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := NewQueueSource(4)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		var cell Cell
		cell[0] = byte(i)
		if !queue.Enqueue(cell) {
			t.Fatal("enqueue failed")
		}
	}
	scheduler, err := NewScheduler(
		Config{Epoch: 80 * time.Millisecond, CellsPerEpoch: 4, MaxLateness: 40 * time.Millisecond},
		&CoverSource{Work: queue, Filler: RandomSource{}},
		sink,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type captureResult struct {
		observations []Observation
		err          error
	}
	captured := make(chan captureResult, 1)
	go func() {
		observations, err := observer.Capture(ctx, 4)
		captured <- captureResult{observations: observations, err: err}
	}()
	if err := scheduler.RunCells(ctx, 4); err != nil {
		t.Fatal(err)
	}
	result := <-captured
	if result.err != nil {
		t.Fatal(result.err)
	}
	if span := result.observations[3].ReceivedAt.Sub(result.observations[0].ReceivedAt); span < 45*time.Millisecond {
		t.Fatalf("observer saw a burst: span %s", span)
	}
	for i, observation := range result.observations {
		if observation.Size != CellSize || observation.Cell[0] != byte(i) {
			t.Fatalf("observation %d: size=%d first=%d", i, observation.Size, observation.Cell[0])
		}
	}
}

func TestEpochTraceMatchesConfiguredShape(t *testing.T) {
	cfg := Config{Epoch: time.Second, CellsPerEpoch: 16}
	trace, err := EpochTrace(cfg, 10)
	if err != nil {
		t.Fatal(err)
	}
	for i, bytes := range trace {
		if bytes != 16*CellSize {
			t.Fatalf("epoch %d: got %d bytes", i, bytes)
		}
	}
}

func TestInvalidConfig(t *testing.T) {
	cases := []Config{
		{},
		{Epoch: time.Second},
		{CellsPerEpoch: 1},
		{Epoch: time.Nanosecond, CellsPerEpoch: 2},
		{Epoch: 10 * time.Nanosecond, CellsPerEpoch: 3},
		{Epoch: time.Second, CellsPerEpoch: 1, MaxLateness: -1},
	}
	for _, cfg := range cases {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected validation error for %#v", cfg)
		}
	}
}
