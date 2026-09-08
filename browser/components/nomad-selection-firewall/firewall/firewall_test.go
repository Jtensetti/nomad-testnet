package firewall

import (
	"crypto/sha256"
	"reflect"
	"testing"
	"time"
)

func testConfig() NetworkConfig {
	return NetworkConfig{
		CellsPerEpoch: 32,
		CellSize:      1200,
		CellInterval:  10 * time.Millisecond,
		PeerSlots:     8,
		PublicSeed:    sha256.Sum256([]byte("selection-firewall-test-seed")),
	}
}

func TestPlanShape(t *testing.T) {
	cfg := testConfig()
	plan, err := Plan(cfg, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != int(cfg.CellsPerEpoch) {
		t.Fatalf("got %d emissions, want %d", len(plan), cfg.CellsPerEpoch)
	}
	for i, emission := range plan {
		if emission.Epoch != 42 || emission.Slot != uint32(i) || emission.Size != cfg.CellSize {
			t.Fatalf("invalid emission %d: %#v", i, emission)
		}
		if emission.CadenceIndex != uint64(42*cfg.CellsPerEpoch)+uint64(i) {
			t.Fatalf("invalid cadence index at %d: %d", i, emission.CadenceIndex)
		}
		if emission.Offset != time.Duration(i)*cfg.CellInterval {
			t.Fatalf("invalid offset at %d: %s", i, emission.Offset)
		}
		if emission.PeerSlot >= cfg.PeerSlots {
			t.Fatalf("peer slot %d out of range", emission.PeerSlot)
		}
	}
}

func TestCadenceHasNoEpochBoundaryGap(t *testing.T) {
	cfg := testConfig()
	a, err := Plan(cfg, 7)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Plan(cfg, 8)
	if err != nil {
		t.Fatal(err)
	}
	if b[0].CadenceIndex != a[len(a)-1].CadenceIndex+1 {
		t.Fatal("cadence index has an epoch boundary gap")
	}
	duration, err := cfg.EpochDuration()
	if err != nil {
		t.Fatal(err)
	}
	if duration-a[len(a)-1].Offset != cfg.CellInterval {
		t.Fatal("wire cadence has an epoch boundary gap")
	}
}

func TestPlanDeterministicForSamePublicInputs(t *testing.T) {
	cfg := testConfig()
	a, err := Plan(cfg, 42)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Plan(cfg, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same public inputs produced different plans")
	}
	if ObservableDigest(a) != ObservableDigest(b) {
		t.Fatal("same public inputs produced different observable digests")
	}
}

func TestPeerSequenceDependsOnEpoch(t *testing.T) {
	cfg := testConfig()
	a, err := Plan(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Plan(cfg, 2)
	if err != nil {
		t.Fatal(err)
	}
	same := true
	for i := range a {
		if a[i].PeerSlot != b[i].PeerSlot {
			same = false
			break
		}
	}
	if same {
		t.Fatal("peer-slot sequence did not change across epochs")
	}
}

func TestInvalidConfig(t *testing.T) {
	cases := []NetworkConfig{
		{},
		{CellsPerEpoch: 1, CellSize: 1200, CellInterval: time.Second},
		{CellsPerEpoch: 1, PeerSlots: 1, CellInterval: time.Second},
		{CellSize: 1200, PeerSlots: 1, CellInterval: time.Second},
		{CellsPerEpoch: 1, CellSize: 1200, PeerSlots: 1},
		{CellsPerEpoch: MaxCellsPerEpoch + 1, CellSize: 1200, CellInterval: time.Second, PeerSlots: 1},
		{CellsPerEpoch: 2, CellSize: 1200, CellInterval: time.Duration(1<<63 - 1), PeerSlots: 1},
	}
	for _, cfg := range cases {
		if _, err := Plan(cfg, 0); err == nil {
			t.Fatalf("expected validation error for %#v", cfg)
		}
	}
}

func TestPlanRejectsCadenceIndexOverflow(t *testing.T) {
	cfg := testConfig()
	if _, err := Plan(cfg, ^uint64(0)); err == nil {
		t.Fatal("expected cadence index overflow error")
	}
}
