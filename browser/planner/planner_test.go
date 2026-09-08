package planner

import (
	"reflect"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-selection-firewall/firewall"
)

func TestPlanDelegatesPublicConfig(t *testing.T) {
	cfg := firewall.NetworkConfig{
		CellsPerEpoch: 16,
		CellSize:      1200,
		CellInterval:  10 * time.Millisecond,
		PeerSlots:     4,
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Plan(42)
	if err != nil {
		t.Fatal(err)
	}
	want, err := firewall.Plan(cfg, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("planner changed the public emission plan")
	}
}
