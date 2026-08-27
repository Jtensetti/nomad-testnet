package main

import (
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/rotation"
)

func TestNextWakeUsesPublicLifecycleDeadline(t *testing.T) {
	now := time.Date(2026, 8, 21, 4, 0, 0, 0, time.UTC)
	due := now.Add(17 * time.Minute)
	for _, status := range []string{rotation.StatusIdle, rotation.StatusAwaitActivation} {
		if got := nextWake(now, rotation.Outcome{Status: status, DueAt: due}, 30*time.Second); !got.Equal(due) {
			t.Fatalf("%s wake = %s, want public deadline %s", status, got, due)
		}
	}
}

func TestNextWakeUsesUTCAlignedControlGrid(t *testing.T) {
	now := time.Date(2026, 8, 21, 4, 0, 17, 250_000_000, time.UTC)
	got := nextWake(now, rotation.Outcome{Status: rotation.StatusDKGComplete}, 30*time.Second)
	want := time.Date(2026, 8, 21, 4, 0, 30, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("aligned wake = %s, want %s", got, want)
	}
}

func TestAlignedGridDoesNotDependOnOutcomePayload(t *testing.T) {
	now := time.Date(2026, 8, 21, 4, 0, 1, 0, time.UTC)
	first := nextWake(now, rotation.Outcome{Status: rotation.StatusRetire, Reason: "a"}, time.Minute)
	second := nextWake(now, rotation.Outcome{Status: rotation.StatusRetire, Reason: "different public log text", Epoch: 99}, time.Minute)
	if !first.Equal(second) {
		t.Fatalf("control-grid wake changed with non-schedule outcome fields: %s != %s", first, second)
	}
}

func TestNextWakeSkipsHistoricalGridTicksWithoutCatchUp(t *testing.T) {
	loopStarted := time.Date(2026, 8, 21, 4, 0, 1, 0, time.UTC)
	processingFinished := loopStarted.Add(95 * time.Second)
	got := nextWake(processingFinished, rotation.Outcome{Status: rotation.StatusDKGComplete}, 30*time.Second)
	want := time.Date(2026, 8, 21, 4, 2, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("post-processing wake = %s, want next future grid tick %s", got, want)
	}
	if !got.After(processingFinished) {
		t.Fatal("controller scheduled a historical catch-up tick")
	}
}

func TestControlBindingUsesReservedSuccessorPort(t *testing.T) {
	for _, test := range []struct {
		name    string
		dkg     string
		control string
		valid   bool
	}{
		{name: "IPv4", dkg: "127.0.0.1:6100", control: "127.0.0.1:6101", valid: true},
		{name: "IPv6", dkg: "[::]:6200", control: "[::]:6201", valid: true},
		{name: "wrong port", dkg: ":6100", control: ":6102"},
		{name: "no successor port", dkg: ":65535", control: ":1"},
		{name: "missing port", dkg: "127.0.0.1", control: "127.0.0.1:6101"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateControlBinding(test.dkg, test.control)
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid lifecycle binding was accepted")
			}
		})
	}
}
