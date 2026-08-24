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
