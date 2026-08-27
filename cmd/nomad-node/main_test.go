package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitUntilPublicActivationReturnsImmediatelyForPastBoundary(t *testing.T) {
	started := time.Now()
	if err := waitUntilPublicActivation(context.Background(), time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("wait past activation: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("past activation waited unexpectedly: %v", elapsed)
	}
}

func TestWaitUntilPublicActivationHonorsPublicBoundary(t *testing.T) {
	activateAt := time.Now().Add(40 * time.Millisecond)
	started := time.Now()
	if err := waitUntilPublicActivation(context.Background(), activateAt); err != nil {
		t.Fatalf("wait for activation: %v", err)
	}
	if elapsed := time.Since(started); elapsed < 25*time.Millisecond {
		t.Fatalf("activation wait returned too early: %v", elapsed)
	}
}

func TestWaitUntilPublicActivationCanBeStoppedWithoutWaitingForBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err := waitUntilPublicActivation(ctx, time.Now().Add(time.Hour))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wait after cancellation = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("cancelled activation wait did not stop promptly: %v", elapsed)
	}
}

func TestWaitUntilPublicActivationRejectsNilContext(t *testing.T) {
	if err := waitUntilPublicActivation(nil, time.Now()); err == nil {
		t.Fatal("nil context unexpectedly accepted")
	}
}
