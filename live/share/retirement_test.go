package share

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
)

type retirementDenyingGuard struct{}

func (retirementDenyingGuard) ServesEpoch(uint64, time.Time) error {
	return epoch.ErrEpochNotActive
}

func TestRetiredShareServiceExitsCleanlyInsteadOfRestarting(t *testing.T) {
	cache, err := rawcache.Open(filepath.Join(t.TempDir(), "raw"), 8)
	if err != nil {
		t.Fatal(err)
	}
	service := Service{
		Cache: cache,
		Descriptor: batch.VerifiedDescriptor{
			Committee: mix.ThresholdCommittee{Epoch: 7},
		},
		OutputDir: t.TempDir(), Interval: time.Second,
		ListenAddress: "127.0.0.1:0", Guard: retirementDenyingGuard{},
	}
	if err := service.Run(context.Background()); err != nil {
		t.Fatalf("normal public retirement looked like a crash: %v", err)
	}
}

func TestHTTPDoesNotServeExistingPartialAfterRetirement(t *testing.T) {
	output := t.TempDir()
	service := Service{
		Descriptor: batch.VerifiedDescriptor{
			Descriptor: batch.Descriptor{StreamID: "stream-test"},
			Committee:  mix.ThresholdCommittee{Epoch: 7},
		},
		Secret:    mix.MemberSecret{Index: 0},
		OutputDir: output,
		Guard:     retirementDenyingGuard{},
	}
	path := filepath.Join(output, "stream-test-00.partial.json")
	if err := os.WriteFile(path, []byte(`{"already":"there"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/partial/stream-test/0", nil)
	response := httptest.NewRecorder()
	service.handler().ServeHTTP(response, request)
	if response.Code != http.StatusGone {
		t.Fatalf("retired epoch served an existing partial: status %d", response.Code)
	}
}
