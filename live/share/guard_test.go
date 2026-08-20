package share

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func windowGuard(epoch uint64, notBefore, notAfter time.Time) TopologyWindowGuard {
	return TopologyWindowGuard{Network: topology.Verified{Document: topology.Document{
		Epoch:     epoch,
		NotBefore: notBefore.UTC().Format(time.RFC3339),
		NotAfter:  notAfter.UTC().Format(time.RFC3339),
	}}}
}

func TestTopologyWindowGuardRefusesRetiredAndUnstartedEpochs(t *testing.T) {
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	guard := windowGuard(7, start, end)

	if err := guard.ServesEpoch(7, start.Add(-time.Second)); err == nil {
		t.Fatal("work before the epoch starts must be refused")
	}
	if err := guard.ServesEpoch(7, start); err != nil {
		t.Fatalf("work at the opening boundary must be allowed: %v", err)
	}
	if err := guard.ServesEpoch(7, end.Add(-time.Second)); err != nil {
		t.Fatalf("work inside the window must be allowed: %v", err)
	}
	if err := guard.ServesEpoch(7, end); err == nil {
		t.Fatal("work at the retirement boundary must be refused")
	}
	if err := guard.ServesEpoch(7, end.Add(24*time.Hour)); err == nil {
		t.Fatal("a retired epoch must stay refused")
	}
	if err := guard.ServesEpoch(8, start.Add(time.Minute)); err == nil {
		t.Fatal("an epoch this operator does not serve must be refused")
	}
}

type denyingGuard struct{ err error }

func (guard denyingGuard) ServesEpoch(uint64, time.Time) error { return guard.err }

func TestProcessOnceRefusesWithoutGuardAndWhenRetired(t *testing.T) {
	// A nil guard must fail closed rather than being read as "allowed".
	service := Service{OutputDir: t.TempDir()}
	if _, err := service.ProcessOnce(); err == nil {
		t.Fatal("a share service without a cache must fail")
	}
	service = Service{Cache: nil, OutputDir: t.TempDir()}
	if _, err := service.ProcessOnce(); err == nil {
		t.Fatal("missing cache must fail before any threshold work")
	}

	retired := errors.New("epoch is retired")
	guarded := Service{OutputDir: t.TempDir(), Guard: denyingGuard{err: retired}}
	if _, err := guarded.ProcessOnce(); err == nil {
		t.Fatal("a refused epoch must stop threshold work")
	}
}

func TestHTTPHandlerRefusesPreviouslyGeneratedPartialAfterRetirement(t *testing.T) {
	service := Service{
		Descriptor: batch.VerifiedDescriptor{
			Descriptor: batch.Descriptor{StreamID: "test-stream"},
			Committee:  mix.ThresholdCommittee{Epoch: 7},
		},
		Secret:    mix.MemberSecret{Index: 1},
		OutputDir: t.TempDir(),
		Guard:     denyingGuard{err: errors.New("epoch is retired")},
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/partial/test-stream/1", nil)
	response := httptest.NewRecorder()
	service.handler().ServeHTTP(response, request)
	if response.Code != http.StatusGone {
		t.Fatalf("retired partial endpoint must fail closed with 410, got %d", response.Code)
	}
}
