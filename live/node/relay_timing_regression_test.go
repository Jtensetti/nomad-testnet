package node

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/wire"
)

// TestRelayProducerDoesNotModulateSchedulerCadence is the permanent regression
// for issue #6. It deliberately tests only the production boundary that issue
// #6 isolated: a public relay producer concurrently supplies work while the
// real Node scheduler emits its fixed-rate UDP stream.
//
// Private browser/search/reconstruction CPU and disk work do not belong in
// this process boundary. Their same-host process-isolation requirement is a
// separate system gate (issue #7). Keeping the two experiments separate makes
// a failure attributable instead of letting unrelated host load obscure a
// scheduler-visible producer coupling.
func TestRelayProducerDoesNotModulateSchedulerCadence(t *testing.T) {
	if testing.Short() {
		t.Skip("relay timing regression needs wall-clock time")
	}

	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)
	idle := campaignWorld{name: "relay-idle"}
	active := campaignWorld{name: "relay-producing", private: driveQueueOnly}
	baseline := campaignStressor{name: "relay-producer", run: func(context.Context, string) {}}

	controls := []*wire.Capture{
		{Label: "relay-queue-control-a"},
		{Label: "relay-queue-control-b"},
		{Label: "relay-queue-control-c"},
	}
	treatment := &wire.Capture{Label: "relay-queue-active"}

	for round := 0; round < campaignRounds; round++ {
		for _, control := range controls {
			runCampaignRound(t, network, identities, endpoints, idle, baseline, control)
		}
		runCampaignRound(t, network, identities, endpoints, active, baseline, treatment)
	}

	noise := worldGap{}
	for left := 0; left < len(controls); left++ {
		for right := left + 1; right < len(controls); right++ {
			noise = noise.widen(worldDistance(controls[left], controls[right]))
		}
	}
	signal := worldDistance(controls[0], treatment)
	for _, control := range controls[1:] {
		signal = signal.narrow(worldDistance(control, treatment))
	}

	root := filepath.Join("..", "..", "runtime", "evidence", "wire-campaign")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, capture := range append(append([]*wire.Capture{}, controls...), treatment) {
		writeCampaignCapture(t, root, capture)
	}

	record := struct {
		ControlSpread float64 `json:"control_spread"`
		Signal        float64 `json:"signal"`
		Tolerance     float64 `json:"tolerance"`
		Decision      string  `json:"decision"`
	}{
		ControlSpread: noise.cadence,
		Signal:        signal.cadence,
		Tolerance:     cadenceTolerance,
		Decision:      "PASS",
	}

	// A noisy host cannot establish either pass or failure at the target
	// resolution. Preserve the evidence and mark the test skipped rather than
	// converting host noise into a green privacy result.
	if noise.cadence >= cadenceTolerance {
		record.Decision = "UNDECIDABLE"
		writeRelayTimingEvidence(t, root, record)
		t.Skipf("relay timing regression undecidable: control spread %.4f reaches unchanged %.4f tolerance; signal %.4f",
			noise.cadence, cadenceTolerance, signal.cadence)
	}

	if signal.cadence > cadenceTolerance && signal.cadence > noise.cadence {
		record.Decision = "FAIL"
		writeRelayTimingEvidence(t, root, record)
		t.Fatalf("relay producer changed scheduler cadence by %.4f, above unchanged %.4f tolerance and %.4f control spread",
			signal.cadence, cadenceTolerance, noise.cadence)
	}

	writeRelayTimingEvidence(t, root, record)
	t.Logf("relay producer timing: PASS signal=%.4f control=%.4f tolerance=%.4f",
		signal.cadence, noise.cadence, cadenceTolerance)
}

func writeRelayTimingEvidence(t *testing.T, root string, record any) {
	t.Helper()
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(root, "RELAY_TIMING_REGRESSION.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
