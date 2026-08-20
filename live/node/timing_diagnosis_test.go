package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/wire"
)

// timingDiagnosisRecord is evidence only. The preregistered campaign in
// campaign_test.go remains the gate; this test decomposes its treatment so a
// finding can be attributed instead of being waved away as runner noise.
type timingDiagnosisRecord struct {
	Treatment     string  `json:"treatment"`
	ControlSpread float64 `json:"control_spread"`
	Signal        float64 `json:"signal"`
	Tolerance     float64 `json:"tolerance"`
	Finding       bool    `json:"finding"`
}

func TestTimingShiftDiagnosis(t *testing.T) {
	if testing.Short() {
		t.Skip("timing diagnosis needs wall-clock time")
	}
	network, identities, endpoints := nodeTestTopologyWithCadence(
		t, campaignIntervalMillis, campaignLateness, singlePeerPlan)

	treatments := []campaignWorld{
		{name: "queue-static", private: driveStaticQueue},
		{name: "queue-only", private: driveQueueOnly},
		{name: "compute-only", private: driveComputeOnly},
		{name: "disk-only", private: driveDiskOnly},
		{name: "full-active", private: drivePrivateActivity},
	}
	baseline := campaignStressor{name: "diagnosis", run: func(context.Context, string) {}}
	records := make([]timingDiagnosisRecord, 0, len(treatments))

	for _, treatmentWorld := range treatments {
		controls := []*wire.Capture{
			{Label: treatmentWorld.name + "-control-a"},
			{Label: treatmentWorld.name + "-control-b"},
			{Label: treatmentWorld.name + "-control-c"},
		}
		treatment := &wire.Capture{Label: treatmentWorld.name + "-treatment"}
		idle := campaignWorld{name: "idle"}

		for round := 0; round < campaignRounds; round++ {
			for _, control := range controls {
				runCampaignRound(t, network, identities, endpoints, idle, baseline, control)
			}
			runCampaignRound(t, network, identities, endpoints, treatmentWorld, baseline, treatment)
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
		record := timingDiagnosisRecord{
			Treatment: treatmentWorld.name, ControlSpread: noise.cadence,
			Signal: signal.cadence, Tolerance: cadenceTolerance,
			Finding: noise.cadence < cadenceTolerance && signal.cadence > cadenceTolerance && signal.cadence > noise.cadence,
		}
		records = append(records, record)
		t.Logf("timing diagnosis %s: signal=%.4f control=%.4f tolerance=%.4f finding=%t",
			record.Treatment, record.Signal, record.ControlSpread, record.Tolerance, record.Finding)
	}

	root := filepath.Join("..", "..", "runtime", "evidence", "wire-campaign")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(root, "TIMING_DIAGNOSIS.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

// driveStaticQueue fills the public work queue once, then becomes inert. It
// isolates the work-vs-cover source path from concurrent queue contention and
// from unrelated private CPU/disk activity.
func driveStaticQueue(ctx context.Context, node *Node, _ string) {
	cell, ok := diagnosticCell()
	if !ok {
		return
	}
	for index := 0; index < 32; index++ {
		node.queue.Enqueue(cell)
	}
	<-ctx.Done()
}

// driveQueueOnly keeps the same public work queue busy as the original active
// world but does no hashing and no file I/O. If this alone crosses the gate,
// the transport work-source path is the suspect.
func driveQueueOnly(ctx context.Context, node *Node, _ string) {
	cell, ok := diagnosticCell()
	if !ok {
		return
	}
	for ctx.Err() == nil {
		node.queue.Enqueue(cell)
		time.Sleep(2 * time.Millisecond)
	}
}

// driveComputeOnly consumes the same class of local CPU work but never touches
// the Node or its queue. A finding here points at same-process/runtime resource
// sharing rather than a private input to the transport API.
func driveComputeOnly(ctx context.Context, _ *Node, _ string) {
	digest := sha256.Sum256([]byte("nomad-timing-diagnosis"))
	for ctx.Err() == nil {
		for round := 0; round < 64; round++ {
			digest = sha256.Sum256(digest[:])
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// driveDiskOnly performs private local persistence without touching Node or
// doing the hash loop. A finding here isolates scheduler sensitivity to local
// filesystem activity on the same process/host.
func driveDiskOnly(ctx context.Context, _ *Node, scratch string) {
	private := filepath.Join(scratch, "diagnosis-disk")
	if err := os.MkdirAll(private, 0o700); err != nil {
		return
	}
	payload := []byte("nomad-private-local-persistence-diagnosis")
	counter := 0
	for ctx.Err() == nil {
		counter++
		_ = os.WriteFile(filepath.Join(private, fmt.Sprintf("object-%d", counter%16)), payload, 0o600)
		time.Sleep(2 * time.Millisecond)
	}
}

func diagnosticCell() (cell [1200]byte, ok bool) {
	var payload [hop.CiphertextSize]byte
	if _, err := rand.Read(payload[:]); err != nil {
		return cell, false
	}
	metadata, err := hop.WorkMetadata(hop.StreamID{15: 1}, 0, 2)
	if err != nil {
		return cell, false
	}
	built, err := hop.FromCiphertext(payload, metadata)
	if err != nil {
		return cell, false
	}
	return built, true
}
