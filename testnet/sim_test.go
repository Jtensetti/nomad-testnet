package testnet

import (
	"context"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-selection-firewall/firewall"
	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

func TestEndToEndReferenceStackFromCapturedUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	content := []byte("A signed Nomad object about Iranian military systems, reconstructed only from captured coded cells.")
	result, err := Run(ctx, content, "Iran military weapons systems geopolitics", "weapons systems in Iran military")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Reconstructed || !result.ShuffleProofsVerified {
		t.Fatal("object was not cryptographically shuffled and reconstructed")
	}
	if !result.ReaderTraceIdentical {
		t.Fatal("private selection changed the observed network trace")
	}
	if !result.IdleCadenceValid || !result.ActiveCadenceValid {
		t.Fatalf("invalid cadence: idle=%v active=%v", result.IdleCadenceValid, result.ActiveCadenceValid)
	}
	if result.WireCellsObserved != testCellsPerEpoch || result.WireCellSize != 1200 {
		t.Fatalf("unexpected wire profile: cells=%d size=%d", result.WireCellsObserved, result.WireCellSize)
	}
	if result.ConstantBytesPerEpoch != testCellsPerEpoch*1200 {
		t.Fatalf("unexpected visible epoch size: %d", result.ConstantBytesPerEpoch)
	}
	if result.MixRounds != testMixMembers || result.MixedBatch != testCellsPerEpoch {
		t.Fatalf("unexpected mix result: rounds=%d batch=%d", result.MixRounds, result.MixedBatch)
	}
}

func TestIranAndSourdoughQueriesHaveSameCapturedTrace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := firewall.NetworkConfig{
		CellsPerEpoch: testCellsPerEpoch,
		CellSize:      fabric.CellSize,
		CellInterval:  testCellInterval,
		PeerSlots:     testPeerSlots,
		PublicSeed:    sha256.Sum256([]byte("two-query-public-plan")),
	}
	plan, err := firewall.Plan(cfg, 99)
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]mix.WireCell, testCellsPerEpoch)
	for i := range cells {
		for j := range cells[i] {
			cells[i][j] = byte(i+1) ^ byte(j) ^ byte(j>>8)
		}
	}
	embedder := basin.LexicalHashEmbedder{Dims: 512}
	quantizer := basin.Quantizer{Seed: sha256.Sum256([]byte("two-query-basin-profile"))}
	activityFor := func(query string) activityFunc {
		return func(activityContext context.Context) (privateActivity, error) {
			vector, err := embedder.Embed(activityContext, query)
			if err != nil {
				return privateActivity{}, err
			}
			id, err := quantizer.Basin(vector)
			return privateActivity{queryBasin: id}, err
		}
	}
	iran, err := captureWorld(ctx, cells, cfg, plan, activityFor("Iran military systems"))
	if err != nil {
		t.Fatal(err)
	}
	sourdough, err := captureWorld(ctx, cells, cfg, plan, activityFor("sourdough pizza"))
	if err != nil {
		t.Fatal(err)
	}
	if iran.activity.queryBasin == sourdough.activity.queryBasin {
		t.Fatal("distinct private queries unexpectedly produced the same basin")
	}
	if !iran.cadenceValid || !sourdough.cadenceValid {
		t.Fatal("one of the two query worlds violated wire cadence")
	}
	if iran.planDigest != sourdough.planDigest || !reflect.DeepEqual(iran.shapes, sourdough.shapes) {
		t.Fatal("private query changed count, size, payload, peer selection, or public plan")
	}
}

func TestSingleGenerationProfileRejectsOversizedObject(t *testing.T) {
	if _, err := chooseSymbolSize(1 << 20); err == nil {
		t.Fatal("expected oversized generation to be rejected")
	}
}
