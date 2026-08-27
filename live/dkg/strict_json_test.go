package dkgnet

import (
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func TestDKGArtifactsRejectDuplicateJSONKeys(t *testing.T) {
	encoded := []byte(`{"version":"first","version":"second"}`)
	if _, _, err := DecodeEnvelope(encoded, topology.Verified{}); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate envelope key was not rejected: %v", err)
	}
	var destination map[string]any
	if err := strictJSON(encoded, &destination); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate packet key was not rejected: %v", err)
	}
}
