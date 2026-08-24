package committee

import (
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func TestCommitteeArtifactsRejectDuplicateJSONKeys(t *testing.T) {
	encoded := []byte(`{"version":"first","version":"second"}`)
	if _, _, err := Decode(encoded, topology.Verified{}); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate certificate key was not rejected: %v", err)
	}
	if _, err := VerifyShare(encoded, Verified{}, topology.Verified{}); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate share key was not rejected: %v", err)
	}
}
