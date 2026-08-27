package ceremony

import (
	"strings"
	"testing"
)

func TestCeremonyArtifactsRejectDuplicateJSONKeys(t *testing.T) {
	encoded := []byte(`{"version":"first","version":"second"}`)
	var destination map[string]any
	if err := strictJSON(encoded, &destination); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate ceremony key was not rejected: %v", err)
	}
}
