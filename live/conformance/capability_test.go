package conformance_test

import (
	"os"
	"os/exec"
	"testing"
)

// requireSecondImplementation returns the interpreter the second
// implementation runs under.
//
// A skip is green. A gate that quietly stopped running -- an image that no
// longer ships python3, a runner image change -- is indistinguishable from a
// gate that passed, and PROD-03's evidence would go on citing a
// cross-implementation check that had not executed in months. Where the
// environment has declared the capability, its absence is a failure.
func requireSecondImplementation(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err == nil {
		return python
	}
	if os.Getenv("NOMAD_REQUIRE_CAPABILITY_GATES") == "1" {
		t.Fatal("python3 is unavailable, and NOMAD_REQUIRE_CAPABILITY_GATES=1 says " +
			"this environment is supposed to run the second implementation. " +
			"Skipping here would report what passing reports.")
	}
	t.Skip("python3 is not available, so the second implementation cannot be run; " +
		"an environment limit and not a pass")
	return ""
}
