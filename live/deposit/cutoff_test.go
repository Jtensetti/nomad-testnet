package deposit

import "testing"

// The cutoff is computed, so the computation itself needs a check. These are
// the values worked out by hand from the exact fixed-point distribution of a
// uniform permutation of four elements.
func TestTheNullCutoffMatchesTheDistributionItClaims(t *testing.T) {
	for _, testCase := range []struct {
		publishers, trials int
		budget             float64
		want               int
	}{
		{4, 40, 1e-6, 74},
		{4, 24, 1e-6, 51},
		{4, 12, 1e-6, 32},
		// The threshold this experiment used to run at: 12 trials failing above
		// twice chance is 25 hits, and 25 hits is what a 1e-3 budget buys. Its
		// actual false-failure rate was 6.7e-4 -- about one run in 1500.
		{4, 12, 1e-3, 25},
	} {
		got := nullHitCutoff(testCase.publishers, testCase.trials, testCase.budget)
		if got != testCase.want {
			t.Errorf("nullHitCutoff(%d, %d, %.0e) = %d, want %d",
				testCase.publishers, testCase.trials, testCase.budget, got, testCase.want)
		}
	}
	// A cutoff above every attainable value would make the test unfailable.
	if got := nullHitCutoff(4, 40, 1e-6); got > 4*40 {
		t.Errorf("cutoff %d exceeds the %d attainable hits: the gate could never fire",
			got, 4*40)
	}
}
