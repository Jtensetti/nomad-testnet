package node

import (
	"math"
	"sort"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/wire"
)

// The published decision rule (scripts/two-world-analysis.py) judges captures
// with a two-sample Kolmogorov-Smirnov test over inter-arrivals. The
// in-process campaign used only the median, which is far less sensitive: on
// the same captures the median reported no finding while KS rejected at
// p=1.5e-06. Gating on the weaker statistic while publishing the stronger one
// means the gate passes things the published rule would reject, so the same
// statistic family is computed here.

// kolmogorovSmirnov returns the two-sample KS statistic and its asymptotic
// p-value over two inter-arrival samples.
func kolmogorovSmirnov(left, right []float64) (float64, float64) {
	if len(left) == 0 || len(right) == 0 {
		return 1, 0
	}
	first := append([]float64(nil), left...)
	second := append([]float64(nil), right...)
	sort.Float64s(first)
	sort.Float64s(second)

	n, m := len(first), len(second)
	i, j := 0, 0
	statistic := 0.0
	// Both empirical CDFs advance past every observation equal to the current
	// value before the gap is measured. Inter-arrivals from a fixed-cadence
	// capture are heavily tied, and a per-observation walk charges each tie
	// run as a gap, reporting a large statistic for a sample against itself.
	for i < n && j < m {
		value := first[i]
		if second[j] < value {
			value = second[j]
		}
		for i < n && first[i] == value {
			i++
		}
		for j < m && second[j] == value {
			j++
		}
		gap := math.Abs(float64(i)/float64(n) - float64(j)/float64(m))
		if gap > statistic {
			statistic = gap
		}
	}
	if statistic <= 0 {
		return 0, 1
	}
	effective := math.Sqrt(float64(n) * float64(m) / float64(n+m))
	lambda := (effective + 0.12 + 0.11/effective) * statistic
	return statistic, kolmogorovSurvival(lambda)
}

// kolmogorovSurvival is Q(lambda). The alternating series does not converge
// as lambda approaches zero -- which is what two identical samples produce --
// so the sum carries an explicit convergence test and a non-converging sum
// returns 1, meaning no evidence of a difference.
func kolmogorovSurvival(lambda float64) float64 {
	if lambda <= 0 {
		return 1
	}
	scale, total, previous := 2.0, 0.0, 0.0
	exponent := -2.0 * lambda * lambda
	for k := 1; k <= 100; k++ {
		term := scale * math.Exp(exponent*float64(k)*float64(k))
		total += term
		if math.Abs(term) <= 1e-6*previous || math.Abs(term) <= 1e-16*math.Abs(total) {
			return math.Max(0, math.Min(1, total))
		}
		scale = -scale
		previous = math.Abs(term)
	}
	return 1
}

// boundedGaps returns a capture's inter-arrivals in nanoseconds, excluding the
// round boundaries, which come from restarting the sender rather than from
// either world.
func boundedGaps(capture *wire.Capture) []float64 {
	ceiling := float64(campaignIntervalMillis*10) * float64(time.Millisecond)
	gaps := make([]float64, 0, len(capture.Packets))
	for _, gap := range capture.Interarrivals() {
		if float64(gap) <= ceiling {
			gaps = append(gaps, float64(gap))
		}
	}
	return gaps
}
