//go:build !race

package deposit

// raceDetectorEnabled reports whether this binary was built with -race.
//
// The race detector instruments every memory access, which multiplies the cost
// of the elliptic-curve work an uplink seal performs. That is harmless for a
// correctness test and fatal for a timing one: the campaign's interval is
// calibrated against the real seal cost, and under -race the seal grows past
// the interval, so the loop stops keeping a cadence and starts sealing as fast
// as it can. Whatever the resulting capture measures, it is not the protocol.
const raceDetectorEnabled = false
