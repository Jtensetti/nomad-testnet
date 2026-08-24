//go:build race

package deposit

// See race_off_test.go for why the campaign distinguishes these builds.
const raceDetectorEnabled = true
