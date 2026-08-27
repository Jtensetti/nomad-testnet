// Command crasher panics while holding a secret in a live local variable, so a
// test can observe exactly what a crashing Nomad process writes.
//
// It lives under testdata and is built by the test rather than being part of
// the module's own build: the go tool ignores testdata, and the measurement
// needs a real process whose panic the testing framework has not wrapped in
// its own recover-and-repanic path.
package main

import (
	"os"

	"github.com/Jtensetti/nomad-testnet/live/telemetry"
)

func main() {
	telemetry.WarnIfCrashDumpsEnabled(os.Stderr)
	panicWithSecretAlive([]byte("SUPERSECRETKEYMATERIAL-0123456789abcdef"))
}

//go:noinline
func panicWithSecretAlive(secret []byte) {
	if len(secret) == 0 {
		return
	}
	panic("deliberate crash for the telemetry boundary test")
}
